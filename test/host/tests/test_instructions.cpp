// Instruction builders (System, SPL Token / Token-2022, ATA, Memo) against @solana/web3.js and @solana/spl-token,
// plus wrapSol / unwrapSol with a mocked RPC.

static bool insSameIx(const Instruction &ix, JsonObject c, std::string &why)
{
    if (b58(String(c["program"].as<const char *>())) != ix.programId.data) { why = "program id"; return false; }
    JsonArray accs = c["accounts"].as<JsonArray>();
    if (accs.size() != ix.accounts.size()) { why = "account count " + std::to_string(ix.accounts.size()) + " want " + std::to_string(accs.size()); return false; }
    size_t i = 0;
    for (JsonObject a : accs)
    {
        const AccountMeta &m = ix.accounts[i];
        if (m.pubkey.data != b58(String(a["pubkey"].as<const char *>()))) { why = "pubkey #" + std::to_string(i); return false; }
        if (m.isSigner != a["signer"].as<bool>()) { why = "isSigner #" + std::to_string(i); return false; }
        if (m.isWritable != a["writable"].as<bool>()) { why = "isWritable #" + std::to_string(i); return false; }
        i++;
    }
    if (toHex(ix.data) != c["data"].as<std::string>()) { why = "data " + toHex(ix.data) + " want " + c["data"].as<std::string>(); return false; }
    return true;
}

// Builds the instruction a vector case describes, with the library
static bool insBuild(JsonObject c, Instruction &out)
{
    std::string n = c["name"].as<std::string>();
    JsonObject a = c["args"].as<JsonObject>();
    std::vector<Pubkey> k;
    for (JsonVariant v : a["k"].as<JsonArray>()) k.push_back(Pubkey::fromBase58(String(v.as<const char *>())));
    std::vector<uint64_t> u;
    for (JsonVariant v : a["u"].as<JsonArray>()) u.push_back(strtoull(v.as<const char *>(), nullptr, 10));
    uint8_t d = (uint8_t)a["d"].as<int>();
    String seed(a["seed"].as<const char *>() ? a["seed"].as<const char *>() : "");
    bool none = a["none"].as<bool>();
    Pubkey tp = Pubkey::fromBase58(String(a["p"].as<const char *>() ? a["p"].as<const char *>() : INFRATIC_TOKEN_PROGRAM_ID));

    if (n == "sys.transfer") out = SystemProgram::transferIx(k[0], k[1], u[0]);
    else if (n == "sys.createAccount") out = SystemProgram::createAccountIx(k[0], k[1], u[0], u[1], k[2]);
    else if (n == "sys.assign") out = SystemProgram::assignIx(k[0], k[1]);
    else if (n == "sys.allocate") out = SystemProgram::allocateIx(k[0], u[0]);
    else if (n == "sys.createAccountWithSeed") out = SystemProgram::createAccountWithSeedIx(k[0], k[1], k[2], seed, u[0], u[1], k[3]);
    else if (n == "sys.transferWithSeed") out = SystemProgram::transferWithSeedIx(k[0], k[1], seed, k[2], k[3], u[0]);
    else if (n == "tok.initializeMint2") out = SplToken::initializeMint2Ix(k[0], d, k[1], none ? nullptr : &k[2], tp);
    else if (n == "tok.initializeAccount3") out = SplToken::initializeAccount3Ix(k[0], k[1], k[2], tp);
    else if (n == "tok.transfer") out = SplToken::transferIx(k[0], k[1], k[2], u[0], tp);
    else if (n == "tok.mintTo") out = SplToken::mintToIx(k[0], k[1], k[2], u[0], tp);
    else if (n == "tok.mintToChecked") out = SplToken::mintToCheckedIx(k[0], k[1], k[2], u[0], d, tp);
    else if (n == "tok.burn") out = SplToken::burnIx(k[0], k[1], k[2], u[0], tp);
    else if (n == "tok.burnChecked") out = SplToken::burnCheckedIx(k[0], k[1], k[2], u[0], d, tp);
    else if (n == "tok.approve") out = SplToken::approveIx(k[0], k[1], k[2], u[0], tp);
    else if (n == "tok.approveChecked") out = SplToken::approveCheckedIx(k[0], k[1], k[2], k[3], u[0], d, tp);
    else if (n == "tok.revoke") out = SplToken::revokeIx(k[0], k[1], tp);
    else if (n == "tok.closeAccount") out = SplToken::closeAccountIx(k[0], k[1], k[2], tp);
    else if (n == "tok.setAuthority") out = SplToken::setAuthorityIx(k[0], (AuthorityType)a["t"].as<int>(), k[1], none ? nullptr : &k[2], tp);
    else if (n == "tok.syncNative") out = SplToken::syncNativeIx(k[0], tp);
    else if (n == "tok.freezeAccount") out = SplToken::freezeAccountIx(k[0], k[1], k[2], tp);
    else if (n == "tok.thawAccount") out = SplToken::thawAccountIx(k[0], k[1], k[2], tp);
    else if (n == "ata.create") out = SplToken::createAssociatedTokenAccountIx(k[0], k[1], k[2], k[3], tp);
    else if (n == "ata.createIdempotent") out = Infratic::createAssociatedTokenAccountIdempotentIx(k[0], k[1], k[2], k[3], tp);
    else if (n == "memo") out = MemoProgram::memoIx(seed, k);
    else return false;
    return true;
}

static std::vector<uint8_t> insSentMessage(const std::string &sentB64, size_t &nsigs, std::vector<uint8_t> &sig0)
{
    std::vector<uint8_t> raw(sentB64.size());
    size_t len = 0;
    mbedtls_base64_decode(raw.data(), raw.size(), &len, (const unsigned char *)sentB64.data(), sentB64.size());
    raw.resize(len);
    nsigs = raw.empty() ? 0 : raw[0];
    if (raw.size() < 1 + 64 * nsigs) return {};
    sig0.assign(raw.begin() + 1, raw.begin() + 65);
    return std::vector<uint8_t>(raw.begin() + 1 + 64 * nsigs, raw.end());
}

INFRATIC_TEST(instructions)
{
    // ---- every instruction against web3.js / spl-token, byte for byte ----
    int built = 0;
    for (JsonObject c : vec["ix"].as<JsonArray>())
    {
        Instruction ix(Pubkey(), {}, {});
        std::string why;
        std::string label = c["name"].as<std::string>() + " " + (c["args"]["p"].as<const char *>() ? std::string(c["args"]["p"].as<const char *>()).substr(0, 6) : "");
        bool ok = insBuild(c, ix) && insSameIx(ix, c, why);
        built++;
        CHECK(ok, label + ": " + why);
    }
    CHECK(built > 300, "vector count " + std::to_string(built));

    // ---- createWithSeed ----
    for (JsonObject c : vec["seeds"].as<JsonArray>())
    {
        String out;
        bool ok = SystemProgram::createWithSeed(Pubkey::fromBase58(String(c["base"].as<const char *>())), String(c["seed"].as<const char *>()),
                                                Pubkey::fromBase58(String(c["program"].as<const char *>())), out);
        CHECK(ok && out == c["address"].as<const char *>(), "createWithSeed '" + std::string(c["seed"].as<const char *>()) + "' " + out.s);
    }
    for (JsonObject c : vec["badSeeds"].as<JsonArray>())
    {
        String out("untouched");
        Pubkey prog = c.containsKey("programHex") ? Pubkey() : Pubkey::fromBase58(String(c["program"].as<const char *>()));
        if (c.containsKey("programHex")) prog.data = fromHex(c["programHex"].as<std::string>());
        CHECK(!SystemProgram::createWithSeed(Pubkey::fromBase58(String(c["base"].as<const char *>())), String(c["seed"].as<const char *>()), prog, out),
              "createWithSeed rejects seed/program");
    }
    {
        String out;
        Pubkey shortKey; shortKey.data = {1, 2, 3};
        CHECK(!SystemProgram::createWithSeed(shortKey, "a", Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), out), "createWithSeed rejects short base");
    }

    // ---- wrapSol / unwrapSol: decode the transaction that was sent ----
    std::string sent;
    bool rpcError = false;
    g_httpHandler = [&](const std::string &, const std::string &body) -> MockHttpResponse {
        auto has = [&](const char *m) { return body.find(m) != std::string::npos; };
        if (has("getLatestBlockhash"))
            return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":{\"blockhash\":\"" + vec["blockhash"].as<std::string>() + "\",\"lastValidBlockHeight\":1}}}"};
        if (has("sendTransaction"))
        {
            if (rpcError) return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32002,\"message\":\"Transaction simulation failed\",\"data\":{\"err\":\"InsufficientFundsForFee\",\"logs\":[]}}}"};
            DynamicJsonDocument d(8192); deserializeJson(d, body); sent = d["params"][0].as<std::string>();
            return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"5sig\"}"};
        }
        if (has("getSignatureStatuses")) return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":[{\"confirmationStatus\":\"confirmed\",\"err\":null}]}}"};
        return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"};
    };
    Keypair owner = Keypair::fromBase58(String(vec["ownerSecret"].as<const char *>()));
    CHECK(owner.publicBase58() == vec["owner"].as<const char *>(), "owner keypair");

    for (JsonObject w : vec["wrapTx"].as<JsonArray>())
    {
        String prog(w["program"].as<const char *>());
        String sig;
        sent.clear();
        CHECK(sol.wrapSol(owner, w["lamports"].as<uint64_t>(), sig, prog) && sig == "5sig", "wrapSol sends " + prog.s);
        size_t ns = 0;
        std::vector<uint8_t> s0;
        std::vector<uint8_t> msg = insSentMessage(sent, ns, s0);
        DecodedMsg a = decodeMsg(msg), b = decodeMsg(fromHex(w["wrapMessage"].as<std::string>()));
        CHECK(ns == 1 && a.ok && a.canon == b.canon, "wrapSol message " + prog.s + "\n    want " + b.canon + "\n    got  " + a.canon);
        CHECK(!msg.empty() && Ed25519::verify(s0.data(), owner.pubkey().data.data(), msg.data(), msg.size()), "wrapSol signature");

        sent.clear();
        CHECK(sol.unwrapSol(owner, sig, prog) && sig == "5sig", "unwrapSol sends " + prog.s);
        msg = insSentMessage(sent, ns, s0);
        a = decodeMsg(msg); b = decodeMsg(fromHex(w["unwrapMessage"].as<std::string>()));
        CHECK(ns == 1 && a.ok && a.canon == b.canon, "unwrapSol message " + prog.s + "\n    want " + b.canon + "\n    got  " + a.canon);
    }

    // errors: zero amount, empty keypair, bad token program, RPC error
    String sig;
    sent.clear();
    CHECK(!sol.wrapSol(owner, 0, sig) && sent.empty(), "wrapSol rejects zero lamports");
    CHECK(!sol.wrapSol(Keypair(), 1000, sig) && sent.empty(), "wrapSol rejects empty keypair");
    CHECK(!sol.unwrapSol(Keypair(), sig) && sent.empty(), "unwrapSol rejects empty keypair");
    CHECK(!sol.wrapSol(owner, 1000, sig, "not-a-program") && sent.empty(), "wrapSol rejects bad token program");
    rpcError = true;
    CHECK(!sol.wrapSol(owner, 1000, sig) && sol.lastTxError().name == "InsufficientFundsForFee", "wrapSol reports RPC error: " + sol.lastTxError().name.s);
    CHECK(!sol.unwrapSol(owner, sig), "unwrapSol reports RPC error");
    g_httpHandler = nullptr;
}
