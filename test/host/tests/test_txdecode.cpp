// ParsedTransaction: parsing, signing, decoding and cost of transactions built by web3.js
static std::string tdHex(const std::vector<uint8_t> &v) { return toHex(v); }

static bool validUtf8Probe(const String &s)
{
    size_t i = 0, n = s.length();
    while (i < n)
    {
        uint8_t c = (uint8_t)s[i];
        size_t extra = c < 0x80 ? 0 : (c & 0xe0) == 0xc0 ? 1 : (c & 0xf0) == 0xe0 ? 2 : (c & 0xf8) == 0xf0 ? 3 : 99;
        if (i + extra >= n + (extra == 0 ? 1 : 0) && extra) return false;
        for (size_t k = 1; k <= extra; k++)
            if (extra == 99 || ((uint8_t)s[i + k] & 0xc0) != 0x80) return false;
        i += extra + 1;
    }
    return true;
}

static std::vector<uint8_t> tdFromB64(const std::string &s)
{
    std::vector<uint8_t> out;
    infratic_detail::fromBase64(s.c_str(), out);
    return out;
}

static void tdCheckDecoded(const ParsedTransaction &tx, size_t i, JsonVariantConst want, const std::string &name)
{
    DecodedInstruction d = tx.decodeInstruction(i);
    std::string n = name + " ix" + std::to_string(i) + " ";
    auto str = [&](const char *k, const String &got)
    {
        if (!want.containsKey(k)) return;
        std::string w = want[k].as<std::string>(), g = got.c_str();
        CHECK(g == w, n + k + ": got '" + g + "' want '" + w + "'");
    };
    str("program", d.program);
    str("type", d.type);
    str("summary", d.summary);
    str("source", d.source);
    str("destination", d.destination);
    str("authority", d.authority);
    str("mint", d.mint);
    str("owner", d.owner);
    str("text", d.text);
    if (want.containsKey("known")) CHECK(d.known == want["known"].as<bool>(), n + "known");
    if (want.containsKey("amount")) CHECK(String((unsigned long long)d.amount) == String(want["amount"].as<const char *>()), n + "amount");
    if (want.containsKey("decimals")) CHECK(d.decimals == want["decimals"].as<int>(), n + "decimals");
    if (want.containsKey("resolved")) CHECK(d.resolved == want["resolved"].as<bool>(), n + "resolved");
}

INFRATIC_TEST(txdecode)
{
    // ---- vectors from web3.js ----------------------------------------------------
    for (JsonVariant c : vec["cases"].as<JsonArray>())
    {
        std::string name = c["name"].as<std::string>();
        std::vector<uint8_t> raw = tdFromB64(c["base64"].as<std::string>());
        ParsedTransaction tx;
        CHECK(tx.fromBase64(c["base64"].as<const char *>()), name + " parses: " + tx.error().c_str());
        CHECK(raw.size() <= INFRATIC_MAX_TX_SIZE, name + " size");
        CHECK(tx.isVersioned == (std::string(c["version"].as<const char *>()) == "v0"), name + " version");
        CHECK(tx.numRequiredSignatures == c["header"][0].as<int>() && tx.numReadonlySigned == c["header"][1].as<int>() &&
                  tx.numReadonlyUnsigned == c["header"][2].as<int>(), name + " header");
        CHECK(tdHex(tx.message) == c["message"].as<std::string>(), name + " message bytes");
        CHECK(tx.recentBlockhash == String(c["blockhash"].as<const char *>()), name + " blockhash");
        JsonArray keys = c["staticKeys"].as<JsonArray>();
        bool keysOk = tx.staticKeys.size() == keys.size();
        for (size_t i = 0; keysOk && i < keys.size(); i++) keysOk = tx.staticKeys[i] == String(keys[i].as<const char *>());
        CHECK(keysOk, name + " static keys");
        JsonArray ixs = c["instructions"].as<JsonArray>();
        bool ixOk = tx.instructions.size() == ixs.size();
        for (size_t i = 0; ixOk && i < ixs.size(); i++)
        {
            const ParsedInstruction &p = tx.instructions[i];
            JsonArray acc = ixs[i]["accounts"].as<JsonArray>();
            ixOk = p.programIdIndex == ixs[i]["program"].as<int>() && tdHex(p.data) == ixs[i]["data"].as<std::string>() &&
                   p.accountIndexes.size() == acc.size();
            for (size_t k = 0; ixOk && k < acc.size(); k++) ixOk = p.accountIndexes[k] == acc[k].as<int>();
        }
        CHECK(ixOk, name + " instructions");
        JsonArray lk = c["lookups"].as<JsonArray>();
        bool lkOk = tx.lookups.size() == lk.size();
        for (size_t i = 0; lkOk && i < lk.size(); i++)
        {
            lkOk = tx.lookups[i].table == String(lk[i]["table"].as<const char *>()) &&
                   tx.lookups[i].writableIndexes.size() == lk[i]["writable"].size() &&
                   tx.lookups[i].readonlyIndexes.size() == lk[i]["readonly"].size();
            for (size_t k = 0; lkOk && k < tx.lookups[i].writableIndexes.size(); k++) lkOk = tx.lookups[i].writableIndexes[k] == lk[i]["writable"][k].as<int>();
            for (size_t k = 0; lkOk && k < tx.lookups[i].readonlyIndexes.size(); k++) lkOk = tx.lookups[i].readonlyIndexes[k] == lk[i]["readonly"][k].as<int>();
        }
        CHECK(lkOk, name + " lookups");

        // exact round trip
        CHECK(tdHex(tx.serialize()) == tdHex(raw) && tx.toBase64() == String(c["base64"].as<const char *>()), name + " reserializes byte for byte");

        // which signatures are present
        JsonArray pb = c["presentBefore"].as<JsonArray>();
        bool presOk = tx.signatures.size() == pb.size();
        for (size_t i = 0; presOk && i < pb.size(); i++)
        {
            bool present = false;
            for (uint8_t b : tx.signatures[i]) present |= b != 0;
            presOk = present == pb[i].as<bool>();
        }
        CHECK(presOk, name + " signatures present");
        std::vector<uint8_t> missing;
        CHECK(tx.verifySignatures(&missing), name + " present signatures are valid");
        size_t wantMissing = 0;
        for (JsonVariant v : pb) if (!v.as<bool>()) wantMissing++;
        CHECK(missing.size() == wantMissing && tx.isFullySigned() == (wantMissing == 0), name + " missing signers reported");

        // sign with the device key
        Keypair esp = Keypair::fromBase58(c["espSecret"].as<const char *>());
        CHECK(tx.signerIndex(esp.pubkey()) == c["espSignerIndex"].as<int>() && tx.signerIndex(esp.publicBase58()) == c["espSignerIndex"].as<int>(), name + " signerIndex");
        CHECK(tx.sign(esp), name + " sign");
        CHECK(tx.toBase64() == String(c["base64After"].as<const char *>()), name + " signed transaction equals web3.js");
        CHECK(tx.verifySignatures() && tx.isFullySigned() == c["fullySignedAfter"].as<bool>(), name + " fully signed state");
        CHECK(tdHex(tx.message) == c["message"].as<std::string>(), name + " message untouched by signing");
        // signing twice gives the same bytes (deterministic)
        CHECK(tx.sign(esp) && tx.toBase64() == String(c["base64After"].as<const char *>()), name + " sign is idempotent");

        // decoder
        ParsedTransaction fresh;
        fresh.fromBase64(c["base64"].as<const char *>());
        JsonArray dec = c["decoded"].as<JsonArray>();
        CHECK(fresh.instructions.size() == dec.size(), name + " decoded count");
        if (c["tables"].size())
        {
            // before the tables are known, loaded accounts are reported as unresolved
            JsonArray un = c["unresolvedDecoded"].as<JsonArray>();
            for (size_t i = 0; i < un.size(); i++) tdCheckDecoded(fresh, i, un[i], name + " (unresolved)");
            CHECK(fresh.accountKey(fresh.staticKeys.size()).isEmpty() && fresh.accountCount() > fresh.staticKeys.size(), name + " loaded keys unresolved");
            for (JsonPair kv : c["tables"].as<JsonObject>())
            {
                std::vector<String> addrs;
                for (JsonVariant a : kv.value().as<JsonArray>()) addrs.push_back(a.as<const char *>());
                CHECK(fresh.setLookupTable(kv.key().c_str(), addrs), name + " setLookupTable");
            }
            CHECK(!fresh.setLookupTable("11111111111111111111111111111111", {}), name + " setLookupTable for a table that is not referenced");
        }
        for (size_t i = 0; i < dec.size(); i++) tdCheckDecoded(fresh, i, dec[i], name);
        CHECK(fresh.decodeAll().size() == dec.size(), name + " decodeAll");

        // cost
        JsonVariant cost = c["cost"];
        TxCostEstimate e = fresh.estimateCost(c["costSigner"].as<const char *>());
        CHECK(String((unsigned long long)e.baseFee) == String(cost["baseFee"].as<const char *>()), name + " base fee");
        CHECK(String((unsigned long long)e.priorityFee) == String(cost["priorityFee"].as<const char *>()), name + " priority fee");
        CHECK(String((unsigned long long)e.lamportsTransferred) == String(cost["transferred"].as<const char *>()), name + " transferred");
        CHECK(String((unsigned long long)e.lamportsFunded) == String(cost["funded"].as<const char *>()), name + " funded");
        CHECK(String((unsigned long long)e.totalLamports) == String(cost["total"].as<const char *>()), name + " total");
        CHECK(e.computeUnitLimit == cost["limit"].as<uint32_t>() && e.limitRequested == cost["limitRequested"].as<bool>() &&
                  String((unsigned long long)e.microLamportsPerCU) == String(cost["price"].as<const char *>()), name + " compute budget");
    }

    // ---- signing guards ---------------------------------------------------------
    {
        JsonVariant c = vec["cases"][0];
        ParsedTransaction tx;
        tx.fromBase64(c["base64"].as<const char *>());
        Keypair stranger = Keypair::fromSeed((const uint8_t *)"0123456789abcdef0123456789abcdef");
        std::string before = tx.toBase64().c_str();
        CHECK(!tx.sign(stranger) && tx.signerIndex(stranger.pubkey()) == -1 && before == tx.toBase64().c_str(), "key that is not a signer is refused and nothing changes");
        Keypair empty;
        CHECK(!tx.sign(empty), "keypair without private key refused");
        // fee-paying account that is not a signer slot (a non-signer key of the message)
        Pubkey nonSigner = Pubkey::fromBase58(tx.staticKeys[tx.staticKeys.size() - 1]);
        CHECK(tx.signerIndex(nonSigner) == -1, "non-signer account has no signer index");
        // a tampered signature is detected
        Keypair esp = Keypair::fromBase58(c["espSecret"].as<const char *>());
        tx.sign(esp);
        tx.signatures[tx.signerIndex(esp.pubkey())][5] ^= 1;
        std::vector<uint8_t> missing;
        CHECK(!tx.verifySignatures(&missing) && !tx.isFullySigned(), "corrupted signature detected");
        // keypair whose public half does not match the secret half
        ParsedTransaction t2;
        t2.fromBase64(c["base64"].as<const char *>());
        Keypair broken = esp;
        broken.privkey[40] ^= 0xff;
        CHECK(!t2.sign(broken), "inconsistent keypair refused");
        // after a message change the old signatures no longer verify
        ParsedTransaction t3;
        t3.fromBase64(c["base64After"].as<const char *>());
        CHECK(t3.verifySignatures(), "signed vector verifies");
        t3.message[t3.message.size() - 1] ^= 1;
        CHECK(!t3.verifySignatures(), "signature does not verify for a modified message");
        ParsedTransaction blank;
        CHECK(!blank.verifySignatures() && blank.serialize().empty() && blank.toBase64() == "" && !blank.sign(esp), "empty object is inert");
        CHECK(blank.decodeInstruction(0).type == "unknown" && blank.accountKey(3).isEmpty(), "empty object decode");
    }

    // ---- raw inputs that must parse ------------------------------------------------
    for (JsonVariant p : vec["positives"].as<JsonArray>())
    {
        ParsedTransaction tx;
        std::vector<uint8_t> raw = fromHex(p["hex"].as<std::string>());
        CHECK(tx.fromBytes(raw) && tx.serialize() == raw, p["name"].as<std::string>() + " parses and round trips");
    }
    {
        ParsedTransaction tx;
        std::vector<uint8_t> raw = fromHex(vec["maxHex"].as<std::string>());
        CHECK(raw.size() == INFRATIC_MAX_TX_SIZE && tx.fromBytes(raw) && tx.serialize() == raw, "1232 bytes accepted");
    }

    // ---- malformed input -----------------------------------------------------------
    for (JsonVariant n : vec["negatives"].as<JsonArray>())
    {
        ParsedTransaction tx;
        bool ok = tx.fromBytes(fromHex(n["hex"].as<std::string>()));
        CHECK(!ok && tx.error().length() > 0 && tx.staticKeys.empty() && tx.instructions.empty() && tx.message.empty() && tx.signatures.empty(),
              n["name"].as<std::string>() + " rejected: " + tx.error().c_str());
        CHECK(tx.serialize().empty(), n["name"].as<std::string>() + " leaves nothing to serialize");
    }
    for (JsonVariant b : vec["bad64"].as<JsonArray>())
    {
        ParsedTransaction tx;
        CHECK(!tx.fromBase64(b.as<const char *>()), std::string("bad base64 rejected: ") + b.as<std::string>().substr(0, 12));
    }
    {
        ParsedTransaction tx;
        CHECK(tx.fromBase64(vec["cases"][1]["base64"].as<const char *>()) && !tx.fromBase64("") && tx.instructions.empty(), "failed parse clears a previous result");
    }

    // ---- truncation and bit flips of every valid vector (invariants only) -------------
    uint32_t seed = 12345;
    auto rnd = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    for (JsonVariant c : vec["cases"].as<JsonArray>())
    {
        std::vector<uint8_t> raw = tdFromB64(c["base64After"].as<std::string>());
        bool prefixOk = true, mutOk = true;
        for (size_t len = 0; len < raw.size(); len++)
        {
            ParsedTransaction tx;
            if (tx.fromBytes(std::vector<uint8_t>(raw.begin(), raw.begin() + len))) prefixOk = false;
        }
        CHECK(prefixOk, c["name"].as<std::string>() + ": every strict prefix is rejected");
        for (int i = 0; i < 400; i++)
        {
            std::vector<uint8_t> m = raw;
            int flips = 1 + rnd() % 3;
            for (int f = 0; f < flips; f++) m[rnd() % m.size()] ^= (uint8_t)(1u << (rnd() % 8));
            ParsedTransaction tx;
            if (tx.fromBytes(m))
            {
                // whatever is accepted must be internally consistent and reproduce its input
                bool ok = tx.serialize() == m && tx.signatures.size() == tx.numRequiredSignatures && tx.staticKeys.size() >= tx.numRequiredSignatures;
                for (size_t k = 0; ok && k < tx.instructions.size(); k++)
                {
                    ok = tx.instructions[k].programIdIndex < tx.staticKeys.size();
                    for (uint8_t a : tx.instructions[k].accountIndexes) ok = ok && a < tx.accountCount();
                    tx.decodeInstruction(k);
                }
                tx.estimateCost(tx.staticKeys[0]);
                tx.verifySignatures();
                if (!ok) mutOk = false;
            }
        }
        CHECK(mutOk, c["name"].as<std::string>() + ": accepted mutations stay consistent");
    }
    {
        // random garbage never crashes
        bool ok = true;
        for (int i = 0; i < 2000; i++)
        {
            std::vector<uint8_t> g(rnd() % 300);
            for (auto &b : g) b = rnd() & 0xff;
            if (!g.empty() && i % 2) g[0] = 1; // plausible signature count
            ParsedTransaction tx;
            if (tx.fromBytes(g) && tx.serialize() != g) ok = false;
        }
        CHECK(ok, "random input");
    }

    // ---- formatting and decoder edge cases ------------------------------------------
    CHECK(ParsedTransaction::formatSol(250000000) == "0.25 SOL" && ParsedTransaction::formatSol(0) == "0 SOL" &&
          ParsedTransaction::formatSol(1) == "0.000000001 SOL" && ParsedTransaction::formatSol(1000000000) == "1 SOL" &&
          ParsedTransaction::formatSol(18446744073709551615ULL) == "18446744073.709551615 SOL", "formatSol");
    CHECK(ParsedTransaction::formatUnits(1500000, 6) == "1.5" && ParsedTransaction::formatUnits(5, 6) == "0.000005" &&
          ParsedTransaction::formatUnits(7, 0) == "7" && ParsedTransaction::formatUnits(100, 2) == "1", "formatUnits");
    CHECK(ParsedTransaction::shortKey("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM") == "9WzD...AWWM" && ParsedTransaction::shortKey("abc") == "abc", "shortKey");
    {
        // handcrafted: memo with control characters and invalid UTF-8, truncated system transfer, short token data
        auto build = [&](const std::string &programB58, const std::vector<uint8_t> &data, int nAccts)
        {
            std::vector<uint8_t> raw(1 + 64, 0);
            raw[0] = 1;
            std::vector<uint8_t> msg = {1, 0, 1, 3};
            Keypair k = Keypair::fromSeed((const uint8_t *)"0123456789abcdef0123456789abcdef");
            msg.insert(msg.end(), k.pubkey().data.begin(), k.pubkey().data.end());
            std::vector<uint8_t> other(32, 9);
            msg.insert(msg.end(), other.begin(), other.end());
            std::vector<uint8_t> prog = b58(programB58.c_str());
            msg.insert(msg.end(), prog.begin(), prog.end());
            msg.insert(msg.end(), 32, 0);
            msg.push_back(1);
            msg.push_back(2);
            msg.push_back((uint8_t)nAccts);
            for (int i = 0; i < nAccts; i++) msg.push_back(i % 2);
            appendCompactU16(msg, data.size());
            msg.insert(msg.end(), data.begin(), data.end());
            raw.insert(raw.end(), msg.begin(), msg.end());
            ParsedTransaction tx;
            if (!tx.fromBytes(raw)) return DecodedInstruction();
            return tx.decodeInstruction(0);
        };
        std::string memo = INFRATIC_MEMO_PROGRAM_ID;
        DecodedInstruction d = build(memo, {'h', 'i', '\n', '\t', 'x'}, 0);
        CHECK(d.type == "memo" && d.text == "hi  x" && d.summary == "Memo: \"hi  x\"", "memo control characters become spaces");
        d = build(memo, {0xff, 0xfe, 'a'}, 0);
        CHECK(d.type == "memo" && d.text == "" && d.summary.indexOf("non-text") > 0, "invalid utf-8 memo is not shown");
        d = build(memo, std::vector<uint8_t>(200, 'a'), 0);
        CHECK(d.summary.length() < 100 && d.text.length() == 200, "long memo summary is cut");
        std::vector<uint8_t> multi;
        for (int i = 0; i < 60; i++) { multi.push_back(0xc3); multi.push_back(0xa9); }
        d = build(memo, multi, 0);
        CHECK(validUtf8Probe(d.summary), "memo cut keeps utf-8 valid");
        d = build(INFRATIC_SYSTEM_PROGRAM_ID, {2, 0, 0, 0, 1, 0}, 2);
        CHECK(!d.known && d.type == "unknown" && d.program == "system", "short system transfer data is not decoded");
        d = build(INFRATIC_SYSTEM_PROGRAM_ID, {2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, 1);
        CHECK(!d.known && d.type == "unknown", "system transfer with too few accounts is not decoded");
        d = build(INFRATIC_TOKEN_PROGRAM_ID, {12, 1, 0, 0, 0, 0, 0, 0, 0}, 4);
        CHECK(!d.known && d.type == "unknown" && d.program == "spl-token", "transferChecked without decimals byte is not decoded");
        d = build(INFRATIC_TOKEN_PROGRAM_ID, {6, 1, 0}, 2);
        CHECK(!d.known && d.type == "unknown" && d.summary.indexOf("tag 6") > 0, "setAuthority is flagged as unrecognised");
        d = build(INFRATIC_COMPUTE_BUDGET_PROGRAM_ID, {3, 1, 0}, 0);
        CHECK(!d.known, "short compute budget data is not decoded");
        d = build(INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID, {}, 4);
        CHECK(d.known && d.type == "create", "original ATA create has no data");
        d = build(INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID, {2}, 4);
        CHECK(!d.known, "ATA recoverNested is not decoded");
    }
}
