// Off-chain messages, Sign-In With Solana and Solana Pay.
// Vectors: ../js/gen_offchain.mjs (@solana/offchain-messages, @solana/wallet-standard-util, @solana/pay).

static std::string oc_s(JsonVariantConst v) { const char *p = v.as<const char *>(); return p ? p : ""; }

static Keypair oc_kp(const std::string &secretHex) { std::vector<uint8_t> b = fromHex(secretHex); return Keypair::fromPrivateKey(b.data()); }

static std::string oc_expand(JsonObject c)
{
    if (!c.containsKey("repeat")) return oc_s(c["text"]);
    std::string out, f = oc_s(c["fill"]);
    for (size_t i = 0; i < c["repeat"].as<size_t>(); i++) out += f;
    return out;
}

static void oc_offchain(JsonVariant vec)
{
    g_group = "offchain";
    String err;
    size_t n_ok = 0;
    for (JsonObject c : vec["offchain"]["cases"].as<JsonArray>())
    {
        std::string name = oc_s(c["name"]);
        OffchainMessage m;
        std::vector<uint8_t> dom = b58(oc_s(c["applicationDomain"]).c_str());
        m.applicationDomain = dom;
        m.format = (OffchainFormat)c["format"].as<int>();
        for (JsonVariant s : c["signers"].as<JsonArray>()) m.signers.push_back(Pubkey::fromBase58(oc_s(s).c_str()));
        std::string text = oc_expand(c);
        m.body.assign(text.begin(), text.end());
        std::vector<uint8_t> content;
        bool ok = Offchain::build(m, content, &err);
        CHECK(ok == c["ok"].as<bool>(), name + " build verdict " + err.s);
        if (!c["ok"].as<bool>()) continue;
        n_ok++;
        if (c.containsKey("content")) CHECK(toHex(content) == oc_s(c["content"]), name + " content bytes");
        else CHECK(content.size() == c["contentLength"].as<size_t>(), name + " content length");
        OffchainMessage back;
        CHECK(Offchain::parse(content, back, &err) && back.body == m.body && back.format == m.format &&
              back.signers.size() == m.signers.size() && back.applicationDomain == m.applicationDomain, name + " parse round trip " + err.s);
        std::vector<Keypair> kps;
        size_t i = 0;
        for (JsonVariant sec : c["secrets"].as<JsonArray>())
        {
            Keypair kp = oc_kp(oc_s(sec));
            kps.push_back(kp);
            uint8_t sig[64];
            bool signedOk = Offchain::sign(content, kp, sig);
            std::vector<uint8_t> sv(sig, sig + 64);
            CHECK(signedOk && toHex(sv) == oc_s(c["signatures"][i]), name + " signature " + std::to_string(i));
            CHECK(Offchain::verify(content, kp.pubkey(), sig), name + " verify " + std::to_string(i));
            sig[5] ^= 1;
            CHECK(!Offchain::verify(content, kp.pubkey(), sig), name + " tampered signature rejected");
            i++;
        }
        std::vector<uint8_t> env;
        CHECK(Offchain::buildEnvelope(content, kps, env, &err), name + " envelope " + err.s);
        if (c.containsKey("envelope")) CHECK(toHex(env) == oc_s(c["envelope"]), name + " envelope bytes");
        CHECK(Offchain::verifyEnvelope(env, &err), name + " envelope verifies " + err.s);
        if (c.containsKey("partialEnvelope"))
        {
            std::vector<Keypair> rest(kps.begin() + 1, kps.end());
            std::vector<uint8_t> pe;
            CHECK(Offchain::buildEnvelope(content, rest, pe) && toHex(pe) == oc_s(c["partialEnvelope"]), name + " partial envelope bytes");
            CHECK(!Offchain::verifyEnvelope(pe, &err) && err == "signature missing", name + " partial envelope not fully signed");
        }
        // a signer that is not required must be refused
        Keypair stranger = Keypair::generate();
        uint8_t sig[64];
        CHECK(!Offchain::sign(content, stranger, sig), name + " stranger cannot sign");
    }
    CHECK(n_ok >= 13, "enough valid cases");

    for (JsonObject mu : vec["offchain"]["mutations"].as<JsonArray>())
    {
        std::string name = "mutation " + oc_s(mu["name"]);
        OffchainMessage m;
        bool ok = Offchain::parse(fromHex(oc_s(mu["content"])), m, &err);
        CHECK(ok == mu["ok"].as<bool>(), name + " verdict " + err.s);
        if (ok && mu["ok"].as<bool>())
        {
            CHECK(std::string(m.body.begin(), m.body.end()) == oc_s(mu["text"]) && (int)m.format == mu["format"].as<int>(), name + " fields");
            CHECK(m.signers.size() == mu["signers"].size() && base58Encode(m.signers[0].data.data(), 32) == oc_s(mu["signers"][0]).c_str(), name + " signers");
        }
    }
    for (JsonObject e : vec["offchain"]["envelopes"].as<JsonArray>())
    {
        std::string name = "envelope " + oc_s(e["name"]);
        std::vector<uint8_t> env = fromHex(oc_s(e["envelope"])), content;
        std::vector<std::vector<uint8_t>> sigs;
        CHECK(Offchain::parseEnvelope(env, content, sigs, &err) == e["decodes"].as<bool>(), name + " decodes " + err.s);
        CHECK(Offchain::verifyEnvelope(env) == e["verifies"].as<bool>(), name + " verifies");
    }

    // limits and validation rules
    CHECK(Offchain::maxBodyLength(OffchainFormat::RestrictedAscii, 1) == 1147, "max ascii 1 signer");
    CHECK(Offchain::maxBodyLength(OffchainFormat::Utf8Limited, 3) == 1083, "max utf8 3 signers");
    CHECK(Offchain::maxBodyLength(OffchainFormat::Utf8Extended, 7) == 65535, "max extended");
    CHECK(Offchain::maxBodyLength(OffchainFormat::RestrictedAscii, 40) == 0, "40 signers leave no room");
    {
        OffchainMessage m;
        Pubkey k = Pubkey::fromBase58("11111111111111111111111111111112");
        CHECK(Offchain::make("11111111111111111111111111111111", OffchainFormat::Utf8Limited, k, "hi", m) && Offchain::validate(m), "make + validate");
        CHECK(!Offchain::make("not base58 !", OffchainFormat::Utf8Limited, k, "hi", m), "make rejects bad domain");
        CHECK(!Offchain::make("1111", OffchainFormat::Utf8Limited, k, "hi", m), "make rejects short domain");
        Offchain::make("11111111111111111111111111111111", OffchainFormat::Utf8Limited, k, "hi", m);
        OffchainMessage x = m; x.signers.clear();
        CHECK(!Offchain::validate(x, &err), "zero signers rejected");
        x = m; x.version = 1;
        CHECK(!Offchain::validate(x), "version 1 rejected");
        x = m; x.applicationDomain.resize(31);
        CHECK(!Offchain::validate(x), "short application domain rejected");
        x = m; x.format = (OffchainFormat)3;
        CHECK(!Offchain::validate(x), "unknown format rejected");
        x = m; x.signers[0].data.resize(31);
        CHECK(!Offchain::validate(x), "short signer key rejected");
        const char *bad[] = {"\xc3", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe0\x80\x80", "\x80", "a\xff"};
        for (const char *b : bad)
        {
            x = m; x.body.assign(b, b + strlen(b));
            CHECK(!Offchain::validate(x), "invalid UTF-8 rejected");
            x.format = OffchainFormat::Utf8Extended;
            CHECK(!Offchain::validate(x), "invalid UTF-8 rejected (extended)");
        }
        x = m; x.body = {0xf0, 0x9f, 0x9a, 0x80};
        CHECK(Offchain::validate(x), "4 byte UTF-8 accepted");
    }
}

// ---------------------------------------------------------------------------
static SignInMessage oc_siws(JsonVariantConst o)
{
    SignInMessage m;
    m.domain = oc_s(o["domain"]).c_str(); m.address = oc_s(o["address"]).c_str(); m.statement = oc_s(o["statement"]).c_str();
    m.uri = oc_s(o["uri"]).c_str(); m.version = oc_s(o["version"]).c_str(); m.chainId = oc_s(o["chainId"]).c_str();
    m.nonce = oc_s(o["nonce"]).c_str(); m.issuedAt = oc_s(o["issuedAt"]).c_str(); m.expirationTime = oc_s(o["expirationTime"]).c_str();
    m.notBefore = oc_s(o["notBefore"]).c_str(); m.requestId = oc_s(o["requestId"]).c_str();
    for (JsonVariantConst r : o["resources"].as<JsonArrayConst>()) m.resources.push_back(oc_s(r).c_str());
    return m;
}
static bool oc_sameSiws(const SignInMessage &a, const SignInMessage &b)
{
    return a.domain == b.domain && a.address == b.address && a.statement == b.statement && a.uri == b.uri && a.version == b.version &&
           a.chainId == b.chainId && a.nonce == b.nonce && a.issuedAt == b.issuedAt && a.expirationTime == b.expirationTime &&
           a.notBefore == b.notBefore && a.requestId == b.requestId && a.resources == b.resources;
}

static void oc_siwsTests(JsonVariant vec)
{
    g_group = "siws";
    String err;
    int i = 0;
    for (JsonObject c : vec["siws"]["cases"].as<JsonArray>())
    {
        std::string name = "case " + std::to_string(i++);
        SignInMessage in = oc_siws(c["input"]);
        String text;
        CHECK(Siws::buildText(in, text, &err) && text == oc_s(c["text"]).c_str(), name + " text\n    want " + oc_s(c["text"]) + "\n    got  " + text.s);
        Keypair kp = oc_kp(oc_s(c["secret"]));
        String t2; uint8_t sig[64];
        SignInMessage noAddr = in; noAddr.address = "";
        CHECK(Siws::sign(noAddr, kp, t2, sig, &err) && t2 == text, name + " sign fills address " + err.s);
        std::vector<uint8_t> sv(sig, sig + 64);
        CHECK(toHex(sv) == oc_s(c["signature"]), name + " signature");
        std::vector<uint8_t> bytes(text.s.begin(), text.s.end());
        CHECK(Siws::verify(in, bytes, sig, kp.pubkey(), 0, &err) == c["verifies"].as<bool>(), name + " verify " + err.s);
        SignInMessage back;
        CHECK(Siws::parse(text, back) && oc_sameSiws(back, in), name + " parse round trip");
        SignInMessage ref;
        bool refOk = !c["parsed"].isNull();
        CHECK(Siws::parse(text, ref) == refOk, name + " parse verdict");
        if (refOk) CHECK(oc_sameSiws(ref, oc_siws(c["parsed"])), name + " parse fields");
    }
    for (JsonObject c : vec["siws"]["verify"].as<JsonArray>())
    {
        std::string name = "verify " + oc_s(c["name"]);
        SignInMessage expected = oc_siws(c["expected"]);
        std::string t = oc_s(c["text"]);
        std::vector<uint8_t> bytes(t.begin(), t.end());
        std::vector<uint8_t> sig = fromHex(oc_s(c["signature"])), pub = fromHex(oc_s(c["publicKey"]));
        Pubkey pk; pk.data = pub;
        CHECK(Siws::verify(expected, bytes, sig.data(), pk, 0, &err) == c["expectOk"].as<bool>(), name + " " + err.s);
    }
    int pi = 0;
    for (JsonObject c : vec["siws"]["parse"].as<JsonArray>())
    {
        std::string name = "parse #" + std::to_string(pi++);
        SignInMessage got;
        bool ok = Siws::parse(oc_s(c["text"]).c_str(), got);
        CHECK(ok == !c["parsed"].isNull(), name + " verdict for: " + oc_s(c["text"]));
        if (ok && !c["parsed"].isNull()) CHECK(oc_sameSiws(got, oc_siws(c["parsed"])), name + " fields for: " + oc_s(c["text"]));
    }

    // checks the reference does not do
    {
        SignInMessage m;
        m.domain = "example.com"; m.address = "11111111111111111111111111111112";
        String t;
        CHECK(Siws::buildText(m, t) && t == "example.com wants you to sign in with your Solana account:\n11111111111111111111111111111112", "minimal message");
        SignInMessage x = m; x.domain = "";
        CHECK(!Siws::buildText(x, t), "empty domain rejected");
        x = m; x.address = "";
        CHECK(!Siws::buildText(x, t), "empty address rejected");
        x = m; x.nonce = "a\nURI: evil";
        CHECK(!Siws::buildText(x, t, &err), "newline in a field rejected");
        x = m; x.resources.push_back("");
        CHECK(!Siws::buildText(x, t), "empty resource rejected");
        Keypair kp = Keypair::generate();
        uint8_t sig[64];
        x = m; x.address = "11111111111111111111111111111112";
        CHECK(!Siws::sign(x, kp, t, sig), "sign refuses a foreign address");
        // time checks
        SignInMessage w = m; w.address = kp.publicBase58();
        w.expirationTime = "2025-01-01T00:00:10.000Z"; w.notBefore = "2025-01-01T00:00:00Z";
        CHECK(Siws::sign(w, kp, t, sig), "sign with times");
        std::vector<uint8_t> bytes(t.s.begin(), t.s.end());
        CHECK(Siws::verify(w, bytes, sig, kp.pubkey(), 1735689605), "inside the window");
        CHECK(!Siws::verify(w, bytes, sig, kp.pubkey(), 1735689610, &err) && err == "message expired", "expired");
        CHECK(!Siws::verify(w, bytes, sig, kp.pubkey(), 1735689599, &err) && err == "message not valid yet", "not valid yet");
        CHECK(Siws::verify(w, bytes, sig, kp.pubkey(), 0), "time not checked when now is 0");
        int64_t u;
        CHECK(Siws::parseTime("2025-01-01T00:00:00.000Z", u) && u == 1735689600, "parseTime Z");
        CHECK(Siws::parseTime("2025-01-01T03:00:00+03:00", u) && u == 1735689600, "parseTime offset");
        CHECK(Siws::parseTime("2024-02-29T12:00:00-05:00", u) && u == 1709226000, "parseTime leap day");
        CHECK(!Siws::parseTime("2025-13-01T00:00:00Z", u) && !Siws::parseTime("yesterday", u) && !Siws::parseTime("2025-01-01 00:00:00Z", u), "parseTime rejects junk");
    }
}

// ---------------------------------------------------------------------------
static PayTransfer oc_pay(JsonVariantConst o, const char *amountKey = "amount")
{
    PayTransfer t;
    t.recipient = oc_s(o["recipient"]).c_str(); t.amount = oc_s(o[amountKey]).c_str(); t.splToken = oc_s(o["splToken"]).c_str();
    t.label = oc_s(o["label"]).c_str(); t.message = oc_s(o["message"]).c_str(); t.memo = oc_s(o["memo"]).c_str();
    for (JsonVariantConst r : o["reference"].as<JsonArrayConst>()) t.references.push_back(oc_s(r).c_str());
    return t;
}
static bool oc_samePay(const PayTransfer &a, const PayTransfer &b)
{
    return a.recipient == b.recipient && a.amount == b.amount && a.splToken == b.splToken && a.label == b.label && a.message == b.message &&
           a.memo == b.memo && a.references == b.references;
}

static std::string oc_rpcOk(const std::string &result) { return "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" + result + "}"; }

static void oc_payTests(Infratic &sol, JsonVariant vec)
{
    g_group = "solanapay";
    String err;
    int i = 0;
    for (JsonObject c : vec["pay"]["transfers"].as<JsonArray>())
    {
        std::string name = "transfer " + std::to_string(i++);
        PayTransfer req = oc_pay(c["request"], "amountInput");
        CHECK(SolanaPay::encodeTransfer(req, &err) == oc_s(c["url"]).c_str(), name + " encode\n    want " + oc_s(c["url"]) + "\n    got  " + SolanaPay::encodeTransfer(req).s);
        PayTransfer p;
        CHECK(SolanaPay::parseTransfer(oc_s(c["url"]).c_str(), p, &err) && oc_samePay(p, oc_pay(c["parsed"])), name + " parse " + err.s);
        PayTransactionRequest tr;
        CHECK(!SolanaPay::parseTransactionRequest(oc_s(c["url"]).c_str(), tr), name + " is not a transaction request");
    }
    i = 0;
    for (JsonObject c : vec["pay"]["txRequests"].as<JsonArray>())
    {
        std::string name = "txRequest " + std::to_string(i++) + " " + oc_s(c["link"]);
        PayTransactionRequest r;
        r.link = oc_s(c["link"]).c_str(); r.label = oc_s(c["label"]).c_str(); r.message = oc_s(c["message"]).c_str();
        CHECK(SolanaPay::encodeTransactionRequest(r, &err) == oc_s(c["url"]).c_str(), name + " encode\n    want " + oc_s(c["url"]) + "\n    got  " + SolanaPay::encodeTransactionRequest(r).s);
        PayTransactionRequest p;
        CHECK(SolanaPay::parseTransactionRequest(oc_s(c["url"]).c_str(), p, &err) && p.link == oc_s(c["parsedLink"]).c_str() &&
              p.label == oc_s(c["parsedLabel"]).c_str() && p.message == oc_s(c["parsedMessage"]).c_str(), name + " parse " + err.s);
        PayTransfer t;
        CHECK(!SolanaPay::parseTransfer(oc_s(c["url"]).c_str(), t), name + " is not a transfer");
    }
    for (JsonObject c : vec["pay"]["parse"].as<JsonArray>())
    {
        std::string url = oc_s(c["url"]), name = "parse '" + url.substr(0, 70) + "'";
        PayTransfer t; PayTransactionRequest tr;
        PayUrlKind k = SolanaPay::parse(url.c_str(), t, tr, &err);
        bool wantOk = c["ok"].as<bool>();
        if (url.find("%40") != std::string::npos) { CHECK(k == PayUrlKind::Invalid, name + " (user info in link is rejected on purpose)"); continue; }
        CHECK((k != PayUrlKind::Invalid) == wantOk, name + " verdict " + err.s);
        if (!wantOk)
        {
            if (c.containsKey("error")) CHECK(err == oc_s(c["error"]).c_str(), name + " error '" + err.s + "' want '" + oc_s(c["error"]) + "'");
            continue;
        }
        if (oc_s(c["kind"]) == "tx")
            CHECK(k == PayUrlKind::Transaction && tr.link == oc_s(c["link"]).c_str() && tr.label == oc_s(c["label"]).c_str() && tr.message == oc_s(c["message"]).c_str(), name + " tx fields");
        else
            CHECK(k == PayUrlKind::Transfer && oc_samePay(t, oc_pay(c)), name + " transfer fields");
    }
    {
        PayTransfer t;
        t.recipient = "11111111111111111111111111111112";
        t.amount = "-1";
        CHECK(SolanaPay::encodeTransfer(t, &err).isEmpty() && err == "amount invalid", "encode rejects negative amount");
        t.amount = "1"; t.references.push_back("bad");
        CHECK(SolanaPay::encodeTransfer(t, &err).isEmpty() && err == "reference invalid", "encode rejects bad reference");
        t.references.clear(); t.recipient = "x";
        CHECK(SolanaPay::encodeTransfer(t, &err).isEmpty() && err == "recipient invalid", "encode rejects bad recipient");
        PayTransactionRequest r;
        r.link = "http://example.com/api";
        CHECK(SolanaPay::encodeTransactionRequest(r, &err).isEmpty(), "encode rejects http link");
    }
    for (JsonObject c : vec["pay"]["amounts"].as<JsonArray>())
    {
        std::string name = "amount " + oc_s(c["amount"]) + "/" + std::to_string(c["decimals"].as<int>());
        uint8_t d = c["decimals"].as<int>();
        uint64_t u = 0;
        bool exact = c["exact"].as<bool>();
        bool fits = c["floorFits"].as<bool>();
        bool r = SolanaPay::amountToBaseUnits(oc_s(c["amount"]).c_str(), d, u);
        CHECK(r == (exact && fits), name + " exact verdict");
        if (r) CHECK(std::to_string(u) == oc_s(c["floor"]), name + " exact value");
        r = SolanaPay::amountToBaseUnits(oc_s(c["amount"]).c_str(), d, u, true);
        CHECK(r == c["ceilFits"].as<bool>(), name + " round-up verdict");
        if (r) CHECK(std::to_string(u) == oc_s(c["ceil"]), name + " round-up value");
    }
    uint64_t dummy = 0;
    CHECK(!SolanaPay::amountToBaseUnits("1e3", 6, dummy) && !SolanaPay::amountToBaseUnits("", 6, dummy) &&
          !SolanaPay::amountToBaseUnits("-1", 6, dummy) && !SolanaPay::amountToBaseUnits("1.", 6, dummy), "amountToBaseUnits rejects junk");

    // ---- createPayTransfer against a mock RPC built from the same accounts ----
    for (JsonObject c : vec["pay"]["build"].as<JsonArray>())
    {
        std::string name = "build " + oc_s(c["name"]);
        JsonObject accounts = c["accounts"];
        std::string bh = oc_s(c["blockhash"]);
        g_httpHandler = [&](const std::string &, const std::string &body) -> MockHttpResponse {
            DynamicJsonDocument d(4096);
            deserializeJson(d, body);
            std::string method = oc_s(d["method"]);
            if (method == "getLatestBlockhash") return {200, oc_rpcOk("{\"context\":{\"slot\":1},\"value\":{\"blockhash\":\"" + bh + "\",\"lastValidBlockHeight\":100}}")};
            if (method == "getAccountInfo")
            {
                std::string addr = oc_s(d["params"][0]);
                JsonObject a = accounts[addr];
                if (a.isNull()) return {200, oc_rpcOk("{\"context\":{\"slot\":1},\"value\":null}")};
                bool slice0 = d["params"][1]["dataSlice"]["length"] | 1;
                slice0 = !slice0 && d["params"][1].containsKey("dataSlice");
                std::string data = slice0 ? "" : oc_s(a["data"]);
                return {200, oc_rpcOk("{\"context\":{\"slot\":1},\"value\":{\"lamports\":" + std::to_string(a["lamports"].as<uint64_t>()) + ",\"owner\":\"" + oc_s(a["owner"]) +
                                      "\",\"executable\":" + (a["executable"].as<bool>() ? "true" : "false") + ",\"rentEpoch\":0,\"data\":[\"" + data + "\",\"base64\"]}}")};
            }
            return {200, oc_rpcOk("null")};
        };
        Transaction tx;
        bool ok = sol.createPayTransfer(oc_pay(c["request"]), oc_s(c["sender"]).c_str(), tx, &err);
        CHECK(ok == c["ok"].as<bool>(), name + " verdict " + err.s);
        if (!c["ok"].as<bool>())
        {
            if (c.containsKey("error")) CHECK(err == oc_s(c["error"]).c_str(), name + " error '" + err.s + "' want '" + oc_s(c["error"]) + "'");
            continue;
        }
        if (!ok) continue;
        DecodedMsg a = decodeMsg(tx.serializeMessage()), b = decodeMsg(fromHex(oc_s(c["message"])));
        CHECK(a.ok && a.canon == b.canon && a.header[0] == b.header[0] && a.header[1] == b.header[1] && a.header[2] == b.header[2],
              name + " message\n    want " + b.canon + "\n    got  " + a.canon);
    }

    // ---- validateTransfer ----
    for (JsonObject c : vec["pay"]["validate"].as<JsonArray>())
    {
        std::string name = "validate " + oc_s(c["name"]);
        std::string result = c["rpc"].isNull() ? "null" : oc_s(c["rpc"]);
        g_httpHandler = [&](const std::string &, const std::string &body) -> MockHttpResponse {
            if (body.find("getTransaction") != std::string::npos && body.find("maxSupportedTransactionVersion") != std::string::npos) return {200, oc_rpcOk(result)};
            return {200, oc_rpcOk("null")};
        };
        bool ok = sol.validateTransfer("5sig", oc_pay(c["expected"]), &err);
        CHECK(ok == c["ok"].as<bool>(), name + " verdict (error: " + err.s + ")");
        if (!ok && c.containsKey("error")) CHECK(err == oc_s(c["error"]).c_str(), name + " error '" + err.s + "' want '" + oc_s(c["error"]) + "'");
        if (c["extension"].as<bool>() && c.containsKey("payReferenceOk")) CHECK(c["payReferenceOk"].as<bool>() == false, name + " (@solana/pay itself rejects this)");
    }
    // overload with plain strings
    {
        JsonObject c;
        for (JsonObject v : vec["pay"]["validate"].as<JsonArray>()) if (oc_s(v["name"]) == "spl ok exact") c = v;
        std::string result = oc_s(c["rpc"]);
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, oc_rpcOk(result)}; };
        CHECK(sol.validateTransfer("5sig", oc_s(c["expected"]["recipient"]).c_str(), "2.5", oc_s(c["expected"]["splToken"]).c_str(), oc_s(c["expected"]["reference"][0]).c_str(), &err), "validateTransfer(recipient, amount, token, reference) " + err.s);
        CHECK(!sol.validateTransfer("5sig", oc_s(c["expected"]["recipient"]).c_str(), "2.6", oc_s(c["expected"]["splToken"]).c_str(), "", &err), "validateTransfer overload wrong amount");
        PayTransfer bad;
        bad.recipient = "nope";
        CHECK(!sol.validateTransfer("5sig", bad, &err) && err == "invalid expected transfer", "invalid expected recipient");
        // RPC failures
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad\"}}"}; };
        CHECK(!sol.validateTransfer("5sig", oc_pay(c["expected"]), &err) && err == "RPC request failed", "RPC error object");
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {500, ""}; };
        CHECK(!sol.validateTransfer("5sig", oc_pay(c["expected"]), &err) && err == "RPC request failed", "HTTP 500");
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, oc_rpcOk("{\"meta\":{\"err\":null}}")}; };
        CHECK(!sol.validateTransfer("5sig", oc_pay(c["expected"]), &err), "answer without a transaction");
    }

    // ---- findReference ----
    for (JsonObject c : vec["pay"]["findReference"].as<JsonArray>())
    {
        std::string name = "findReference n=" + std::to_string(c["count"].as<int>());
        JsonArray chain = c["chain"];
        int calls = 0;
        g_httpHandler = [&](const std::string &, const std::string &body) -> MockHttpResponse {
            calls++;
            DynamicJsonDocument d(2048);
            deserializeJson(d, body);
            size_t start = 0;
            std::string before = oc_s(d["params"][1]["before"]);
            if (!before.empty()) { for (size_t k = 0; k < chain.size(); k++) if (oc_s(chain[k]) == before) start = k + 1; }
            size_t limit = d["params"][1]["limit"] | 1000;
            std::string r = "[";
            for (size_t k = start; k < chain.size() && k < start + limit; k++)
                r += std::string(k > start ? "," : "") + "{\"signature\":\"" + oc_s(chain[k]) + "\",\"slot\":1,\"err\":null,\"blockTime\":1,\"confirmationStatus\":\"confirmed\"}";
            return {200, oc_rpcOk(r + "]")};
        };
        String sig;
        bool found = sol.findReference(oc_s(c["reference"]).c_str(), sig, "confirmed", &err);
        CHECK(found == !c["oldest"].isNull(), name + " verdict " + err.s);
        if (found) CHECK(sig == oc_s(c["oldest"]).c_str(), name + " oldest signature");
        else CHECK(err == "not found", name + " error");
        int n = c["count"].as<int>();
        CHECK(calls == (n / 100) + 1, name + " pages " + std::to_string(calls));
    }
    {
        int calls = 0;
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { calls++; return {200, oc_rpcOk("[]")}; };
        String sig, e;
        CHECK(!sol.findReference("not-a-key", sig, "confirmed", &e) && calls == 0 && e == "reference invalid", "invalid reference makes no request");
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32005,\"message\":\"node unhealthy\"}}"}; };
        CHECK(!sol.findReference("11111111111111111111111111111112", sig, "confirmed", &e) && e == "RPC request failed", "findReference RPC error");
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, oc_rpcOk("{\"x\":1}")}; };
        CHECK(!sol.findReference("11111111111111111111111111111112", sig, "confirmed", &e) && e == "unexpected RPC response", "findReference malformed result");
        // failed transactions still count as "found" (validateTransfer rejects them)
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse { return {200, oc_rpcOk("[{\"signature\":\"abc\",\"slot\":1,\"err\":{\"InstructionError\":[0,\"Custom\"]}}]")}; };
        CHECK(sol.findReference("11111111111111111111111111111112", sig, "confirmed", &e) && sig == "abc", "failed transaction is still returned");
    }
}

INFRATIC_TEST(offchain)
{
    oc_offchain(vec);
    oc_siwsTests(vec);
    oc_payTests(sol, vec);
}
