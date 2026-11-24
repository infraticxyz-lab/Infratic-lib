// Commitments, Merkle trees, signed attestations, memo and Anchor storage encoding.
// Reference values: js/gen_zk.mjs (node crypto sha256, tweetnacl, @coral-xyz/anchor, @solana/web3.js).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static std::string zkS(const String &s) { return s.s; }
static std::vector<uint8_t> zkBytes(const std::string &s) { return std::vector<uint8_t>(s.begin(), s.end()); }

// mocks the RPC calls used by the ZK functions and records the transaction that was sent
struct ZkRpc
{
    std::string blockhash;
    long long time = 1767225600;
    bool timeOk = true;
    uint64_t balance = 0;
    bool sendFails = false;
    int sends = 0;
    std::string sentB64;
    void install()
    {
        g_httpHandler = [this](const std::string &, const std::string &body) -> MockHttpResponse {
            auto has = [&](const char *x) { return body.find(x) != std::string::npos; };
            if (has("getLatestBlockhash"))
                return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":{\"blockhash\":\"" + blockhash + "\",\"lastValidBlockHeight\":100}}}"};
            if (has("getSlot")) return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":4242}"};
            if (has("getBlockTime"))
                return {200, timeOk ? "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" + std::to_string(time) + "}"
                                    : "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32004,\"message\":\"Block not available\"}}"};
            if (has("getBalance"))
                return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":" + std::to_string(balance) + "}}"};
            if (has("sendTransaction"))
            {
                sends++;
                if (sendFails) return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32002,\"message\":\"nope\"}}"};
                DynamicJsonDocument d(8192);
                deserializeJson(d, body);
                sentB64 = d["params"][0].as<std::string>();
                return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"5zkSig\"}"};
            }
            if (has("getSignatureStatuses"))
                return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[{\"confirmationStatus\":\"confirmed\",\"err\":null}]}}"};
            return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"};
        };
    }
    // message bytes of the transaction that was sent (skips the signature section)
    std::vector<uint8_t> sentMessage(std::vector<std::vector<uint8_t>> *sigs = nullptr)
    {
        std::vector<uint8_t> raw;
        size_t olen = 0;
        raw.resize(sentB64.size());
        if (mbedtls_base64_decode(raw.data(), raw.size(), &olen, (const unsigned char *)sentB64.c_str(), sentB64.size()) != 0)
            return {};
        raw.resize(olen);
        size_t n = raw.empty() ? 0 : raw[0]; // < 128 signatures
        if (sigs)
            for (size_t i = 0; i < n; i++) sigs->push_back(std::vector<uint8_t>(raw.begin() + 1 + 64 * i, raw.begin() + 65 + 64 * i));
        return std::vector<uint8_t>(raw.begin() + 1 + 64 * n, raw.end());
    }
};

static bool zkSameMessage(const std::vector<uint8_t> &ours, const std::string &wantHex)
{
    DecodedMsg a = decodeMsg(ours), b = decodeMsg(fromHex(wantHex));
    return a.ok && b.ok && a.canon == b.canon && a.header[0] == b.header[0] && a.header[1] == b.header[1] &&
           a.header[2] == b.header[2] && a.payer == b.payer;
}

INFRATIC_TEST(zk)
{
    // ---------------- commitments ----------------
    for (JsonObject c : vec["commit"].as<JsonArray>())
    {
        std::vector<uint8_t> data = fromHex(c["data"].as<std::string>()), secret = fromHex(c["secret"].as<std::string>());
        std::vector<uint8_t> want = fromHex(c["commitment"].as<std::string>()), got;
        CHECK(Infratic::commitDataWithSecret(data, secret, got) && got == want, "commitment known answer len " + std::to_string(data.size()));
        CHECK(Infratic::verifyCommitment(data, secret, want), "commitment verifies");
        std::vector<uint8_t> bad = data;
        bad.push_back(0);
        CHECK(!Infratic::verifyCommitment(bad, secret, want), "extra byte rejected");
        std::vector<uint8_t> bad2 = secret;
        bad2[0] ^= 1;
        CHECK(!Infratic::verifyCommitment(data, bad2, want), "wrong secret rejected");
        std::vector<uint8_t> bad3 = want;
        bad3[31] ^= 0x80;
        CHECK(!Infratic::verifyCommitment(data, secret, bad3), "wrong commitment rejected");
        CHECK(!Infratic::verifyCommitment(data, std::vector<uint8_t>(31), want), "short secret rejected");
        CHECK(!Infratic::verifyCommitment(data, secret, std::vector<uint8_t>(31)), "short commitment rejected");
    }
    {
        // length prefix: moving a byte between data and secret must change the commitment
        std::vector<uint8_t> secret(32, 7), a, b;
        Infratic::commitDataWithSecret(std::vector<uint8_t>{1, 2, 3}, secret, a);
        std::vector<uint8_t> secret2(secret.begin() + 1, secret.end());
        secret2.push_back(0);
        Infratic::commitDataWithSecret(std::vector<uint8_t>{1, 2, 3, 7}, secret2, b);
        CHECK(a != b, "unambiguous data/secret boundary");

        std::vector<uint8_t> c1, s1, c2, s2;
        std::vector<uint8_t> d = zkBytes("temp:25.7C");
        CHECK(Infratic::commitData(d, c1, s1) && Infratic::commitData(d, c2, s2), "random commitments");
        CHECK(s1.size() == 32 && c1.size() == 32 && s1 != s2 && c1 != c2, "fresh secret every time (hiding)");
        CHECK(Infratic::verifyCommitment(d, s1, c1) && !Infratic::verifyCommitment(d, s2, c1), "random commitment opens only with its secret");
        // independent construction of the hash in the test itself
        std::vector<uint8_t> msg = zkBytes("infratic-zk/commit/v1");
        msg.push_back((uint8_t)d.size()); msg.push_back(0); msg.push_back(0); msg.push_back(0);
        msg.insert(msg.end(), d.begin(), d.end());
        msg.insert(msg.end(), s1.begin(), s1.end());
        uint8_t h[32];
        mbedtls_sha256(msg.data(), msg.size(), h, 0);
        CHECK(std::vector<uint8_t>(h, h + 32) == c1, "commitment layout tag||len||data||secret");

        String ch, sh;
        CHECK(Infratic::commitString("hello", ch, sh) && ch.length() == 64 && sh.length() == 64, "string commitment hex sizes");
        CHECK(Infratic::verifyCommitmentString("hello", sh, ch), "string commitment verifies");
        CHECK(!Infratic::verifyCommitmentString("hellO", sh, ch), "string commitment tamper");
        CHECK(!Infratic::verifyCommitmentString("hello", sh.substring(2), ch), "short hex secret rejected");
        CHECK(!Infratic::verifyCommitmentString("hello", "zz" + sh.substring(2), ch), "non hex secret rejected");
        String chUp = ch;
        for (char &x : chUp.s) x = toupper(x);
        CHECK(Infratic::verifyCommitmentString("hello", sh, chUp), "hex is case-insensitive on input");
    }
    {
        JsonObject l = vec["legacyCommit"];
        String data = l["data"].as<const char *>(), st = l["secretText"].as<const char *>();
        String nonce = l["nonce"].as<const char *>(), c = l["commitment"].as<const char *>();
        uint64_t ts = l["ts"].as<uint64_t>();
        CHECK(sol.verifyDataCommitment(data, st, nonce, ts, c), "legacy commitment known answer");
        CHECK(!sol.verifyDataCommitment(data, "other", nonce, ts, c), "legacy: wrong secret text");
        CHECK(!sol.verifyDataCommitment(data, st, nonce, ts + 1, c), "legacy: wrong timestamp");
        CHECK(!sol.verifyDataCommitment("x", st, nonce, ts, c), "legacy: wrong data");
        CHECK(!sol.verifyDataCommitment(data, st, "short", ts, c), "legacy: malformed nonce");
        String c2, n2; uint64_t t2;
        CHECK(sol.createDataCommitment(data, st, c2, n2, t2) && sol.verifyDataCommitment(data, st, n2, t2, c2), "legacy round trip");
    }

    // ---------------- Merkle ----------------
    JsonObject mk = vec["merkle"];
    {
        std::vector<String> rfc;
        for (JsonVariant h : mk["rfc"]["leaves"].as<JsonArray>()) { auto b = fromHex(h.as<std::string>()); rfc.push_back(String((const char *)b.data(), b.size())); }
        String root;
        CHECK(Infratic::buildMerkleTree(rfc, root) && root == mk["rfc"]["root"].as<const char *>(), "RFC 6962 8-leaf test tree root");
        std::vector<String> one(1, String());
        CHECK(Infratic::buildMerkleTree(one, root) && root == mk["emptyLeafHash"].as<const char *>(), "single empty leaf = sha256(0x00)");
        CHECK(!Infratic::buildMerkleTree(std::vector<String>(), root), "empty list rejected");
        MerkleProof p;
        CHECK(!Infratic::createMerkleProof(std::vector<String>(), 0, p) && !p.isValid, "proof for empty list rejected");
    }
    for (JsonObject set : mk["sets"].as<JsonArray>())
    {
        std::vector<String> leaves;
        for (JsonVariant v : set["leaves"].as<JsonArray>()) leaves.push_back(v.as<const char *>());
        std::string n = std::to_string(leaves.size());
        String root;
        CHECK(Infratic::buildMerkleTree(leaves, root) && root == set["root"].as<const char *>(), "root of " + n + " leaves");
        MerkleProof oob;
        CHECK(!Infratic::createMerkleProof(leaves, leaves.size(), oob) && !oob.isValid, "index == size rejected");
        for (size_t i = 0; i < leaves.size(); i++)
        {
            MerkleProof p;
            JsonArray want = set["proofs"][i];
            bool created = Infratic::createMerkleProof(leaves, i, p);
            bool same = created && p.siblings.size() == want.size() && p.root == root && p.index == i && p.leafCount == leaves.size();
            for (size_t k = 0; same && k < want.size(); k++) same = p.siblings[k] == want[k].as<const char *>();
            CHECK(same, "proof " + std::to_string(i) + "/" + n + " equals JS reference");
            CHECK(Infratic::verifyMerkleProof(leaves[i], p, root), "proof " + std::to_string(i) + "/" + n + " verifies");
            if (leaves.size() > 1)
            {
                CHECK(!Infratic::verifyMerkleProof(leaves[(i + 1) % leaves.size()], p, root), "wrong leaf rejected " + std::to_string(i) + "/" + n);
                MerkleProof w = p;
                w.index = (i + 1) % leaves.size();
                CHECK(!Infratic::verifyMerkleProof(leaves[i], w, root), "wrong index rejected " + std::to_string(i) + "/" + n);
                if (!w.siblings.empty())
                {
                    MerkleProof s = p;
                    s.siblings[0] = s.siblings[0].substring(0, 63) + (s.siblings[0].s[63] == '0' ? "1" : "0");
                    CHECK(!Infratic::verifyMerkleProof(leaves[i], s, root), "wrong sibling rejected " + std::to_string(i) + "/" + n);
                    MerkleProof t = p;
                    t.siblings.pop_back();
                    CHECK(!Infratic::verifyMerkleProof(leaves[i], t, root), "truncated path rejected " + std::to_string(i) + "/" + n);
                    MerkleProof e = p;
                    e.siblings.push_back(p.siblings[0]);
                    CHECK(!Infratic::verifyMerkleProof(leaves[i], e, root), "extended path rejected " + std::to_string(i) + "/" + n);
                }
                MerkleProof c = p;
                c.leafCount = 1;
                CHECK(!Infratic::verifyMerkleProof(leaves[i], c, root), "leafCount 1 rejected " + std::to_string(i) + "/" + n);
                c.leafCount = p.leafCount;
                c.index = p.leafCount;
                CHECK(!Infratic::verifyMerkleProof(leaves[i], c, root), "index >= leafCount rejected " + std::to_string(i) + "/" + n);
            }
            String otherRoot = root.substring(0, 63) + (root.s[63] == '0' ? "1" : "0");
            CHECK(!Infratic::verifyMerkleProof(leaves[i], p, otherRoot), "wrong trusted root rejected");
            CHECK(!Infratic::verifyMerkleProof(leaves[i], p, "nothex"), "malformed trusted root rejected");
        }
    }
    {
        // duplicated last leaf must not give the same root (CVE-2012-2459 style)
        std::vector<String> three = {"a", "b", "c"}, four = {"a", "b", "c", "c"};
        String r3, r4;
        Infratic::buildMerkleTree(three, r3);
        Infratic::buildMerkleTree(four, r4);
        CHECK(r3 != r4, "odd leaf is not duplicated");
        std::vector<String> big(4097, "x");
        CHECK(!Infratic::buildMerkleTree(big, r3), "more than 4096 leaves rejected");
        MerkleProof p;
        Infratic::createMerkleProof(three, 2, p);
        CHECK(sol.verifyMerkleProof("c", p), "deprecated self-rooted verify still works");
        p.root = r4;
        CHECK(!sol.verifyMerkleProof("c", p), "deprecated verify with forged root fails");
    }

    // ---------------- attestations / signatures ----------------
    std::vector<uint8_t> sk = b58(vec["key"]["secret"].as<const char *>());
    Keypair dev = Keypair::fromPrivateKey(sk.data());
    String devPub = vec["key"]["pub"].as<const char *>(), otherPub = vec["key"]["otherPub"].as<const char *>();
    {
        JsonObject a = vec["attest"];
        CommitmentAttestation att;
        CHECK(Infratic::createCommitmentAttestation(dev, a["commitment"].as<const char *>(), a["context"].as<const char *>(),
                                                    fromHex(a["publicData"].as<std::string>()), att),
              "attestation created");
        CHECK(att.signature == a["signature"].as<const char *>(), "attestation signature equals tweetnacl: " + zkS(att.signature).substr(0, 16));
        CHECK(att.signer == devPub, "attestation signer");
        CHECK(Infratic::verifyCommitmentAttestation(att, devPub), "attestation verifies");
        CHECK(!Infratic::verifyCommitmentAttestation(att, otherPub), "other expected signer rejected");
        CHECK(!Infratic::verifyCommitmentAttestation(att, ""), "empty expected signer rejected");
        CommitmentAttestation t = att;
        t.context = "temp-sensor/v2";
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "context tamper");
        t = att; t.publicData[0] ^= 1;
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "public data tamper");
        t = att; t.commitment = t.commitment.substring(0, 63) + (t.commitment.s[63] == '0' ? "1" : "0");
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "commitment tamper");
        t = att; t.signature = t.signature.substring(0, 127) + (t.signature.s[127] == '0' ? "1" : "0");
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "signature tamper");
        t = att; t.signer = otherPub;
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "swapped signer field rejected");
        t = att; t.signature = "00";
        CHECK(!Infratic::verifyCommitmentAttestation(t, devPub), "short signature rejected");
        // ambiguity: moving bytes between context and publicData must change the statement
        CommitmentAttestation m1, m2;
        Infratic::createCommitmentAttestation(dev, a["commitment"].as<const char *>(), "ab", std::vector<uint8_t>{'c'}, m1);
        Infratic::createCommitmentAttestation(dev, a["commitment"].as<const char *>(), "a", std::vector<uint8_t>{'b', 'c'}, m2);
        CHECK(m1.signature != m2.signature, "context/publicData boundary is length prefixed");
        CommitmentAttestation e;
        CHECK(Infratic::createCommitmentAttestation(dev, vec["attestEmpty"]["commitment"].as<const char *>(), "", std::vector<uint8_t>(), e) &&
                  e.signature == vec["attestEmpty"]["signature"].as<const char *>(), "empty context/data attestation equals tweetnacl");
        CHECK(!Infratic::createCommitmentAttestation(dev, "abcd", "x", std::vector<uint8_t>(), e), "bad commitment hex rejected");
        Keypair empty;
        CHECK(!Infratic::createCommitmentAttestation(empty, a["commitment"].as<const char *>(), "x", std::vector<uint8_t>(), e), "keypair without private key rejected");
        Keypair broken = dev;
        broken.privkey[40] ^= 1; // public half does not match the seed
        CHECK(!Infratic::createCommitmentAttestation(broken, a["commitment"].as<const char *>(), "x", std::vector<uint8_t>(), e), "inconsistent keypair rejected");
    }
    {
        JsonObject t = vec["timestamp"];
        std::vector<uint8_t> data = zkBytes(t["data"].as<std::string>());
        SignedTimestamp ts;
        CHECK(Infratic::signTimestamp(dev, data, t["time"].as<int64_t>(), t["blockhash"].as<const char *>(), ts), "timestamp signed");
        CHECK(ts.dataHash == t["hash"].as<const char *>() && ts.signature == t["signature"].as<const char *>(), "timestamp equals tweetnacl");
        CHECK(Infratic::verifySignedTimestamp(ts, data, devPub), "timestamp verifies");
        CHECK(!Infratic::verifySignedTimestamp(ts, zkBytes("other"), devPub), "timestamp wrong data");
        CHECK(!Infratic::verifySignedTimestamp(ts, data, otherPub), "timestamp wrong signer");
        SignedTimestamp x = ts; x.unixTime += 1;
        CHECK(!Infratic::verifySignedTimestamp(x, data, devPub), "timestamp time tamper");
        x = ts; x.blockhash = "";
        CHECK(!Infratic::verifySignedTimestamp(x, data, devPub), "timestamp blockhash tamper");
        x = ts; x.dataHash = x.dataHash.substring(0, 63) + (x.dataHash.s[63] == '0' ? "1" : "0");
        CHECK(!Infratic::verifySignedTimestamp(x, data, devPub), "timestamp hash tamper");
        SignedTimestamp nb;
        CHECK(Infratic::signTimestamp(dev, data, t["time"].as<int64_t>(), "", nb) && nb.signature == t["signatureNoBlockhash"].as<const char *>(), "timestamp without blockhash equals tweetnacl");

        // over RPC
        ZkRpc rpc;
        rpc.blockhash = t["blockhash"].as<const char *>();
        rpc.time = t["time"].as<long long>();
        rpc.install();
        SignedTimestamp r;
        CHECK(sol.createSignedTimestamp(dev, data, r) && r.unixTime == rpc.time && r.blockhash == rpc.blockhash.c_str() &&
                  r.signature == ts.signature, "createSignedTimestamp uses cluster time and blockhash");
        rpc.timeOk = false;
        SignedTimestamp r2;
        CHECK(!sol.createSignedTimestamp(dev, data, r2), "no cluster time = no timestamp (no uptime fallback)");
        String lp; uint64_t lt; String lb;
        CHECK(!sol.createTimestampedProof("d", lp, lt, lb), "legacy timestamped proof also needs cluster time");
        rpc.timeOk = true;
        JsonObject lg = vec["legacyTime"];
        rpc.blockhash = lg["blockhash"].as<const char *>();
        rpc.time = lg["ts"].as<long long>();
        CHECK(sol.createTimestampedProof("old-data", lp, lt, lb) && lp == lg["proof"].as<const char *>() && lt == lg["ts"].as<uint64_t>() &&
                  lb == lg["blockhash"].as<const char *>(), "legacy timestamped proof known answer");
        CHECK(sol.verifyTimestampedProof("old-data", lp, lt, lb), "legacy timestamped proof verifies");
        CHECK(!sol.verifyTimestampedProof("old-data!", lp, lt, lb) && !sol.verifyTimestampedProof("old-data", lp, lt + 1, lb) &&
                  !sol.verifyTimestampedProof("old-data", lp, lt, "x") && !sol.verifyTimestampedProof("old-data", "zz", lt, lb), "legacy timestamped proof tamper");
    }
    {
        JsonObject r = vec["range"];
        RangeAttestation ra;
        std::vector<uint8_t> secret;
        CHECK(Infratic::createRangeAttestation(dev, r["value"].as<int64_t>(), r["min"].as<int64_t>(), r["max"].as<int64_t>(), ra, secret), "range attestation created");
        CHECK(!ra.commitment.isEmpty() && secret.size() == 32, "range attestation has commitment and secret");
        CHECK(Infratic::verifyRangeAttestation(ra, devPub), "range attestation verifies without the value");
        CHECK(Infratic::openRangeAttestation(ra, r["value"].as<int64_t>(), secret, devPub), "opening with the right value");
        CHECK(!Infratic::openRangeAttestation(ra, r["value"].as<int64_t>() + 1, secret, devPub), "opening with another in-range value fails");
        CHECK(!Infratic::openRangeAttestation(ra, 1000, secret, devPub), "opening with out-of-range value fails");
        std::vector<uint8_t> bad = secret; bad[3] ^= 1;
        CHECK(!Infratic::openRangeAttestation(ra, r["value"].as<int64_t>(), bad, devPub), "opening with wrong secret fails");
        CHECK(!Infratic::verifyRangeAttestation(ra, otherPub), "range attestation wrong signer");
        RangeAttestation w = ra; w.maxValue += 1;
        CHECK(!Infratic::verifyRangeAttestation(w, devPub), "widened range rejected");
        w = ra; w.minValue -= 1;
        CHECK(!Infratic::verifyRangeAttestation(w, devPub), "widened min rejected");
        RangeAttestation o; std::vector<uint8_t> so;
        CHECK(!Infratic::createRangeAttestation(dev, 101, 0, 100, o, so), "value above range cannot be attested");
        CHECK(!Infratic::createRangeAttestation(dev, -1, 0, 100, o, so), "value below range cannot be attested");
        CHECK(!Infratic::createRangeAttestation(dev, 5, 10, 0, o, so), "inverted range rejected");
        // known answer: JS commitment/signature for the same secret
        std::vector<uint8_t> js = fromHex(r["secret"].as<std::string>()), c;
        std::vector<uint8_t> v(8);
        int64_t val = r["value"].as<int64_t>();
        for (int i = 0; i < 8; i++) v[i] = (uint8_t)((uint64_t)val >> (8 * i));
        CHECK(Infratic::commitDataWithSecret(v, js, c) && toHex(c) == r["commitment"].as<std::string>(), "range commitment equals JS");
        RangeAttestation k;
        k.commitment = r["commitment"].as<const char *>(); k.minValue = r["min"].as<int64_t>(); k.maxValue = r["max"].as<int64_t>();
        k.signer = devPub; k.signature = r["signature"].as<const char *>();
        CHECK(Infratic::verifyRangeAttestation(k, devPub), "tweetnacl range signature verifies in C++");
    }

    // ---------------- deprecated placeholders now fail closed ----------------
    {
        zkSNARKProof p; p.isValid = true;
        CHECK(!sol.createzkSNARKProof(zkBytes("x"), zkBytes("y"), "c", p) && !p.isValid && p.proofData.empty(), "fake zkSNARK prover refuses");
        zkSNARKProof forged;
        forged.proofData.assign(96, 1);
        forged.publicInputs = zkBytes("y");
        CHECK(!sol.verifyzkSNARKProof(forged, zkBytes("y")), "forged zkSNARK is not accepted");
        RangeProof rp;
        CHECK(!sol.createRangeProof(5, 0, 10, "s", rp) && !rp.isValid, "fake range proof creation refuses");
        rp.minValue = 0; rp.maxValue = 10;
        CHECK(!sol.verifyRangeProof(5, "s", rp), "fake range proof verification refuses");
    }

    // ---------------- batch ----------------
    {
        std::vector<String> items = {"r1", "r2", "r3"};
        std::vector<ZKCommitment> cs;
        CHECK(sol.createBatchCommitments(items, "", cs) && cs.size() == 3, "batch commitments");
        bool open = true;
        for (size_t i = 0; i < cs.size(); i++) open = open && Infratic::verifyCommitmentString(items[i], cs[i].nonce, cs[i].commitment);
        CHECK(open && cs[0].nonce != cs[1].nonce, "each batch item opens with its own secret");
        CHECK(!sol.createBatchCommitments(std::vector<String>(), "", cs) && cs.empty(), "empty batch is an error");
    }

    // ---------------- memo on chain ----------------
    JsonObject an = vec["anchor"];
    {
        ZkRpc rpc;
        rpc.blockhash = an["blockhash"].as<const char *>();
        rpc.install();
        std::vector<uint8_t> k = b58(an["authoritySecret"].as<const char *>());
        String secret = an["authoritySecret"].as<const char *>(), pub = an["authority"].as<const char *>();
        JsonObject m = vec["memo"];
        String sig;
        CHECK(sol.storeCommitmentOnChain(secret, pub, m["commitment"].as<const char *>(), "", sig) && sig == "5zkSig", "memo sent, signature returned");
        std::vector<std::vector<uint8_t>> sigs;
        std::vector<uint8_t> msg = rpc.sentMessage(&sigs);
        CHECK(zkSameMessage(msg, m["plain"]["message"].as<std::string>()), "memo transaction equals web3.js");
        CHECK(sigs.size() == 1 && Ed25519::verify(sigs[0].data(), k.data() + 32, msg.data(), msg.size()), "memo transaction signature valid");
        CHECK(sol.storeCommitmentOnChain(secret, pub, m["commitment"].as<const char *>(), m["metadata"].as<const char *>(), sig), "memo with metadata sent");
        CHECK(zkSameMessage(rpc.sentMessage(), m["withMeta"]["message"].as<std::string>()), "memo with metadata equals web3.js");
        int before = rpc.sends;
        CHECK(!sol.storeCommitmentOnChain(secret, pub, "deadbeef", "", sig), "short commitment rejected");
        CHECK(!sol.storeCommitmentOnChain(secret, pub, std::string(64, 'g').c_str(), "", sig), "non-hex commitment rejected");
        CHECK(!sol.storeCommitmentOnChain(secret, pub, m["commitment"].as<const char *>(), String(std::string(401, 'x').c_str()), sig), "metadata over 400 bytes rejected");
        CHECK(!sol.storeCommitmentOnChain(secret, otherPub, m["commitment"].as<const char *>(), "", sig), "payer that does not match the key is rejected");
        CHECK(rpc.sends == before, "nothing was sent for invalid input");
        rpc.sendFails = true;
        CHECK(!sol.storeCommitmentOnChain(secret, pub, m["commitment"].as<const char *>(), "", sig), "RPC send error reported");
        rpc.sendFails = false;

        // batch root goes into the memo
        std::vector<String> items = {"r1", "r2", "r3"};
        std::vector<ZKCommitment> cs;
        sol.createBatchCommitments(items, "", cs);
        std::vector<String> leaves;
        for (auto &c : cs) leaves.push_back(c.commitment);
        String root;
        Infratic::buildMerkleTree(leaves, root);
        CHECK(sol.storeBatchCommitmentsOnChain(secret, pub, cs, sig), "batch commitments stored");
        // the memo data is the last instruction data of the sent message
        std::vector<uint8_t> bm = rpc.sentMessage();
        std::string want = "ZK_COMMITMENT:" + root.s + "|META:batch_size:3";
        CHECK(toHex(bm).find(toHex(zkBytes(want))) != std::string::npos, "batch memo carries the Merkle root and size");
        CHECK(!sol.storeBatchCommitmentsOnChain(secret, pub, std::vector<ZKCommitment>(), sig), "empty batch not stored");
    }

    // ---------------- Anchor instruction encoding ----------------
    {
        ZkRpc rpc;
        rpc.blockhash = an["blockhash"].as<const char *>();
        rpc.time = an["clusterTime"].as<long long>();
        rpc.install();
        String secret = an["authoritySecret"].as<const char *>(), auth = an["authority"].as<const char *>();
        String prog = an["program"].as<const char *>(), seed = an["seedName"].as<const char *>();
        String meta = an["metadata"].as<const char *>(), hash = an["hash"].as<const char *>();
        std::vector<uint8_t> k = b58(secret);

        // discriminators
        for (const char *n : {"initialize_storage", "store_commitment", "update_commitment", "store_merkle_root", "store_batch"})
            CHECK(toHex(sol.calculateDiscriminator(n)) == an["discriminators"][n].as<std::string>(), std::string("discriminator ") + n);

        auto checkCall = [&](const char *name, bool ok, const char *label) {
            CHECK(ok, std::string(label) + " call succeeds");
            std::vector<std::vector<uint8_t>> sigs;
            std::vector<uint8_t> msg = rpc.sentMessage(&sigs);
            CHECK(zkSameMessage(msg, an["calls"][name]["message"].as<std::string>()), std::string(label) + " message equals web3.js + anchor BorshCoder");
            DecodedMsg d = decodeMsg(msg);
            CHECK(d.canon.find(an["calls"][name]["data"].as<std::string>()) != std::string::npos, std::string(label) + " instruction data equals BorshCoder");
            CHECK(sigs.size() == 1 && Ed25519::verify(sigs[0].data(), k.data() + 32, msg.data(), msg.size()), std::string(label) + " signature valid");
        };

        String pda, sig;
        rpc.balance = 0;
        checkCall("initialize", sol.initializeZKStorage(secret, auth, prog, seed, pda, sig), "initialize_storage");
        CHECK(pda == an["pda"].as<const char *>(), "initialize returns the PDA derived by web3.js");
        int sends = rpc.sends;
        rpc.balance = 5000;
        CHECK(sol.initializeZKStorage(secret, auth, prog, seed, pda, sig) && sig == "EXISTING_ACCOUNT" && rpc.sends == sends, "existing account is not initialized again");
        rpc.balance = 0;

        checkCall("store", sol.storeCommitmentInAnchor(secret, auth, prog, seed, hash, meta, sig), "store_commitment");
        checkCall("update", sol.updateCommitmentInAnchor(secret, auth, prog, seed, hash, meta, sig), "update_commitment");
        checkCall("merkle", sol.storeMerkleRootInAnchor(secret, auth, prog, seed, hash, 37, meta, sig), "store_merkle_root");
        checkCall("batch", sol.storeBatchInAnchor(secret, auth, prog, an["batchId"].as<const char *>(), hash, 5, meta, sig), "store_batch");

        // invalid input never reaches the network
        sends = rpc.sends;
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, seed, "abcd", meta, sig), "short hash rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, seed, hash.substring(0, 62) + "zz", meta, sig), "non-hex hash rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, seed, hash + "00", meta, sig), "long hash rejected");
        CHECK(!sol.storeMerkleRootInAnchor(secret, auth, prog, seed, "", 1, meta, sig), "empty root rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, vec["key"]["pub"].as<const char *>(), prog, seed, hash, meta, sig), "key that does not belong to the authority rejected");
        CHECK(!sol.storeCommitmentInAnchor("abc", auth, prog, seed, hash, meta, sig), "bad private key rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, "abc", seed, hash, meta, sig), "bad program id rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, String(std::string(33, 's').c_str()), hash, meta, sig), "seed over 32 bytes rejected");
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, seed, hash, String(std::string(1200, 'm').c_str()), sig), "transaction over 1232 bytes rejected");
        CHECK(rpc.sends == sends, "no transaction sent for invalid input");
        rpc.timeOk = false;
        CHECK(!sol.storeCommitmentInAnchor(secret, auth, prog, seed, hash, meta, sig) && rpc.sends == sends, "no cluster time = no timestamped call");
        rpc.timeOk = true;
        rpc.sendFails = true;
        CHECK(!sol.storeMerkleRootInAnchor(secret, auth, prog, seed, hash, 1, meta, sig), "RPC error reported");
    }
}

#pragma GCC diagnostic pop
