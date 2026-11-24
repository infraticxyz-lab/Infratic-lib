// More RPC methods (src/Infratic-rpc.cpp). Mock answers and expected values come from
// @solana/web3.js (js/gen_rpc.mjs): web3.js validated each answer, parsed it and recorded
// the request it sends. We check the request body of the library against it and the parsed values.

namespace rpct
{
    std::vector<std::string> bodies;
    std::vector<std::string> answers; // consumed in order, the last one repeats
    size_t next = 0;

    static void mock(const std::vector<std::string> &a, int http = 200)
    {
        bodies.clear();
        answers = a;
        next = 0;
        g_httpHandler = [http](const std::string &, const std::string &body) -> MockHttpResponse {
            bodies.push_back(body);
            std::string r = answers[next < answers.size() ? next : answers.size() - 1];
            next++;
            return {http, r};
        };
    }
    static std::string ser(JsonVariantConst v) { std::string s; serializeJson(v, s); return s; }

    // every field of `want` must be present and equal in `got` (got may have more object fields)
    static bool subset(JsonVariantConst want, JsonVariantConst got)
    {
        if (want.is<JsonObjectConst>())
        {
            if (!got.is<JsonObjectConst>()) return false;
            for (JsonPairConst kv : want.as<JsonObjectConst>())
                if (!subset(kv.value(), got[kv.key()])) return false;
            return true;
        }
        if (want.is<JsonArrayConst>())
        {
            if (!got.is<JsonArrayConst>() || want.size() != got.size()) return false;
            for (size_t i = 0; i < want.size(); i++)
                if (!subset(want[i], got[i])) return false;
            return true;
        }
        return ser(want) == ser(got);
    }

    // last request sent must have the method and params web3.js sends (library may add options)
    static bool sameRequest(JsonVariantConst want, const std::string &body, size_t idx = (size_t)-1)
    {
        DynamicJsonDocument d(1 << 16);
        const std::string &b = idx == (size_t)-1 ? bodies.back() : bodies[idx];
        (void)body;
        if (deserializeJson(d, b)) return false;
        return d["method"] == want["method"] && subset(want["params"], d["params"]);
    }
    static bool sameRequest(JsonVariantConst want, size_t idx = (size_t)-1) { return sameRequest(want, "", idx); }

    static std::string rpcErr(int code, const char *msg)
    {
        return std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":") + std::to_string(code) + ",\"message\":\"" + msg + "\"}}";
    }
    static std::string answer(JsonVariantConst v) { return v.as<std::string>(); } // responses are stored as strings

    static bool acc(const AccountInfo &a, JsonVariantConst e)
    {
        if (a.exists != e["exists"].as<bool>()) return false;
        if (!a.exists) return a.data.empty() && a.lamports == 0;
        return a.lamports == e["lamports"].as<uint64_t>() && std::string(a.owner.c_str()) == e["owner"].as<std::string>() &&
               a.executable == e["executable"].as<bool>() && a.rentEpoch == e["rentEpoch"].as<uint64_t>() &&
               toHex(a.data) == e["dataHex"].as<std::string>();
    }
    static bool strs(const std::vector<String> &v, JsonArrayConst e)
    {
        if (v.size() != e.size()) return false;
        for (size_t i = 0; i < v.size(); i++)
            if (std::string(v[i].c_str()) != e[i].as<std::string>()) return false;
        return true;
    }
    template <typename T> static bool nums(const std::vector<T> &v, JsonArrayConst e)
    {
        if (v.size() != e.size()) return false;
        for (size_t i = 0; i < v.size(); i++)
            if ((int64_t)v[i] != e[i].as<int64_t>()) return false;
        return true;
    }
}

INFRATIC_TEST(rpc)
{
    using namespace rpct;
    const String KEY = "So11111111111111111111111111111111111111112";

    // ---- getSlot / getHealth / getVersion --------------------------------------------
    {
        uint64_t slot = 0;
        mock({answer(vec["getSlot"]["response"])});
        CHECK(sol.getSlot(slot) && slot == vec["getSlot"]["expected"].as<uint64_t>(), "getSlot value");
        CHECK(sameRequest(vec["getSlot"]["request"]), "getSlot request " + bodies.back());
        mock({answer(vec["getSlot"]["response"])});
        CHECK(sol.getSlot(slot, "finalized") && bodies.back().find("\"finalized\"") != std::string::npos, "getSlot commitment");
        CHECK(!sol.getSlot(slot, "bogus") && bodies.size() == 1, "getSlot rejects bad commitment without a request");
        mock({rpcErr(-32005, "Node is behind by 100 slots")});
        CHECK(!sol.getSlot(slot), "getSlot rpc error");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"});
        CHECK(!sol.getSlot(slot), "getSlot null result");

        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}"});
        CHECK(sol.getHealth(), "getHealth ok");
        CHECK(sameRequest(vec["getHealth"]["request"]), "getHealth request " + bodies.back());
        mock({rpcErr(-32005, "Node is unhealthy")});
        CHECK(!sol.getHealth(), "getHealth unhealthy (RPC error)");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"behind\"}"});
        CHECK(!sol.getHealth(), "getHealth other result");
        mock({"x"}, 500);
        CHECK(!sol.getHealth(), "getHealth http 500");

        String ver;
        mock({answer(vec["getVersion"]["response"])});
        CHECK(sol.getVersion(ver) && ver == vec["getVersion"]["expected"].as<const char *>(), "getVersion value " + std::string(ver.c_str()));
        CHECK(sameRequest(vec["getVersion"]["request"]), "getVersion request");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"feature-set\":1}}"});
        CHECK(!sol.getVersion(ver), "getVersion without solana-core");
    }

    // ---- getBalance with commitment ---------------------------------------------------
    {
        JsonVariant c = vec["getBalance"];
        uint64_t bal = 0;
        mock({answer(c["response"])});
        CHECK(sol.getSolBalance(c["key"].as<const char *>(), bal, "finalized") && bal == c["expected"].as<uint64_t>(), "getBalance value");
        CHECK(sameRequest(c["request"]), "getBalance request " + bodies.back());
        mock({answer(c["response"])});
        CHECK(sol.getSolBalance(c["key"].as<const char *>(), bal) && bodies.back().find("commitment") == std::string::npos, "old 2-arg getSolBalance unchanged");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":null}}"});
        CHECK(!sol.getSolBalance(c["key"].as<const char *>(), bal, "confirmed"), "getBalance null value");
        mock({answer(c["response"])});
        CHECK(!sol.getSolBalance("not a key\"", bal, "confirmed") && bodies.empty(), "getBalance rejects bad address");
    }

    // ---- getAccountInfo ---------------------------------------------------------------
    {
        JsonVariant c = vec["getAccountInfo"];
        AccountInfo a;
        mock({answer(c["response"])});
        CHECK(sol.getAccountInfo(c["key"].as<const char *>(), a) && acc(a, c["expected"]), "getAccountInfo parsed");
        CHECK(sameRequest(c["request"]) && bodies.back().find("\"base64\"") != std::string::npos, "getAccountInfo request " + bodies.back());
        CHECK(a.executable && a.data.size() == 40, "getAccountInfo executable flag / size");

        JsonVariant n = vec["getAccountInfoNull"];
        AccountInfo b;
        b.lamports = 77;
        mock({answer(n["response"])});
        CHECK(sol.getAccountInfo(n["key"].as<const char *>(), b) && acc(b, n["expected"]) && !b.exists, "getAccountInfo null -> exists=false");
        mock({rpcErr(-32602, "Invalid param: could not find account")});
        CHECK(!sol.getAccountInfo(KEY, b), "getAccountInfo rpc error");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1}}}"});
        CHECK(!sol.getAccountInfo(KEY, b), "getAccountInfo without value field");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":{\"lamports\":1,\"owner\":\"x\",\"data\":[\"!!notb64\",\"base64\"]}}}"});
        CHECK(!sol.getAccountInfo(KEY, b), "getAccountInfo bad base64");
        CHECK(!sol.getAccountInfo("short", b), "getAccountInfo invalid address");
        // u64 max rent epoch (what the runtime reports for rent exempt accounts)
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":1,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":18446744073709551615,\"space\":0}}}"});
        CHECK(sol.getAccountInfo(KEY, b) && b.exists && b.data.empty() && b.rentEpoch == 18446744073709551615ULL, "getAccountInfo rentEpoch u64 max");
    }

    // ---- getMultipleAccounts ----------------------------------------------------------
    {
        JsonVariant c = vec["getMultipleAccounts"];
        std::vector<String> keys;
        for (JsonVariant k : c["keys"].as<JsonArray>()) keys.push_back(k.as<String>());
        std::vector<AccountInfo> out;
        mock({answer(c["response"])});
        bool ok = sol.getMultipleAccounts(keys, out);
        CHECK(ok && out.size() == 3 && bodies.size() == 1, "getMultipleAccounts count");
        bool all = ok;
        for (size_t i = 0; ok && i < out.size(); i++) all = all && acc(out[i], c["expected"][i]);
        CHECK(all, "getMultipleAccounts parsed (exists / null / empty data)");
        CHECK(sameRequest(c["request"]) && bodies.back().find("\"base64\"") != std::string::npos, "getMultipleAccounts request " + bodies.back());
        CHECK(out.size() == 3 && !out[1].exists, "getMultipleAccounts null entry");

        // 250 keys -> 100 + 100 + 50
        JsonVariant m = vec["getMultipleAccountsMany"];
        keys.clear();
        for (JsonVariant k : m["keys"].as<JsonArray>()) keys.push_back(k.as<String>());
        std::vector<std::string> ans;
        for (JsonVariant ch : m["chunks"].as<JsonArray>()) ans.push_back(answer(ch["response"]));
        mock(ans);
        ok = sol.getMultipleAccounts(keys, out, "confirmed");
                CHECK(ok && bodies.size() == 3 && out.size() == 250, "getMultipleAccounts 250 keys -> 3 calls, 250 results");
        bool reqs = bodies.size() == 3;
        for (size_t i = 0; reqs && i < 3; i++) reqs = sameRequest(m["chunks"][i]["request"], i);
        CHECK(reqs, "getMultipleAccounts chunk requests are keys[0..100), [100..200), [200..250)");
        bool vals = ok && out.size() == 250;
        for (size_t i = 0; vals && i < 250; i++) vals = acc(out[i], m["chunks"][i / 100]["expected"][i % 100]);
        CHECK(vals, "getMultipleAccounts chunked results in key order");

        // exactly 100 keys: one call; 101: two calls
        std::vector<String> k100(keys.begin(), keys.begin() + 100), k101(keys.begin(), keys.begin() + 101);
        mock({answer(m["chunks"][0]["response"]), answer(m["chunks"][0]["response"])});
        CHECK(sol.getMultipleAccounts(k100, out) && bodies.size() == 1 && out.size() == 100, "getMultipleAccounts 100 keys -> 1 call");
        mock({answer(m["chunks"][0]["response"]), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[null]}}"});
        CHECK(sol.getMultipleAccounts(k101, out) && bodies.size() == 2 && out.size() == 101 && !out[100].exists, "getMultipleAccounts 101 keys -> 2 calls");

        // failures
        mock({answer(m["chunks"][0]["response"]), rpcErr(-32005, "busy")});
        CHECK(!sol.getMultipleAccounts(k101, out) && out.empty(), "getMultipleAccounts: failing 2nd chunk -> false, nothing half filled");
        mock({answer(c["response"])});
        CHECK(!sol.getMultipleAccounts(std::vector<String>(keys.begin(), keys.begin() + 2), out), "getMultipleAccounts wrong result count");
        mock({"{}"});
        CHECK(sol.getMultipleAccounts(std::vector<String>(), out) && out.empty() && bodies.empty(), "getMultipleAccounts empty list: no request");
        std::vector<String> bad = {KEY, "bad key"};
        CHECK(!sol.getMultipleAccounts(bad, out) && bodies.empty(), "getMultipleAccounts invalid key: no request");
    }

    // ---- getTokenAccountsByOwner ------------------------------------------------------
    {
        const char *names[2] = {"getTokenAccountsByOwner", "getTokenAccountsByOwner2022"};
        for (int n = 0; n < 2; n++)
        {
            JsonVariant c = vec[names[n]];
            std::vector<TokenAccount> t;
            mock({answer(c["response"])});
            bool ok = sol.getTokenAccountsByOwner(c["owner"].as<const char *>(), t, c["program"].as<const char *>());
            CHECK(ok && t.size() == 3, std::string(names[n]) + " count");
            CHECK(sameRequest(c["request"]) && bodies.back().find("jsonParsed") != std::string::npos, std::string(names[n]) + " request " + bodies.back());
            bool same = ok && t.size() == 3;
            for (size_t i = 0; same && i < 3; i++)
            {
                JsonVariant e = c["expected"][i];
                same = std::string(t[i].address.c_str()) == e["address"].as<std::string>() &&
                       std::string(t[i].mint.c_str()) == e["mint"].as<std::string>() &&
                       std::string(t[i].owner.c_str()) == e["owner"].as<std::string>() &&
                       std::to_string((unsigned long long)t[i].amount) == e["amount"].as<std::string>() &&
                       t[i].decimals == e["decimals"].as<int>() &&
                       std::string(t[i].uiAmount.c_str()) == e["uiAmount"].as<std::string>() &&
                       t[i].frozen == e["frozen"].as<bool>();
            }
            CHECK(same, std::string(names[n]) + " fields");
            CHECK(ok && t[1].amount == 18446744073709551615ULL && t[1].frozen && t[1].decimals == 9 && !t[0].frozen && t[2].amount == 0,
                  std::string(names[n]) + " u64 max / frozen / zero");
        }
        // default program is the SPL token program
        std::vector<TokenAccount> t;
        mock({answer(vec["getTokenAccountsByOwner"]["response"])});
        CHECK(sol.getTokenAccountsByOwner(KEY, t) && bodies.back().find(INFRATIC_TOKEN_PROGRAM_ID) != std::string::npos, "getTokenAccountsByOwner default program");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[]}}"});
        t.resize(2);
        CHECK(sol.getTokenAccountsByOwner(KEY, t) && t.empty(), "getTokenAccountsByOwner no accounts");
        // entry whose data is not parsed (unknown layout) is skipped
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[{\"pubkey\":\"" + std::string(KEY.c_str()) + "\",\"account\":{\"data\":[\"AQID\",\"base64\"],\"lamports\":1}}]}}"});
        CHECK(sol.getTokenAccountsByOwner(KEY, t) && t.empty(), "getTokenAccountsByOwner skips unparsed accounts");
        mock({rpcErr(-32602, "Invalid param: could not find mint")});
        CHECK(!sol.getTokenAccountsByOwner(KEY, t), "getTokenAccountsByOwner rpc error");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"});
        CHECK(!sol.getTokenAccountsByOwner(KEY, t), "getTokenAccountsByOwner null result");
        CHECK(!sol.getTokenAccountsByOwner(KEY, t, "bad program") , "getTokenAccountsByOwner invalid program id");
    }

    // ---- getTokenSupply ---------------------------------------------------------------
    {
        JsonVariant c = vec["getTokenSupply"];
        uint64_t amount = 0;
        uint8_t dec = 0;
        mock({answer(c["response"])});
        CHECK(sol.getTokenSupply(c["mint"].as<const char *>(), amount, dec) &&
                  std::to_string((unsigned long long)amount) == c["expected"]["amount"].as<std::string>() && dec == c["expected"]["decimals"].as<int>(),
              "getTokenSupply value");
        CHECK(sameRequest(c["request"]), "getTokenSupply request " + bodies.back());
        mock({rpcErr(-32602, "Invalid param: not a Token mint")});
        CHECK(!sol.getTokenSupply(KEY, amount, dec), "getTokenSupply rpc error");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":{\"decimals\":6}}}"});
        CHECK(!sol.getTokenSupply(KEY, amount, dec), "getTokenSupply without amount");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":{\"amount\":\"18446744073709551615\",\"decimals\":0}}}"});
        CHECK(sol.getTokenSupply(KEY, amount, dec) && amount == 18446744073709551615ULL && dec == 0, "getTokenSupply u64 max");
    }

    // ---- getSignatureStatuses ---------------------------------------------------------
    {
        JsonVariant c = vec["getSignatureStatuses"];
        std::vector<String> sigs;
        for (JsonVariant s : c["sigs"].as<JsonArray>()) sigs.push_back(s.as<String>());
        std::vector<SignatureStatus> st;
        mock({answer(c["response"])});
        bool ok = sol.getSignatureStatuses(sigs, st);
        CHECK(ok && st.size() == 4, "getSignatureStatuses count");
        CHECK(sameRequest(c["request"]) && bodies.back().find("searchTransactionHistory") == std::string::npos, "getSignatureStatuses request " + bodies.back());
        bool same = ok && st.size() == 4;
        for (size_t i = 0; same && i < 4; i++)
        {
            JsonVariant e = c["expected"][i];
            same = st[i].found == e["found"].as<bool>();
            if (same && st[i].found)
                same = st[i].slot == e["slot"].as<uint64_t>() && std::string(st[i].confirmationStatus.c_str()) == e["confirmationStatus"].as<std::string>() &&
                       st[i].failed == e["failed"].as<bool>() && std::string(st[i].err.c_str()) == e["err"].as<std::string>();
        }
        CHECK(same, "getSignatureStatuses fields");
        CHECK(ok && st[0].found && !st[0].failed && st[0].err.isEmpty() && !st[1].found && st[2].failed && st[3].failed, "getSignatureStatuses ok / null / err object / err string");
        CHECK(ok && std::string(st[2].err.c_str()) == "{\"InstructionError\":[2,{\"Custom\":6001}]}" && std::string(st[3].err.c_str()) == "\"BlockhashNotFound\"", "getSignatureStatuses err JSON");

        mock({answer(c["response"])});
        CHECK(sol.getSignatureStatuses(sigs, st, true) && sameRequest(vec["getSignatureStatusesHistory"]["request"]), "getSignatureStatuses searchHistory request " + bodies.back());
        // confirmationStatus null on old signatures
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[{\"slot\":5,\"confirmations\":null,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":null}]}}"});
        std::vector<String> one = {sigs[0]};
        CHECK(sol.getSignatureStatuses(one, st) && st.size() == 1 && st[0].found && st[0].confirmationStatus.isEmpty() && !st[0].failed, "getSignatureStatuses null confirmationStatus");
        mock({answer(c["response"])});
        CHECK(!sol.getSignatureStatuses(one, st), "getSignatureStatuses wrong result count");
        mock({rpcErr(-32602, "bad")});
        CHECK(!sol.getSignatureStatuses(one, st), "getSignatureStatuses rpc error");
        std::vector<String> bad = {sigs[0], KEY}; // a pubkey is not a signature
        mock({"{}"});
        CHECK(!sol.getSignatureStatuses(bad, st) && bodies.empty(), "getSignatureStatuses invalid signature: no request");
        CHECK(sol.getSignatureStatuses(std::vector<String>(), st) && st.empty() && bodies.empty(), "getSignatureStatuses empty list");

        // 300 signatures -> 256 + 44
        std::vector<String> many;
        for (int i = 0; i < 300; i++) many.push_back(sigs[i % 4]);
        auto vals = [](int n) {
            std::string r = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":[";
            for (int i = 0; i < n; i++) r += std::string(i ? "," : "") + "null";
            return r + "]}}";
        };
        mock({vals(256), vals(44)});
        CHECK(sol.getSignatureStatuses(many, st) && bodies.size() == 2 && st.size() == 300, "getSignatureStatuses 300 sigs -> 2 calls");
    }

    // ---- getTransaction ---------------------------------------------------------------
    {
        const char *names[3] = {"getTransaction", "getTransactionFailed", "getTransactionV0"};
        for (int n = 0; n < 3; n++)
        {
            JsonVariant c = vec[names[n]];
            TransactionInfo t;
            mock({answer(c["response"])});
            bool ok = sol.getTransaction(c["sig"].as<const char *>(), t);
            JsonVariant e = c["expected"];
            std::string nm = names[n];
            CHECK(ok && t.found, nm + " found");
            CHECK(ok && t.slot == e["slot"].as<uint64_t>() && t.blockTime == e["blockTime"].as<int64_t>() && t.fee == e["fee"].as<uint64_t>(), nm + " slot / blockTime / fee");
            CHECK(ok && t.failed == e["failed"].as<bool>() && std::string(t.err.c_str()) == e["err"].as<std::string>(), nm + " err");
            CHECK(ok && nums(t.preBalances, e["preBalances"]) && nums(t.postBalances, e["postBalances"]), nm + " balances");
            CHECK(ok && strs(t.accountKeys, e["accountKeys"]), nm + " account keys");
            CHECK(ok && strs(t.logs, e["logs"]), nm + " logs");
            CHECK(sameRequest(c["request"]), nm + " request " + bodies.back());
            CHECK(bodies.back().find("\"encoding\":\"json\"") != std::string::npos, nm + " encoding json");
        }
        JsonVariant v0 = vec["getTransactionV0"];
        TransactionInfo t;
        mock({answer(v0["response"])});
        CHECK(sol.getTransaction(v0["sig"].as<const char *>(), t) && t.accountKeys.size() == 5 && t.accountKeys[3] == v0["expected"]["accountKeys"][3].as<String>() && t.accountKeys[3] != t.accountKeys[4], "getTransactionV0 loaded writable before readonly");
        JsonVariant f = vec["getTransactionFailed"];
        mock({answer(f["response"])});
        CHECK(sol.getTransaction(f["sig"].as<const char *>(), t) && t.failed && std::string(t.err.c_str()) == "{\"InstructionError\":[0,\"InsufficientFunds\"]}" && t.logs.size() == 1 && t.logs[0].length() > 900, "getTransaction failed tx + long log kept");
        // not found
        JsonVariant n = vec["getTransactionNull"];
        t.slot = 5;
        mock({answer(n["response"])});
        CHECK(n["webjsNull"].as<bool>() && sol.getTransaction(n["sig"].as<const char *>(), t) && !t.found && t.slot == 0 && t.logs.empty(), "getTransaction null -> true, found=false");
        mock({rpcErr(-32009, "Slot was skipped or missing in long-term storage")});
        CHECK(!sol.getTransaction(n["sig"].as<const char *>(), t), "getTransaction rpc error");
        CHECK(!sol.getTransaction(KEY, t), "getTransaction rejects a pubkey as signature");
        // blockTime null (old blocks) -> 0
        std::string r = answer(vec["getTransaction"]["response"]);
        size_t p = r.find("\"blockTime\":1762600123");
        r.replace(p, 22, "\"blockTime\":null");
        mock({r});
        CHECK(sol.getTransaction(vec["getTransaction"]["sig"].as<const char *>(), t) && t.found && t.blockTime == 0, "getTransaction blockTime null");
        mock({answer(vec["getTransaction"]["response"])});
        CHECK(sol.getTransaction(vec["getTransaction"]["sig"].as<const char *>(), t, "finalized") && bodies.back().find("\"finalized\"") != std::string::npos, "getTransaction commitment");
    }

    // ---- requestAirdrop ---------------------------------------------------------------
    {
        JsonVariant c = vec["requestAirdrop"];
        String sig;
        mock({answer(c["response"])});
        CHECK(sol.requestAirdrop(c["key"].as<const char *>(), c["lamports"].as<uint64_t>(), sig) && sig == c["expected"].as<const char *>(), "requestAirdrop signature");
        CHECK(sameRequest(c["request"]) && bodies.back().find("1000000000]") != std::string::npos, "requestAirdrop request (lamports as number) " + bodies.back());
        mock({"x"});
        CHECK(sol.requestAirdrop(c["key"].as<const char *>(), 18446744073709551615ULL, sig) == false && bodies.back().find("18446744073709551615") != std::string::npos, "requestAirdrop u64 max amount formatted, bad answer rejected");
        mock({rpcErr(-32603, "Airdrop request failed. This can happen when the rate limit is reached.")});
        CHECK(!sol.requestAirdrop(KEY, 1000, sig), "requestAirdrop rate limited (RPC error)");
        mock({"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"});
        CHECK(!sol.requestAirdrop(KEY, 1000, sig), "requestAirdrop null result");
        mock({"{}"});
        CHECK(!sol.requestAirdrop(KEY, 0, sig) && !sol.requestAirdrop("nope", 5, sig) && bodies.empty(), "requestAirdrop bad input: no request");
    }

    // ---- getFeeForMessage -------------------------------------------------------------
    {
        JsonVariant c = vec["getFeeForMessage"];
        uint64_t fee = 0;
        mock({answer(c["response"])});
        CHECK(sol.getFeeForMessage(c["message"].as<const char *>(), fee) && fee == c["expected"].as<uint64_t>(), "getFeeForMessage value");
        CHECK(sameRequest(c["request"]), "getFeeForMessage request " + bodies.back());
        fee = 99;
        mock({answer(c["nullResponse"])});
        CHECK(c["nullExpected"].isNull() && !sol.getFeeForMessage(c["message"].as<const char *>(), fee) && fee == 99, "getFeeForMessage null value -> false, output untouched");
        mock({rpcErr(-32602, "invalid message")});
        CHECK(!sol.getFeeForMessage(c["message"].as<const char *>(), fee), "getFeeForMessage rpc error");
        mock({"{}"});
        CHECK(!sol.getFeeForMessage("", fee) && !sol.getFeeForMessage("AA\",\"x", fee) && bodies.empty(), "getFeeForMessage bad base64: no request");
    }

    // ---- failover / transport still apply (they go through rpcCall) ----------------------
    {
        mock({"overloaded"}, 500);
        uint64_t slot = 0;
        CHECK(!sol.getSlot(slot) && !bodies.empty(), "http 500 -> false");
    }
}
