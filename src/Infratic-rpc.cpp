// More Solana JSON-RPC methods: slot, health, version, accounts, token accounts,
// signature statuses, transactions, airdrop and fee estimation.
#include "infratic_internal.h"

using infratic_detail::fromBase64;
using infratic_detail::jsonCapacity;

namespace
{
    String u64Str(uint64_t v)
    {
        char buf[24];
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
        return String(buf);
    }

    // The raw string goes into a JSON request, so only accept real addresses / signatures
    bool validKey(const String &s)
    {
        uint8_t buf[64];
        size_t len = sizeof(buf);
        return base58Decode(s, buf, len) && len == 32;
    }

    bool validSignature(const String &s)
    {
        uint8_t buf[96];
        size_t len = sizeof(buf);
        return base58Decode(s, buf, len) && len == 64;
    }

    bool validCommitment(const String &c)
    {
        return c == "processed" || c == "confirmed" || c == "finalized";
    }

    bool validBase64(const String &s)
    {
        if (s.isEmpty()) return false;
        for (size_t i = 0; i < s.length(); i++)
        {
            char c = s[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
                  c == '/' || c == '='))
                return false;
        }
        return true;
    }

    String commitmentObj(const String &commitment)
    {
        return String("{\"commitment\":\"") + commitment + "\"}";
    }

    uint64_t parseU64(const char *s)
    {
        return s ? (uint64_t)strtoull(s, nullptr, 10) : 0;
    }

    // Parses {"context":..,"value":..} account objects. `v` may be null (account missing).
    bool parseAccount(JsonVariantConst v, AccountInfo &out)
    {
        out = AccountInfo();
        if (v.isNull()) return true;
        const char *b64 = v["data"][0];
        if (!b64) return false;
        out.exists = true;
        out.lamports = v["lamports"].as<uint64_t>();
        out.owner = v["owner"] | "";
        out.executable = v["executable"] | false;
        out.rentEpoch = v["rentEpoch"].as<uint64_t>();
        return fromBase64(b64, out.data);
    }

    // only the fields of AccountInfo, the rest (space, context...) is dropped while parsing
    void addAccountFilter(JsonObject f)
    {
        f["data"] = true;
        f["lamports"] = true;
        f["owner"] = true;
        f["executable"] = true;
        f["rentEpoch"] = true;
    }

    String errJson(JsonVariantConst err)
    {
        String s;
        if (!err.isNull()) serializeJson(err, s);
        return s;
    }

    const size_t MAX_ACCOUNTS_PER_CALL = 100;
    const size_t MAX_SIGNATURES_PER_CALL = 256;
}

bool Infratic::getSolBalance(const String &walletPubkeyBase58, uint64_t &outLamports, const String &commitment)
{
    if (!validKey(walletPubkeyBase58) || !validCommitment(commitment))
    {
        _logErr.println("❌ getBalance: invalid address or commitment");
        return false;
    }
    String response;
    if (!rpcCall("getBalance", "[\"" + walletPubkeyBase58 + "\"," + commitmentObj(commitment) + "]", response))
    {
        return false;
    }
    StaticJsonDocument<1024> filter;
    filter["result"]["value"] = true;
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter), DeserializationOption::NestingLimit(32)) || doc["result"]["value"].isNull())
    {
        return false;
    }
    outLamports = doc["result"]["value"].as<uint64_t>();
    return true;
}

bool Infratic::getSlot(uint64_t &outSlot, const String &commitment)
{
    if (!validCommitment(commitment)) return false;
    String response;
    if (!rpcCall("getSlot", "[" + commitmentObj(commitment) + "]", response))
    {
        return false;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, response) || !doc["result"].is<uint64_t>())
    {
        return false;
    }
    outSlot = doc["result"].as<uint64_t>();
    return true;
}

bool Infratic::getHealth()
{
    String response;
    if (!rpcCall("getHealth", "[]", response))
    {
        return false;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, response))
    {
        return false;
    }
    return String(doc["result"] | "") == "ok";
}

bool Infratic::getVersion(String &outSolanaCore)
{
    String response;
    if (!rpcCall("getVersion", "[]", response))
    {
        return false;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, response) || !doc["result"]["solana-core"].is<const char *>())
    {
        return false;
    }
    outSolanaCore = doc["result"]["solana-core"].as<String>();
    return true;
}

bool Infratic::getAccountInfo(const String &accountBase58, AccountInfo &out, const String &commitment)
{
    if (!validKey(accountBase58) || !validCommitment(commitment))
    {
        _logErr.println("❌ getAccountInfo: invalid address or commitment");
        return false;
    }
    String response;
    String params = "[\"" + accountBase58 + R"(",{"encoding":"base64","commitment":")" + commitment + "\"}]";
    if (!rpcCall("getAccountInfo", params, response))
    {
        return false;
    }
    StaticJsonDocument<1024> filter;
    JsonObject fv = filter["result"]["value"].to<JsonObject>();
    addAccountFilter(fv);
    DynamicJsonDocument doc(jsonCapacity(response));
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter)) || !doc.containsKey("result") ||
        !doc["result"].containsKey("value"))
    {
        _logErr.println("❌ getAccountInfo: bad response");
        return false;
    }
    return parseAccount(doc["result"]["value"], out);
}

bool Infratic::getMultipleAccounts(const std::vector<String> &keys, std::vector<AccountInfo> &out,
                                   const String &commitment)
{
    out.clear();
    if (!validCommitment(commitment)) return false;
    for (const String &k : keys)
    {
        if (!validKey(k))
        {
            _logErr.println("❌ getMultipleAccounts: invalid address " + k);
            return false;
        }
    }

    std::vector<AccountInfo> result;
    for (size_t start = 0; start < keys.size(); start += MAX_ACCOUNTS_PER_CALL)
    {
        size_t n = keys.size() - start;
        if (n > MAX_ACCOUNTS_PER_CALL) n = MAX_ACCOUNTS_PER_CALL;

        String params = "[[";
        for (size_t i = 0; i < n; i++)
        {
            if (i) params += ",";
            params += "\"" + keys[start + i] + "\"";
        }
        params += R"(],{"encoding":"base64","commitment":")" + commitment + "\"}]";

        String response;
        if (!rpcCall("getMultipleAccounts", params, response))
        {
            return false;
        }
        StaticJsonDocument<1024> filter;
        JsonObject fv = filter["result"]["value"].createNestedObject();
        addAccountFilter(fv);
        // each account needs ~10 nodes plus its strings, more than the raw text suggests for small accounts
        DynamicJsonDocument doc(jsonCapacity(response) + n * 320);
        if (deserializeJson(doc, response, DeserializationOption::Filter(filter)))
        {
            _logErr.println("❌ getMultipleAccounts: JSON parse error");
            return false;
        }
        JsonArray values = doc["result"]["value"];
        if (values.isNull() || values.size() != n)
        {
            _logErr.println("❌ getMultipleAccounts: unexpected number of results");
            return false;
        }
        for (JsonVariant v : values)
        {
            AccountInfo acc;
            if (!parseAccount(v, acc)) return false;
            result.push_back(std::move(acc));
        }
    }
    out = std::move(result);
    return true;
}

bool Infratic::getTokenAccountsByOwner(const String &ownerBase58, std::vector<TokenAccount> &out,
                                       const String &programId, const String &commitment)
{
    out.clear();
    if (!validKey(ownerBase58) || !validKey(programId) || !validCommitment(commitment))
    {
        _logErr.println("❌ getTokenAccountsByOwner: invalid owner, program or commitment");
        return false;
    }
    String params = "[\"" + ownerBase58 + R"(",{"programId":")" + programId +
                    R"("},{"encoding":"jsonParsed","commitment":")" + commitment + "\"}]";
    String response;
    if (!rpcCall("getTokenAccountsByOwner", params, response))
    {
        return false;
    }

    // keep only what TokenAccount needs, the answer is verbose. Token-2022 extensions nest
    // deeper than the default limit, the filter drops them but the parser still counts the depth.
    StaticJsonDocument<1024> filter;
    JsonObject f = filter["result"]["value"].createNestedObject();
    f["pubkey"] = true;
    JsonObject info = f["account"]["data"]["parsed"]["info"].to<JsonObject>();
    info["mint"] = true;
    info["owner"] = true;
    info["state"] = true;
    info["tokenAmount"]["amount"] = true;
    info["tokenAmount"]["decimals"] = true;
    info["tokenAmount"]["uiAmountString"] = true;

    DynamicJsonDocument doc(jsonCapacity(response) / 2 + 1024);
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter), DeserializationOption::NestingLimit(32)))
    {
        _logErr.println("❌ getTokenAccountsByOwner: JSON parse error");
        return false;
    }
    JsonArray values = doc["result"]["value"];
    if (values.isNull())
    {
        return false;
    }
    for (JsonObject item : values)
    {
        JsonObject i = item["account"]["data"]["parsed"]["info"];
        if (i.isNull()) continue; // not parsed (unknown layout)
        TokenAccount t;
        t.address = item["pubkey"] | "";
        t.mint = i["mint"] | "";
        t.owner = i["owner"] | "";
        t.amount = parseU64(i["tokenAmount"]["amount"] | "0");
        t.decimals = i["tokenAmount"]["decimals"] | 0;
        t.uiAmount = i["tokenAmount"]["uiAmountString"] | "";
        t.frozen = String(i["state"] | "") == "frozen";
        out.push_back(t);
    }
    return true;
}

bool Infratic::getTokenSupply(const String &mintBase58, uint64_t &outAmount, uint8_t &outDecimals,
                              const String &commitment)
{
    if (!validKey(mintBase58) || !validCommitment(commitment))
    {
        _logErr.println("❌ getTokenSupply: invalid mint or commitment");
        return false;
    }
    String response;
    if (!rpcCall("getTokenSupply", "[\"" + mintBase58 + "\"," + commitmentObj(commitment) + "]", response))
    {
        return false;
    }
    StaticJsonDocument<1024> filter;
    filter["result"]["value"]["amount"] = true;
    filter["result"]["value"]["decimals"] = true;
    StaticJsonDocument<512> doc;
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter), DeserializationOption::NestingLimit(32)))
    {
        return false;
    }
    const char *amount = doc["result"]["value"]["amount"];
    if (!amount || !doc["result"]["value"]["decimals"].is<int>())
    {
        return false;
    }
    outAmount = parseU64(amount);
    outDecimals = doc["result"]["value"]["decimals"].as<uint8_t>();
    return true;
}

bool Infratic::getSignatureStatuses(const std::vector<String> &sigs, std::vector<SignatureStatus> &out,
                                    bool searchHistory)
{
    out.clear();
    for (const String &s : sigs)
    {
        if (!validSignature(s))
        {
            _logErr.println("❌ getSignatureStatuses: invalid signature " + s);
            return false;
        }
    }

    std::vector<SignatureStatus> result;
    for (size_t start = 0; start < sigs.size(); start += MAX_SIGNATURES_PER_CALL)
    {
        size_t n = sigs.size() - start;
        if (n > MAX_SIGNATURES_PER_CALL) n = MAX_SIGNATURES_PER_CALL;

        String params = "[[";
        for (size_t i = 0; i < n; i++)
        {
            if (i) params += ",";
            params += "\"" + sigs[start + i] + "\"";
        }
        params += searchHistory ? R"(],{"searchTransactionHistory":true}])" : "]]";

        String response;
        if (!rpcCall("getSignatureStatuses", params, response))
        {
            return false;
        }
        DynamicJsonDocument doc(jsonCapacity(response) + n * 320);
        if (deserializeJson(doc, response))
        {
            _logErr.println("❌ getSignatureStatuses: JSON parse error");
            return false;
        }
        JsonArray values = doc["result"]["value"];
        if (values.isNull() || values.size() != n)
        {
            _logErr.println("❌ getSignatureStatuses: unexpected number of results");
            return false;
        }
        for (JsonVariant v : values)
        {
            SignatureStatus st;
            if (!v.isNull())
            {
                st.found = true;
                st.slot = v["slot"].as<uint64_t>();
                st.confirmationStatus = v["confirmationStatus"] | "";
                st.failed = !v["err"].isNull();
                st.err = errJson(v["err"]);
            }
            result.push_back(st);
        }
    }
    out = std::move(result);
    return true;
}

bool Infratic::getTransaction(const String &signature, TransactionInfo &out, const String &commitment)
{
    out = TransactionInfo();
    if (!validSignature(signature) || !validCommitment(commitment))
    {
        _logErr.println("❌ getTransaction: invalid signature or commitment");
        return false;
    }
    String response;
    String params = "[\"" + signature + R"(",{"encoding":"json","commitment":")" + commitment +
                    R"(","maxSupportedTransactionVersion":0}])";
    if (!rpcCall("getTransaction", params, response))
    {
        return false;
    }

    // skip instructions, signatures and token balances, they can be large
    StaticJsonDocument<1024> filter;
    JsonObject r = filter.createNestedObject("result");
    r["slot"] = true;
    r["blockTime"] = true;
    r["transaction"]["message"]["accountKeys"] = true;
    JsonObject meta = r.createNestedObject("meta");
    meta["fee"] = true;
    meta["err"] = true;
    meta["preBalances"] = true;
    meta["postBalances"] = true;
    meta["logMessages"] = true;
    meta["loadedAddresses"]["writable"] = true;
    meta["loadedAddresses"]["readonly"] = true;

    DynamicJsonDocument doc(jsonCapacity(response));
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter), DeserializationOption::NestingLimit(32)))
    {
        _logErr.println("❌ getTransaction: JSON parse error");
        return false;
    }
    if (!doc.containsKey("result"))
    {
        return false;
    }
    JsonVariant result = doc["result"];
    if (result.isNull())
    {
        return true; // not found, out.found stays false
    }

    out.found = true;
    out.slot = result["slot"].as<uint64_t>();
    out.blockTime = result["blockTime"].as<int64_t>();
    JsonObject m = result["meta"];
    out.fee = m["fee"].as<uint64_t>();
    out.failed = !m["err"].isNull();
    out.err = errJson(m["err"]);
    for (JsonVariant v : m["preBalances"].as<JsonArray>()) out.preBalances.push_back(v.as<int64_t>());
    for (JsonVariant v : m["postBalances"].as<JsonArray>()) out.postBalances.push_back(v.as<int64_t>());
    for (JsonVariant v : result["transaction"]["message"]["accountKeys"].as<JsonArray>())
        out.accountKeys.push_back(v.as<String>());
    // v0 transactions: accounts from lookup tables come after the static keys (writable first)
    for (JsonVariant v : m["loadedAddresses"]["writable"].as<JsonArray>()) out.accountKeys.push_back(v.as<String>());
    for (JsonVariant v : m["loadedAddresses"]["readonly"].as<JsonArray>()) out.accountKeys.push_back(v.as<String>());
    for (JsonVariant v : m["logMessages"].as<JsonArray>()) out.logs.push_back(v.as<String>());
    return true;
}

bool Infratic::requestAirdrop(const String &addressBase58, uint64_t lamports, String &outSignature)
{
    if (!validKey(addressBase58) || lamports == 0)
    {
        _logErr.println("❌ requestAirdrop: invalid address or amount");
        return false;
    }
    String response;
    if (!rpcCall("requestAirdrop", "[\"" + addressBase58 + "\"," + u64Str(lamports) + "]", response))
    {
        return false;
    }
    StaticJsonDocument<384> doc;
    if (deserializeJson(doc, response) || !doc["result"].is<const char *>())
    {
        return false;
    }
    outSignature = doc["result"].as<String>();
    return true;
}

bool Infratic::getFeeForMessage(const String &messageBase64, uint64_t &outLamports, const String &commitment)
{
    if (!validBase64(messageBase64) || !validCommitment(commitment))
    {
        _logErr.println("❌ getFeeForMessage: invalid message or commitment");
        return false;
    }
    String response;
    if (!rpcCall("getFeeForMessage", "[\"" + messageBase64 + "\"," + commitmentObj(commitment) + "]", response))
    {
        return false;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, response) || doc["result"]["value"].isNull())
    {
        return false; // value is null when the blockhash of the message is not valid anymore
    }
    outLamports = doc["result"]["value"].as<uint64_t>();
    return true;
}
