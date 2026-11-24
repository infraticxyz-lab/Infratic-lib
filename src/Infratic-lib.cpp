#include "infratic_internal.h"
#include <mbedtls/version.h>

// mbedtls 3.x (arduino-esp32 3.x / ESP-IDF 5) removed the *_ret variants
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
#define mbedtls_sha256_starts_ret mbedtls_sha256_starts
#define mbedtls_sha256_update_ret mbedtls_sha256_update
#define mbedtls_sha256_finish_ret mbedtls_sha256_finish
#endif

// ============================================================================
// LOGGING
// ============================================================================

namespace infratic_detail
{
    uint8_t logLevel = INFRATIC_LOG_INFO;
    InfraticLog logErr{INFRATIC_LOG_ERROR};
    InfraticLog logInfo{INFRATIC_LOG_INFO};
}

void Infratic::setLogLevel(uint8_t level)
{
    infratic_detail::logLevel = level;
}

using infratic_detail::toBase64;
using infratic_detail::fromBase64;
using infratic_detail::jsonCapacity;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// ----------------------------------------------------------------------------
// Ed25519 point check (used for PDA derivation)
// A PDA must NOT be a valid ed25519 point. Field arithmetic below follows
// TweetNaCl (public domain): 16 x 16-bit limbs, p = 2^255 - 19.
// ----------------------------------------------------------------------------
namespace
{
    typedef int64_t gf[16];
    const gf GF1 = {1};
    const gf GF_D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                     0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
    const gf GF_I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                     0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

    void gfCarry(gf o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += (1LL << 16);
            int64_t c = o[i] >> 16;
            o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
            o[i] -= c << 16;
        }
    }

    void gfSelect(gf p, gf q, int b)
    {
        int64_t c = ~(b - 1);
        for (int i = 0; i < 16; i++)
        {
            int64_t t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    void gfPack(uint8_t *o, const gf n)
    {
        gf m, t;
        for (int i = 0; i < 16; i++) t[i] = n[i];
        gfCarry(t);
        gfCarry(t);
        gfCarry(t);
        for (int j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            gfSelect(t, m, 1 - b);
        }
        for (int i = 0; i < 16; i++)
        {
            o[2 * i] = t[i] & 0xff;
            o[2 * i + 1] = t[i] >> 8;
        }
    }

    bool gfEqual(const gf a, const gf b)
    {
        uint8_t x[32], y[32];
        gfPack(x, a);
        gfPack(y, b);
        return memcmp(x, y, 32) == 0;
    }

    void gfAdd(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
    void gfSub(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

    void gfMul(gf o, const gf a, const gf b)
    {
        int64_t t[31] = {0};
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 16; j++)
                t[i + j] += a[i] * b[j];
        for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        for (int i = 0; i < 16; i++) o[i] = t[i];
        gfCarry(o);
        gfCarry(o);
    }

    void gfSquare(gf o, const gf a) { gfMul(o, a, a); }

    void gfPow2523(gf o, const gf in)
    {
        gf c;
        for (int a = 0; a < 16; a++) c[a] = in[a];
        for (int a = 250; a >= 0; a--)
        {
            gfSquare(c, c);
            if (a != 1) gfMul(c, c, in);
        }
        for (int a = 0; a < 16; a++) o[a] = c[a];
    }
}

bool Infratic::isOnCurve(const uint8_t key[32])
{
    gf x, y, num, den, den2, den4, den6, t, chk;
    for (int i = 0; i < 16; i++) y[i] = key[2 * i] + ((int64_t)key[2 * i + 1] << 8);
    y[15] &= 0x7fff;

    // x^2 = (y^2 - 1) / (d*y^2 + 1)
    gfSquare(num, y);
    gfMul(den, num, GF_D);
    gfSub(num, num, GF1);
    gfAdd(den, GF1, den);

    gfSquare(den2, den);
    gfSquare(den4, den2);
    gfMul(den6, den4, den2);
    gfMul(t, den6, num);
    gfMul(t, t, den);
    gfPow2523(t, t);
    gfMul(t, t, num);
    gfMul(t, t, den);
    gfMul(t, t, den);
    gfMul(x, t, den);

    gfSquare(chk, x);
    gfMul(chk, chk, den);
    if (!gfEqual(chk, num)) gfMul(x, x, GF_I);

    gfSquare(chk, x);
    gfMul(chk, chk, den);
    return gfEqual(chk, num);
}

std::vector<uint8_t> encodeU64LE(uint64_t value)
{
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; i++)
    {
        result[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    return result;
}
std::vector<uint8_t> encodeU64BE(uint64_t value)
{
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; i++)
    {
        result[7 - i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    return result;
}

std::vector<uint8_t> encodeU32LE(uint32_t value)
{
    std::vector<uint8_t> result(4);
    for (int i = 0; i < 4; i++)
    {
        result[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    return result;
}

std::vector<uint8_t> encodeI64LE(int64_t value)
{
    return encodeU64LE((uint64_t)value);
}

void appendCompactU16(std::vector<uint8_t> &buffer, uint16_t value)
{
    uint16_t rem = value;
    while (true)
    {
        uint8_t elem = rem & 0x7f;
        rem >>= 7;
        if (rem == 0)
        {
            buffer.push_back(elem);
            break;
        }
        buffer.push_back(elem | 0x80);
    }
}

void appendBorshString(std::vector<uint8_t> &buffer, const String &str)
{
    std::vector<uint8_t> len = encodeU32LE(str.length());
    buffer.insert(buffer.end(), len.begin(), len.end());
    buffer.insert(buffer.end(), str.begin(), str.end());
}

String infratic_detail::toBase64(const uint8_t *data, size_t len)
{
    size_t requiredSize = 4 * ((len + 2) / 3);
    std::vector<unsigned char> outBuf(requiredSize + 1, 0);

    size_t olen = 0;
    int ret = mbedtls_base64_encode(outBuf.data(), outBuf.size(), &olen, data, len);
    if (ret != 0)
    {
        _logErr.println("❌ Base64 encoding error: " + String(ret));
        return "";
    }
    return String((const char *)outBuf.data()).substring(0, olen);
}

std::vector<uint8_t> base58ToPubkey(const String &base58Str)
{
    uint8_t buffer[32];
    size_t len = sizeof(buffer);
    if (!base58Decode(base58Str, buffer, len) || len != 32)
    {
        _logErr.println("❌ base58ToPubkey: Invalid base58 input!");
        return {};
    }
    return std::vector<uint8_t>(buffer, buffer + 32);
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================

Infratic::Infratic(const String &rpcUrl)
{
    _rpcUrl = rpcUrl;
    _rpcUrls.push_back(rpcUrl);
}

// ============================================================================
// BLOCKCHAIN QUERIES
// ============================================================================

String Infratic::getLatestBlockhash()
{
    const int maxRetries = 3;
    const int retryDelayMs = 500;

    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
        _logInfo.printf("🌐 Fetching blockhash (attempt %d/%d)...\n", attempt, maxRetries);

        String response;
        if (rpcCall("getLatestBlockhash", "[]", response))
        {
            DynamicJsonDocument doc(2048);
            if (!deserializeJson(doc, response))
            {
                String blockhash = doc["result"]["value"]["blockhash"].as<String>();
                if (!blockhash.isEmpty() && blockhash != "null")
                {
                    _logInfo.println("✅ Blockhash: " + blockhash);
                    return blockhash;
                }
            }
        }
        delay(retryDelayMs);
    }

    _logErr.println("❌ Failed to get blockhash");
    return "";
}

bool Infratic::getBlockHeight(uint64_t &outBlockHeight)
{
    String response;
    if (!rpcCall("getBlockHeight", "[]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(1024);
    if (deserializeJson(doc, response) || doc["result"].isNull())
    {
        return false;
    }

    outBlockHeight = doc["result"].as<uint64_t>();
    return true;
}

bool Infratic::getEpochInfo(EpochInfo &outEpochInfo)
{
    String response;
    if (!rpcCall("getEpochInfo", "[]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    JsonObject result = doc["result"].as<JsonObject>();
    if (result.isNull())
    {
        return false;
    }
    outEpochInfo.absoluteSlot = result["absoluteSlot"].as<uint64_t>();
    outEpochInfo.blockHeight = result["blockHeight"].as<uint64_t>();
    outEpochInfo.epoch = result["epoch"].as<uint64_t>();
    outEpochInfo.slotIndex = result["slotIndex"].as<uint64_t>();
    outEpochInfo.slotsInEpoch = result["slotsInEpoch"].as<uint64_t>();

    return true;
}

// ============================================================================
// BALANCE QUERIES
// ============================================================================

bool Infratic::getSolBalance(const String &walletPubkeyBase58, uint64_t &outLamports)
{
    String response;
    if (!rpcCall("getBalance", "[\"" + walletPubkeyBase58 + "\"]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response) || doc["result"]["value"].isNull())
    {
        return false;
    }

    outLamports = doc["result"]["value"].as<uint64_t>();
    return true;
}

bool Infratic::getSplTokenBalance(const String &walletPubkeyBase58, const String &tokenMintBase58,
                                  uint64_t &outBalance)
{
    String ataAddress;
    if (!findAssociatedTokenAccount(walletPubkeyBase58, tokenMintBase58, ataAddress))
    {
        _logErr.println("⚠️ ATA not found, balance = 0");
        outBalance = 0;
        return true;
    }

    String response;
    if (!rpcCall("getTokenAccountBalance", "[\"" + ataAddress + "\"]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    String amountStr = doc["result"]["value"]["amount"].as<String>();
    if (amountStr.isEmpty())
    {
        return false;
    }

    outBalance = strtoull(amountStr.c_str(), nullptr, 10);
    return true;
}

bool Infratic::getTokenDecimals(const String &mintPubkeyBase58, uint8_t &outDecimals)
{
    String response;
    if (!rpcCall("getTokenSupply", "[\"" + mintPubkeyBase58 + "\"]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    JsonVariant decimals = doc["result"]["value"]["decimals"];
    if (decimals.isNull())
    {
        return false;
    }

    outDecimals = decimals.as<uint8_t>();
    return true;
}

// ============================================================================
// TOKEN ACCOUNT OPERATIONS
// ============================================================================

bool Infratic::findAssociatedTokenAccount(const String &ownerPubkeyBase58,
                                          const String &mintPubkeyBase58,
                                          String &outATA)
{
    String response;
    if (!rpcCall("getTokenAccountsByOwner", "[\"" + ownerPubkeyBase58 + R"(",{"mint":")" + mintPubkeyBase58 + R"("},{"encoding":"jsonParsed"}])", response))
    {
        return false;
    }

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    JsonArray arr = doc["result"]["value"].as<JsonArray>();
    if (!arr || arr.size() == 0)
    {
        return false;
    }

    outATA = arr[0]["pubkey"].as<String>();
    return true;
}

// ============================================================================
// TRANSACTION OPERATIONS
// ============================================================================

bool Infratic::sendSol(const String &privateKeyBase58, const String &fromPubkeyBase58,
                       const String &toPubkeyBase58, uint64_t lamports)
{
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen))
    {
        _logErr.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32], toPub[32];
    size_t fromLen = 32, toLen = 32;

    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32)
    {
        _logErr.println("❌ From pubkey decode error");
        return false;
    }

    if (!base58Decode(toPubkeyBase58, toPub, toLen) || toLen != 32)
    {
        _logErr.println("❌ To pubkey decode error");
        return false;
    }

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
    {
        return false;
    }

    String txBase64;
    if (!buildAndSignTransaction(privateKey, privateKeyLen, fromPub, toPub, lamports, blockhash, txBase64))
    {
        return false;
    }

    String signature;
    if (!sendRawTransaction(txBase64, signature))
    {
        return false;
    }

    _logInfo.println("✅ Transaction Signature: " + signature);
    return true;
}

bool Infratic::sendProgramDataTransaction(const String &privateKeyBase58,
                                          const String &fromPubkeyBase58,
                                          const String &programIdBase58,
                                          const String &dataString,
                                          uint32_t confirmWaitMs)
{
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64)
    {
        _logErr.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32];
    size_t fromLen = sizeof(fromPub);
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32)
    {
        _logErr.println("❌ Public key decode error");
        return false;
    }

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
    {
        return false;
    }

    String txBase64;
    if (!buildAndSignMemoTransaction(privateKey, privateKeyLen, fromPub, programIdBase58,
                                     dataString, blockhash, txBase64))
    {
        return false;
    }

    String signature;
    if (!sendRawTransaction(txBase64, signature))
    {
        return false;
    }

    _logInfo.println("✅ Tx Signature: " + signature);

    if (!confirmTransaction(signature, confirmWaitMs))
    {
        _logErr.println("⚠️ Transaction NOT confirmed in time");
        return false;
    }

    _logInfo.println("✅ Transaction confirmed");
    return true;
}

bool Infratic::sendRawTransaction(const String &txBase64, String &outSignature, bool skipPreflight)
{
    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[")" +
                  txBase64 + R"(",{"encoding":"base64","skipPreflight":)" + (skipPreflight ? "true" : "false") +
                  R"(,"preflightCommitment":"confirmed"}]})";

    String response;
    int code = 0;
    if (!httpPost(body, response, code))
    {
        _logErr.printf("❌ sendTransaction: HTTP code %d\n", code);
        return false;
    }

    DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        _logErr.println("❌ JSON parse error");
        return false;
    }

    if (doc["error"])
    {
        TxError err;
        if (!doc["error"]["data"]["err"].isNull())
        {
            infratic_detail::parseTxError(doc["error"]["data"]["err"], doc["error"]["data"]["logs"], err);
        }
        else
        {
            err.hasError = true;
            err.name = "RpcError";
        }
        if (err.message.isEmpty())
        {
            err.message = doc["error"]["message"].as<String>();
        }
        _lastTxError = err;
        _logErr.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
        if (err.customCode >= 0)
        {
            _logErr.printf("   Program error %lld %s: %s\n", (long long)err.customCode, err.name.c_str(), err.message.c_str());
        }
        return false;
    }

    outSignature = doc["result"].as<String>();
    return true;
}

int Infratic::checkSignatureStatus(const String &signature)
{
    String response;
    if (!rpcCall("getSignatureStatuses", "[[\"" + signature + "\"],{\"searchTransactionHistory\":true}]", response))
    {
        return 0;
    }

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return 0;
    }

    JsonVariant status = doc["result"]["value"][0];
    if (status.isNull())
    {
        return 0;
    }
    if (!status["err"].isNull())
    {
        infratic_detail::parseTxError(status["err"], JsonVariantConst(), _lastTxError);
        _logErr.println("❌ Transaction failed: " + _lastTxError.raw);
        return -1;
    }

    String conf = status["confirmationStatus"] | "";
    return (conf == "confirmed" || conf == "finalized") ? 1 : 0;
}

bool Infratic::confirmTransaction(const String &signature, uint32_t maxWaitMs)
{
    const uint32_t pollIntervalMs = 500;
    uint32_t waited = 0;

    while (waited <= maxWaitMs)
    {
        int status = checkSignatureStatus(signature);
        if (status == 1)
        {
            _logInfo.println("✅ Transaction confirmed");
            return true;
        }
        if (status < 0)
        {
            return false;
        }

        delay(pollIntervalMs);
        waited += pollIntervalMs;
    }

    _logInfo.println("⏱️ Timeout: Transaction not confirmed");
    return false;
}

// ============================================================================
// GENERIC RPC
// ============================================================================

bool infratic_detail::fromBase64(const char *in, std::vector<uint8_t> &out)
{
    size_t inLen = strlen(in);
    size_t outLen = 0;
    out.assign((inLen / 4) * 3 + 3, 0);
    if (mbedtls_base64_decode(out.data(), out.size(), &outLen, (const unsigned char *)in, inLen) != 0)
    {
        out.clear();
        return false;
    }
    out.resize(outLen);
    return true;
}

size_t infratic_detail::jsonCapacity(const String &response)
{
    // input strings are copied into the document, keep some room for nodes
    return response.length() + response.length() / 2 + 1024;
}

String infratic_detail::filtersJson(const std::vector<AccountFilter> &filters)
{
    String json = "[";
    for (size_t i = 0; i < filters.size(); i++)
    {
        const AccountFilter &f = filters[i];
        if (i) json += ",";
        if (f.isMemcmp)
        {
            json += R"({"memcmp":{"offset":)" + String((unsigned long)f.offset) + R"(,"bytes":")" +
                    base58Encode(f.bytes.data(), f.bytes.size()) + "\"}}";
        }
        else
        {
            json += R"({"dataSize":)" + String((unsigned long)f.size) + "}";
        }
    }
    return json + "]";
}

AccountFilter AccountFilter::dataSize(size_t size)
{
    AccountFilter f;
    f.size = size;
    return f;
}

AccountFilter AccountFilter::memcmp(size_t offset, const std::vector<uint8_t> &bytes)
{
    AccountFilter f;
    f.isMemcmp = true;
    f.offset = offset;
    f.bytes = bytes;
    return f;
}

bool Infratic::getAccountData(const String &accountBase58, std::vector<uint8_t> &outData,
                              const String &commitment, String *outOwner)
{
    String response;
    String params = "[\"" + accountBase58 + R"(",{"encoding":"base64","commitment":")" + commitment + "\"}]";
    if (!rpcCall("getAccountInfo", params, response))
    {
        return false;
    }

    DynamicJsonDocument doc(jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        _logErr.println("❌ getAccountInfo: JSON parse error");
        return false;
    }

    JsonVariant value = doc["result"]["value"];
    const char *data = value["data"][0];
    if (value.isNull() || !data)
    {
        _logErr.println("❌ getAccountInfo: account not found " + accountBase58);
        return false;
    }

    if (outOwner)
    {
        *outOwner = value["owner"] | "";
    }
    return fromBase64(data, outData);
}

bool Infratic::getProgramAccounts(const String &programIdBase58, const std::vector<AccountFilter> &filters,
                                  std::vector<ProgramAccount> &outAccounts, const String &commitment)
{
    String params = "[\"" + programIdBase58 + R"(",{"encoding":"base64","commitment":")" + commitment + "\"";
    if (!filters.empty())
    {
        params += ",\"filters\":" + infratic_detail::filtersJson(filters);
    }
    params += "}]";

    String response;
    if (!rpcCall("getProgramAccounts", params, response))
    {
        return false;
    }

    DynamicJsonDocument doc(jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        _logErr.println("❌ getProgramAccounts: JSON parse error (response too big? add filters)");
        return false;
    }

    outAccounts.clear();
    for (JsonObject item : doc["result"].as<JsonArray>())
    {
        ProgramAccount acc;
        acc.pubkey = item["pubkey"] | "";
        acc.lamports = item["account"]["lamports"] | 0ULL;
        const char *data = item["account"]["data"][0];
        if (data) fromBase64(data, acc.data);
        outAccounts.push_back(acc);
    }
    return true;
}

bool Infratic::getSignaturesForAddress(const String &addressBase58, std::vector<SignatureInfo> &outSignatures,
                                       uint8_t limit, const String &until)
{
    String params = "[\"" + addressBase58 + R"(",{"limit":)" + String((unsigned)limit);
    if (!until.isEmpty())
    {
        params += R"(,"until":")" + until + "\"";
    }
    params += "}]";

    String response;
    if (!rpcCall("getSignaturesForAddress", params, response))
    {
        return false;
    }

    DynamicJsonDocument doc(jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        _logErr.println("❌ getSignaturesForAddress: JSON parse error");
        return false;
    }

    outSignatures.clear();
    for (JsonObject item : doc["result"].as<JsonArray>())
    {
        SignatureInfo info;
        info.signature = item["signature"] | "";
        info.slot = item["slot"] | 0ULL;
        info.blockTime = item["blockTime"] | 0LL;
        info.failed = !item["err"].isNull();
        outSignatures.push_back(info);
    }
    return true;
}

bool Infratic::getMinimumBalanceForRentExemption(size_t dataLength, uint64_t &outLamports)
{
    String response;
    if (!rpcCall("getMinimumBalanceForRentExemption", "[" + String((unsigned long)dataLength) + "]", response))
    {
        return false;
    }

    DynamicJsonDocument doc(256);
    if (deserializeJson(doc, response) || !doc["result"].is<uint64_t>())
    {
        return false;
    }
    outLamports = doc["result"].as<uint64_t>();
    return true;
}

bool Infratic::getClusterTime(int64_t &outUnixTime)
{
    String response;
    if (!rpcCall("getSlot", R"([{"commitment":"confirmed"}])", response))
    {
        return false;
    }

    DynamicJsonDocument doc(256);
    if (deserializeJson(doc, response))
    {
        return false;
    }
    uint64_t slot = doc["result"] | 0ULL;

    // the newest slot may not have a block time yet, step back a few slots
    for (int i = 0; i < 4 && slot > (uint64_t)i; i++)
    {
        if (!rpcCall("getBlockTime", "[" + String((unsigned long long)(slot - i)) + "]", response))
        {
            continue;
        }
        doc.clear();
        if (!deserializeJson(doc, response) && doc["result"].is<int64_t>())
        {
            outUnixTime = doc["result"].as<int64_t>();
            return true;
        }
    }
    return false;
}

// ============================================================================
// CRYPTOGRAPHIC OPERATIONS
// ============================================================================

bool Infratic::signMessageFromBase58(const std::vector<uint8_t> &message,
                                     const String &privateKeyBase58,
                                     uint8_t outSignature[64])
{
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64)
    {
        _logErr.println("❌ Failed to decode private key");
        return false;
    }

    const uint8_t *priv = privateKey;
    const uint8_t *pub = privateKey + 32;

    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}

bool Infratic::signMessageRaw(const std::vector<uint8_t> &message,
                              const std::vector<uint8_t> &privateKey,
                              uint8_t outSignature[64])
{
    if (privateKey.size() < 64)
    {
        _logErr.println("❌ Invalid private key size");
        return false;
    }

    const uint8_t *priv = privateKey.data();
    const uint8_t *pub = privateKey.data() + 32;

    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}

// ============================================================================
// PDA OPERATIONS
// ============================================================================

bool Infratic::derivePDA(const std::vector<std::vector<uint8_t>> &seeds,
                         const String &programIdBase58,
                         String &outPDABase58, uint8_t &outBump)
{
    std::vector<uint8_t> programId = base58ToPubkey(programIdBase58);
    if (programId.size() != 32)
    {
        _logErr.println("❌ Invalid program ID");
        return false;
    }

    std::vector<uint8_t> pdaBytes;
    if (!findProgramAddress(seeds, programId, pdaBytes, outBump))
    {
        _logErr.println("❌ Failed to derive PDA");
        return false;
    }

    outPDABase58 = base58Encode(pdaBytes.data(), pdaBytes.size());
    if (outPDABase58.isEmpty())
    {
        _logErr.println("❌ Failed to encode PDA to Base58");
        return false;
    }

    _logInfo.println("✅ Derived PDA: " + outPDABase58);
    _logInfo.println("   Bump: " + String(outBump));

    return true;
}

bool Infratic::findProgramAddress(const std::vector<std::vector<uint8_t>> &seeds,
                                  const std::vector<uint8_t> &programId,
                                  std::vector<uint8_t> &outPDA, uint8_t &outBump)
{
    // Solana limits: max 16 seeds (bump included), each max 32 bytes
    if (programId.size() != 32 || seeds.size() > 15)
    {
        _logErr.println("❌ Invalid PDA input (program id or seed count)");
        return false;
    }
    for (const auto &seed : seeds)
    {
        if (seed.size() > 32)
        {
            _logErr.println("❌ PDA seed longer than 32 bytes");
            return false;
        }
    }

    const std::string marker = "ProgramDerivedAddress";

    for (int bump = 255; bump >= 0; --bump)
    {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);

        for (const auto &seed : seeds)
        {
            mbedtls_sha256_update_ret(&ctx, seed.data(), seed.size());
        }

        uint8_t bumpByte = static_cast<uint8_t>(bump);
        mbedtls_sha256_update_ret(&ctx, &bumpByte, 1);
        mbedtls_sha256_update_ret(&ctx, programId.data(), programId.size());
        mbedtls_sha256_update_ret(&ctx, (const uint8_t *)marker.c_str(), marker.size());

        uint8_t hash[32];
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        // valid PDA = hash that is NOT on the ed25519 curve
        if (isOnCurve(hash))
        {
            continue;
        }

        outPDA.assign(hash, hash + 32);
        outBump = bump;
        return true;
    }

    _logErr.println("❌ No valid PDA found");
    return false;
}

// ============================================================================
// ANCHOR FRAMEWORK SUPPORT
// ============================================================================

std::vector<uint8_t> Infratic::calculateDiscriminator(const std::string &functionName)
{
    std::string input = "global:" + functionName;

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)input.c_str(), input.size());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    return std::vector<uint8_t>(hash, hash + 8);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

String Infratic::base64Encode(const uint8_t *data, size_t len)
{
    return toBase64(data, len);
}

// ============================================================================
// INTERNAL TRANSACTION BUILDING
// ============================================================================

static const char *SYSTEM_PROGRAM_B58 = "11111111111111111111111111111111";

bool Infratic::buildAndSignTransaction(const uint8_t *privateKey, size_t privLen,
                                       const uint8_t *fromPub, const uint8_t *toPub,
                                       uint64_t lamports, const String &recentBlockhash,
                                       String &outTxBase64)
{
    if (privLen < 64)
    {
        _logErr.println("❌ Invalid private key length");
        return false;
    }

    Pubkey from{std::vector<uint8_t>(fromPub, fromPub + 32)};
    Pubkey to{std::vector<uint8_t>(toPub, toPub + 32)};

    // System program transfer: u32 instruction index (2) + u64 lamports
    std::vector<uint8_t> data = encodeU32LE(2);
    std::vector<uint8_t> amount = encodeU64LE(lamports);
    data.insert(data.end(), amount.begin(), amount.end());

    Transaction tx;
    tx.fee_payer = from;
    tx.recent_blockhash = recentBlockhash;
    tx.add(Instruction(Pubkey::fromBase58(SYSTEM_PROGRAM_B58),
                       {AccountMeta::writable(from, true), AccountMeta::writable(to, false)}, data));

    applyPriorityFee(tx);

    if (!tx.sign({Keypair::fromPrivateKey(privateKey)}))
    {
        return false;
    }

    outTxBase64 = tx.serializeBase64();
    return !outTxBase64.isEmpty();
}

bool Infratic::buildAndSignMemoTransaction(const uint8_t *privateKey, size_t privLen,
                                           const uint8_t *fromPub, const String &programIdBase58,
                                           const String &memoString, const String &recentBlockhash,
                                           String &outTxBase64)
{
    if (privLen < 64)
    {
        _logErr.println("❌ Invalid private key");
        return false;
    }

    Pubkey programId = Pubkey::fromBase58(programIdBase58);
    if (programId.data.size() != 32)
    {
        _logErr.println("❌ Program ID decode error");
        return false;
    }

    Transaction tx;
    tx.fee_payer = Pubkey{std::vector<uint8_t>(fromPub, fromPub + 32)};
    tx.recent_blockhash = recentBlockhash;
    tx.add(Instruction(programId, {}, std::vector<uint8_t>(memoString.begin(), memoString.end())));

    applyPriorityFee(tx);

    if (!tx.sign({Keypair::fromPrivateKey(privateKey)}))
    {
        return false;
    }

    outTxBase64 = tx.serializeBase64();
    return !outTxBase64.isEmpty();
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

Pubkey Pubkey::fromBase58(const String &str)
{
    Pubkey pk;
    pk.data = base58ToPubkey(str);
    return pk;
}

Keypair Keypair::fromPrivateKey(const uint8_t *key64)
{
    Keypair kp;
    kp.privkey = std::vector<uint8_t>(key64, key64 + 64);
    kp.pubkey_ = Pubkey{std::vector<uint8_t>(key64 + 32, key64 + 64)};
    return kp;
}

const Pubkey &Keypair::pubkey() const
{
    return pubkey_;
}

AccountMeta AccountMeta::signer(const Pubkey &key)
{
    return AccountMeta{key, true, false};
}

AccountMeta AccountMeta::writable(const Pubkey &key, bool isSigner)
{
    return AccountMeta{key, isSigner, true};
}

Instruction::Instruction(const Pubkey &pid, const std::vector<AccountMeta> &accts,
                         const std::vector<uint8_t> &d)
    : programId(pid), accounts(accts), data(d) {}

void Transaction::add(const Instruction &ix)
{
    instructions.push_back(ix);
}

namespace infratic_detail
{
    // Collects unique accounts and orders them the way the runtime expects:
    // fee payer, writable signers, readonly signers, writable, readonly.
    std::vector<CompiledKey> compileKeys(const Transaction &tx, uint8_t header[3])
    {
        std::vector<CompiledKey> all;
        auto add = [&](const Pubkey &k, bool signer, bool writable)
        {
            for (auto &e : all)
            {
                if (e.key.data == k.data)
                {
                    e.signer = e.signer || signer;
                    e.writable = e.writable || writable;
                    return;
                }
            }
            all.push_back({k, signer, writable});
        };

        add(tx.fee_payer, true, true);
        for (const auto &ix : tx.instructions)
        {
            for (const auto &acct : ix.accounts)
            {
                add(acct.pubkey, acct.isSigner, acct.isWritable);
            }
            add(ix.programId, false, false);
        }

        std::vector<CompiledKey> ordered;
        ordered.push_back(all[0]);
        const bool groups[4][2] = {{true, true}, {true, false}, {false, true}, {false, false}};
        for (const auto &g : groups)
        {
            for (size_t i = 1; i < all.size(); i++)
            {
                if (all[i].signer == g[0] && all[i].writable == g[1])
                    ordered.push_back(all[i]);
            }
        }

        header[0] = header[1] = header[2] = 0;
        for (const auto &k : ordered)
        {
            if (k.signer)
            {
                header[0]++;
                if (!k.writable) header[1]++;
            }
            else if (!k.writable)
            {
                header[2]++;
            }
        }
        return ordered;
    }

    int keyIndex(const std::vector<CompiledKey> &keys, const Pubkey &k)
    {
        for (size_t i = 0; i < keys.size(); i++)
        {
            if (keys[i].key.data == k.data) return (int)i;
        }
        return -1;
    }
}

using infratic_detail::CompiledKey;
using infratic_detail::compileKeys;
using infratic_detail::keyIndex;

std::vector<uint8_t> Transaction::serializeMessage() const
{
    if (version == 0)
    {
        return serializeMessageV0();
    }
    if (fee_payer.data.size() != 32)
    {
        _logErr.println("❌ Transaction: fee payer not set");
        return {};
    }

    uint8_t header[3];
    std::vector<CompiledKey> keys = compileKeys(*this, header);

    for (const auto &k : keys)
    {
        if (k.key.data.size() != 32)
        {
            _logErr.println("❌ Transaction: invalid public key in accounts");
            return {};
        }
    }

    uint8_t blockhash[32];
    size_t bhLen = sizeof(blockhash);
    if (!base58Decode(recent_blockhash, blockhash, bhLen) || bhLen != 32)
    {
        _logErr.println("❌ Transaction: invalid recent blockhash");
        return {};
    }

    std::vector<uint8_t> msg(header, header + 3);
    appendCompactU16(msg, keys.size());
    for (const auto &k : keys)
    {
        msg.insert(msg.end(), k.key.data.begin(), k.key.data.end());
    }
    msg.insert(msg.end(), blockhash, blockhash + 32);

    appendCompactU16(msg, instructions.size());
    for (const auto &ix : instructions)
    {
        msg.push_back((uint8_t)keyIndex(keys, ix.programId));
        appendCompactU16(msg, ix.accounts.size());
        for (const auto &acct : ix.accounts)
        {
            msg.push_back((uint8_t)keyIndex(keys, acct.pubkey));
        }
        appendCompactU16(msg, ix.data.size());
        msg.insert(msg.end(), ix.data.begin(), ix.data.end());
    }

    return msg;
}

bool Transaction::sign(const std::vector<Keypair> &signers)
{
    std::vector<uint8_t> msg = serializeMessage();
    if (msg.empty())
    {
        return false;
    }

    uint8_t header[3];
    std::vector<CompiledKey> keys = compileKeys(*this, header);

    signatures.assign(header[0], std::vector<uint8_t>(64, 0));
    bool ok = true;

    for (uint8_t i = 0; i < header[0]; i++)
    {
        const Keypair *found = nullptr;
        for (const auto &kp : signers)
        {
            if (kp.privkey.size() >= 64 && kp.pubkey().data == keys[i].key.data)
            {
                found = &kp;
                break;
            }
        }

        if (!found)
        {
            _logErr.println("❌ Missing signer: " + base58Encode(keys[i].key.data.data(), 32));
            ok = false;
            continue;
        }

        Ed25519::sign(signatures[i].data(), found->privkey.data(), found->privkey.data() + 32,
                      msg.data(), msg.size());
    }

    signature = signatures.empty() ? std::vector<uint8_t>() : signatures[0];
    return ok;
}

String Transaction::serializeBase64() const
{
    std::vector<uint8_t> msg = serializeMessage();
    if (msg.empty())
    {
        return "";
    }

    // older code may only fill `signature`
    std::vector<std::vector<uint8_t>> sigs = signatures;
    if (sigs.empty() && signature.size() == 64)
    {
        sigs.push_back(signature);
    }

    std::vector<uint8_t> finalTx;
    appendCompactU16(finalTx, sigs.size());
    for (const auto &sig : sigs)
    {
        finalTx.insert(finalTx.end(), sig.begin(), sig.end());
    }
    finalTx.insert(finalTx.end(), msg.begin(), msg.end());

    return toBase64(finalTx.data(), finalTx.size());
}

// ============================================================================
// COMMITMENTS, MERKLE TREES AND SIGNED ATTESTATIONS ("ZK" helpers)
//
// What is here, honestly:
//  - hash commitments: SHA-256 over a domain tag, the length-prefixed data and a
//    32 byte random secret. Hiding (while the secret is private) and binding.
//  - Merkle trees (RFC 6962 shape, 0x00/0x01 domain separation): prove that one
//    item belongs to a set with a known root.
//  - Ed25519 attestations by the device key: prove WHO vouches for a statement.
// Nothing here is zero-knowledge or proves a statement about hidden data
// mathematically; the verifier always trusts either the hash function (commitments,
// Merkle) or the signer (attestations).
// ============================================================================

namespace
{
    const char ZK_TAG_COMMIT[] = "infratic-zk/commit/v1";
    const char ZK_TAG_ATTEST[] = "infratic-zk/attest/v1";
    const char ZK_TAG_TIME[] = "infratic-zk/timestamp/v1";
    const char ZK_TAG_RANGE[] = "infratic-zk/range/v1";
    const char ZK_TAG_LEGACY_TIME[] = "infratic-zk/legacy-timestamp/v1";
    const size_t ZK_MAX_LEAVES = 4096;      // 128 KB of leaf hashes
    const size_t ZK_MAX_MEMO_META = 400;    // keeps the memo well inside a legacy transaction
    const size_t ZK_MAX_TX_BYTES = 1232;    // Solana packet limit for a serialized transaction

    // Incremental SHA-256
    struct Sha
    {
        mbedtls_sha256_context c;
        Sha()
        {
            mbedtls_sha256_init(&c);
            mbedtls_sha256_starts_ret(&c, 0);
        }
        ~Sha() { mbedtls_sha256_free(&c); }
        void add(const void *p, size_t n)
        {
            if (n) mbedtls_sha256_update_ret(&c, (const uint8_t *)p, n);
        }
        void addByte(uint8_t b) { add(&b, 1); }
        void addU32(uint32_t v)
        {
            uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
            add(b, 4);
        }
        void finish(uint8_t out[32]) { mbedtls_sha256_finish_ret(&c, out); }
    };

    void putU32(std::vector<uint8_t> &v, uint32_t x)
    {
        for (int i = 0; i < 4; i++) v.push_back((uint8_t)(x >> (8 * i)));
    }
    void putU64(std::vector<uint8_t> &v, uint64_t x)
    {
        for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
    }
    void putTag(std::vector<uint8_t> &v, const char *tag)
    {
        v.insert(v.end(), (const uint8_t *)tag, (const uint8_t *)tag + strlen(tag));
    }
    void putLP(std::vector<uint8_t> &v, const uint8_t *p, size_t n)
    {
        putU32(v, (uint32_t)n);
        v.insert(v.end(), p, p + n);
    }

    String zkHex(const uint8_t *p, size_t n)
    {
        static const char *d = "0123456789abcdef";
        std::vector<char> buf(n * 2 + 1);
        for (size_t i = 0; i < n; i++)
        {
            buf[2 * i] = d[p[i] >> 4];
            buf[2 * i + 1] = d[p[i] & 15];
        }
        buf[n * 2] = 0;
        return String(buf.data());
    }

    int hexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Strict: exactly 2*n hex chars, nothing else
    bool zkUnhex(const String &s, uint8_t *out, size_t n)
    {
        if (s.length() != n * 2) return false;
        const char *p = s.c_str();
        for (size_t i = 0; i < n; i++)
        {
            int hi = hexVal(p[2 * i]), lo = hexVal(p[2 * i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }

    // Constant time comparison (no early exit)
    bool ctEq(const uint8_t *a, const uint8_t *b, size_t n)
    {
        uint8_t diff = 0;
        for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
        return diff == 0;
    }

    void zkRandom(uint8_t *out, size_t n)
    {
        for (size_t i = 0; i < n; i += 4)
        {
            uint32_t r = esp_random();
            for (size_t j = 0; j < 4 && i + j < n; j++) out[i + j] = (uint8_t)(r >> (8 * j));
        }
    }

    std::vector<uint8_t> bytesOf(const String &s)
    {
        return std::vector<uint8_t>((const uint8_t *)s.c_str(), (const uint8_t *)s.c_str() + s.length());
    }

    void commitHash(const uint8_t *data, size_t len, const uint8_t secret[32], uint8_t out[32])
    {
        Sha h;
        h.add(ZK_TAG_COMMIT, strlen(ZK_TAG_COMMIT));
        h.addU32((uint32_t)len);
        h.add(data, len);
        h.add(secret, 32);
        h.finish(out);
    }

    // message committed by the deprecated createDataCommitment: lp(data) || lp(secret text) || u64le(timestamp)
    std::vector<uint8_t> legacyCommitMessage(const String &data, const String &secret, uint64_t ts)
    {
        std::vector<uint8_t> m;
        putLP(m, (const uint8_t *)data.c_str(), data.length());
        putLP(m, (const uint8_t *)secret.c_str(), secret.length());
        putU64(m, ts);
        return m;
    }

    // ---- Merkle (RFC 6962 / 9162) ----
    void leafHash(const String &d, uint8_t out[32])
    {
        Sha h;
        h.addByte(0x00);
        h.add(d.c_str(), d.length());
        h.finish(out);
    }
    void nodeHash(const uint8_t *l, const uint8_t *r, uint8_t out[32])
    {
        Sha h;
        h.addByte(0x01);
        h.add(l, 32);
        h.add(r, 32);
        h.finish(out);
    }
    // largest power of two strictly smaller than n (n > 1)
    size_t splitPoint(size_t n)
    {
        size_t k = 1;
        while (k < n) k <<= 1;
        return k >> 1;
    }
    // root of n leaf hashes stored back to back
    void merkleHash(const uint8_t *leaves, size_t n, uint8_t out[32])
    {
        if (n == 1)
        {
            memcpy(out, leaves, 32);
            return;
        }
        size_t k = splitPoint(n);
        uint8_t l[32], r[32];
        merkleHash(leaves, k, l);
        merkleHash(leaves + 32 * k, n - k, r);
        nodeHash(l, r, out);
    }
    // sibling hashes (leaf to root) for leaf m
    void merklePath(const uint8_t *leaves, size_t n, size_t m, std::vector<uint8_t> &out)
    {
        if (n == 1) return;
        size_t k = splitPoint(n);
        uint8_t other[32];
        if (m < k)
        {
            merklePath(leaves, k, m, out);
            merkleHash(leaves + 32 * k, n - k, other);
        }
        else
        {
            merklePath(leaves + 32 * k, n - k, m - k, out);
            merkleHash(leaves, k, other);
        }
        out.insert(out.end(), other, other + 32);
    }
    bool hashLeaves(const std::vector<String> &list, std::vector<uint8_t> &out)
    {
        if (list.empty())
        {
            _logErr.println("Merkle: empty data list");
            return false;
        }
        if (list.size() > ZK_MAX_LEAVES)
        {
            _logErr.println("Merkle: too many leaves (max 4096)");
            return false;
        }
        out.resize(list.size() * 32);
        for (size_t i = 0; i < list.size(); i++) leafHash(list[i], out.data() + 32 * i);
        return true;
    }

    // ---- statements that get signed ----
    bool signStatement(const Keypair &device, const std::vector<uint8_t> &msg, String &outSigHex, String &outSigner)
    {
        if (device.privkey.size() < 64 || device.pubkey().data.size() != 32) return false;
        uint8_t sig[64];
        Ed25519::sign(sig, device.privkey.data(), device.privkey.data() + 32, msg.data(), msg.size());
        // catches a keypair whose public half does not belong to its seed
        if (!Ed25519::verify(sig, device.privkey.data() + 32, msg.data(), msg.size())) return false;
        outSigHex = zkHex(sig, 64);
        outSigner = base58Encode(device.privkey.data() + 32, 32);
        return true;
    }

    bool verifyStatement(const std::vector<uint8_t> &msg, const String &sigHex, const String &signerB58,
                         const String &expectedSignerB58)
    {
        uint8_t sig[64];
        if (!zkUnhex(sigHex, sig, 64)) return false;
        std::vector<uint8_t> signer = base58ToPubkey(signerB58);
        std::vector<uint8_t> expected = base58ToPubkey(expectedSignerB58);
        if (signer.size() != 32 || expected.size() != 32 || !ctEq(signer.data(), expected.data(), 32)) return false;
        return Ed25519::verify(sig, expected.data(), msg.data(), msg.size());
    }

    std::vector<uint8_t> attestStatement(const String &context, const uint8_t commitment[32],
                                         const std::vector<uint8_t> &publicData)
    {
        std::vector<uint8_t> m;
        putTag(m, ZK_TAG_ATTEST);
        putLP(m, (const uint8_t *)context.c_str(), context.length());
        m.insert(m.end(), commitment, commitment + 32);
        putLP(m, publicData.data(), publicData.size());
        return m;
    }

    std::vector<uint8_t> timeStatement(const uint8_t hash[32], int64_t t, const String &blockhash)
    {
        std::vector<uint8_t> m;
        putTag(m, ZK_TAG_TIME);
        m.insert(m.end(), hash, hash + 32);
        putU64(m, (uint64_t)t);
        putLP(m, (const uint8_t *)blockhash.c_str(), blockhash.length());
        return m;
    }

    std::vector<uint8_t> rangeStatement(const uint8_t commitment[32], int64_t lo, int64_t hi)
    {
        std::vector<uint8_t> m;
        putTag(m, ZK_TAG_RANGE);
        m.insert(m.end(), commitment, commitment + 32);
        putU64(m, (uint64_t)lo);
        putU64(m, (uint64_t)hi);
        return m;
    }

    std::vector<uint8_t> i64Bytes(int64_t v)
    {
        std::vector<uint8_t> b;
        putU64(b, (uint64_t)v);
        return b;
    }

    // "ZK_COMMITMENT:<64 hex>[|META:<meta>]"; the hash has a fixed length so the layout is unambiguous
    bool buildMemo(const String &hashHex, const String &metadata, String &memo)
    {
        uint8_t h[32];
        if (!zkUnhex(hashHex, h, 32))
        {
            _logErr.println("ZK memo: commitment must be 64 hex chars");
            return false;
        }
        if (metadata.length() > ZK_MAX_MEMO_META)
        {
            _logErr.println("ZK memo: metadata too long (max 400 bytes)");
            return false;
        }
        for (unsigned i = 0; i < metadata.length(); i++)
        {
            if (metadata.c_str()[i] == 0)
            {
                _logErr.println("ZK memo: metadata contains a NUL byte");
                return false;
            }
        }
        memo = String("ZK_COMMITMENT:") + zkHex(h, 32);
        if (!metadata.isEmpty()) memo += String("|META:") + metadata;
        return true;
    }
}

// ============================================================================
// HASH COMMITMENTS
// ============================================================================

bool Infratic::commitDataWithSecret(const std::vector<uint8_t> &data, const std::vector<uint8_t> &secret,
                                    std::vector<uint8_t> &outCommitment)
{
    if (secret.size() != 32 || data.size() > 0xFFFFFFF0u)
    {
        _logErr.println("commit: secret must be 32 bytes");
        return false;
    }
    outCommitment.resize(32);
    commitHash(data.data(), data.size(), secret.data(), outCommitment.data());
    return true;
}

bool Infratic::commitData(const std::vector<uint8_t> &data, std::vector<uint8_t> &outCommitment,
                          std::vector<uint8_t> &outSecret)
{
    outSecret.resize(32);
    zkRandom(outSecret.data(), 32);
    return commitDataWithSecret(data, outSecret, outCommitment);
}

bool Infratic::verifyCommitment(const std::vector<uint8_t> &data, const std::vector<uint8_t> &secret,
                                const std::vector<uint8_t> &commitment)
{
    if (commitment.size() != 32) return false;
    std::vector<uint8_t> again;
    if (!commitDataWithSecret(data, secret, again)) return false;
    return ctEq(again.data(), commitment.data(), 32);
}

bool Infratic::commitString(const String &data, String &outCommitmentHex, String &outSecretHex)
{
    std::vector<uint8_t> c, s;
    if (!commitData(bytesOf(data), c, s)) return false;
    outCommitmentHex = zkHex(c.data(), 32);
    outSecretHex = zkHex(s.data(), 32);
    return true;
}

bool Infratic::verifyCommitmentString(const String &data, const String &secretHex, const String &commitmentHex)
{
    std::vector<uint8_t> s(32), c(32);
    if (!zkUnhex(secretHex, s.data(), 32) || !zkUnhex(commitmentHex, c.data(), 32)) return false;
    return verifyCommitment(bytesOf(data), s, c);
}

bool Infratic::createDataCommitment(const String &data, const String &secret, String &outCommitment,
                                    String &outNonce, uint64_t &outTimestamp)
{
    outTimestamp = millis();
    std::vector<uint8_t> c, s;
    if (!commitData(legacyCommitMessage(data, secret, outTimestamp), c, s)) return false;
    outCommitment = zkHex(c.data(), 32);
    outNonce = zkHex(s.data(), 32);
    return true;
}

bool Infratic::verifyDataCommitment(const String &data, const String &secret, const String &nonce,
                                    uint64_t timestamp, const String &originalCommitment)
{
    std::vector<uint8_t> s(32), c(32);
    if (!zkUnhex(nonce, s.data(), 32) || !zkUnhex(originalCommitment, c.data(), 32)) return false;
    bool ok = verifyCommitment(legacyCommitMessage(data, secret, timestamp), s, c);
    if (!ok) _logErr.println("Commitment does not match");
    return ok;
}

bool Infratic::storeCommitmentOnChain(const String &privateKeyBase58, const String &fromPubkeyBase58,
                                      const String &commitment, const String &metadata, String &outTxSignature)
{
    String memo;
    if (!buildMemo(commitment, metadata, memo)) return false;

    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        _logErr.println("Private key decode error");
        return false;
    }
    uint8_t fromPub[32];
    size_t fromLen = sizeof(fromPub);
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32)
    {
        _logErr.println("Public key decode error");
        return false;
    }

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return false;

    String txBase64;
    if (!buildAndSignMemoTransaction(privateKey, privLen, fromPub, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                                     memo, blockhash, txBase64))
    {
        return false;
    }
    if (!sendRawTransaction(txBase64, outTxSignature)) return false;
    if (!confirmTransaction(outTxSignature, 5000))
    {
        _logErr.println("Commitment transaction not confirmed in time");
        return false;
    }
    _logInfo.println("Commitment stored on-chain: " + outTxSignature);
    return true;
}

// ============================================================================
// MERKLE TREES
// ============================================================================

bool Infratic::buildMerkleTree(const std::vector<String> &dataList, String &outRoot)
{
    std::vector<uint8_t> leaves;
    if (!hashLeaves(dataList, leaves)) return false;
    uint8_t root[32];
    merkleHash(leaves.data(), dataList.size(), root);
    outRoot = zkHex(root, 32);
    return true;
}

bool Infratic::createMerkleProof(const std::vector<String> &dataList, size_t dataIndex, MerkleProof &outProof)
{
    outProof.siblings.clear();
    outProof.root = "";
    outProof.index = 0;
    outProof.leafCount = 0;
    outProof.isValid = false;

    if (dataIndex >= dataList.size())
    {
        _logErr.println("Merkle proof: index out of range");
        return false;
    }
    std::vector<uint8_t> leaves;
    if (!hashLeaves(dataList, leaves)) return false;

    std::vector<uint8_t> path;
    merklePath(leaves.data(), dataList.size(), dataIndex, path);
    for (size_t i = 0; i < path.size(); i += 32) outProof.siblings.push_back(zkHex(path.data() + i, 32));

    uint8_t root[32];
    merkleHash(leaves.data(), dataList.size(), root);
    outProof.root = zkHex(root, 32);
    outProof.index = dataIndex;
    outProof.leafCount = dataList.size();
    outProof.isValid = true;
    return true;
}

bool Infratic::verifyMerkleProof(const String &data, const MerkleProof &proof, const String &trustedRootHex)
{
    uint8_t root[32];
    if (!zkUnhex(trustedRootHex, root, 32)) return false;
    if (proof.leafCount == 0 || proof.index >= proof.leafCount || proof.siblings.size() > 64) return false;

    uint8_t r[32];
    leafHash(data, r);

    // RFC 9162 section 2.1.3.2
    size_t fn = proof.index, sn = proof.leafCount - 1;
    for (size_t i = 0; i < proof.siblings.size(); i++)
    {
        uint8_t p[32];
        if (!zkUnhex(proof.siblings[i], p, 32) || sn == 0) return false;
        if ((fn & 1) || fn == sn)
        {
            nodeHash(p, r, r);
            if (!(fn & 1))
            {
                do
                {
                    fn >>= 1;
                    sn >>= 1;
                } while (!(fn & 1) && fn != 0);
            }
        }
        else
        {
            nodeHash(r, p, r);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return sn == 0 && ctEq(r, root, 32);
}

bool Infratic::verifyMerkleProof(const String &data, const MerkleProof &proof)
{
    return verifyMerkleProof(data, proof, proof.root);
}

// ============================================================================
// SIGNED ATTESTATIONS
// ============================================================================

bool Infratic::createCommitmentAttestation(const Keypair &device, const String &commitmentHex, const String &context,
                                           const std::vector<uint8_t> &publicData, CommitmentAttestation &out)
{
    uint8_t c[32];
    if (!zkUnhex(commitmentHex, c, 32)) return false;
    CommitmentAttestation a;
    a.commitment = zkHex(c, 32);
    a.context = context;
    a.publicData = publicData;
    if (!signStatement(device, attestStatement(context, c, publicData), a.signature, a.signer)) return false;
    out = a;
    return true;
}

bool Infratic::verifyCommitmentAttestation(const CommitmentAttestation &att, const String &expectedSignerBase58)
{
    uint8_t c[32];
    if (!zkUnhex(att.commitment, c, 32)) return false;
    return verifyStatement(attestStatement(att.context, c, att.publicData), att.signature, att.signer,
                           expectedSignerBase58);
}

bool Infratic::signTimestamp(const Keypair &device, const std::vector<uint8_t> &data, int64_t unixTime,
                             const String &blockhash, SignedTimestamp &out)
{
    uint8_t h[32];
    {
        Sha s;
        s.add(data.data(), data.size());
        s.finish(h);
    }
    SignedTimestamp t;
    t.dataHash = zkHex(h, 32);
    t.unixTime = unixTime;
    t.blockhash = blockhash;
    if (!signStatement(device, timeStatement(h, unixTime, blockhash), t.signature, t.signer)) return false;
    out = t;
    return true;
}

bool Infratic::createSignedTimestamp(const Keypair &device, const std::vector<uint8_t> &data, SignedTimestamp &out)
{
    int64_t now = 0;
    if (!getClusterTime(now) || now <= 0)
    {
        _logErr.println("Signed timestamp: cluster time unavailable");
        return false;
    }
    String blockhash = getLatestBlockhash(); // optional anchor, empty if the RPC cannot provide one
    return signTimestamp(device, data, now, blockhash, out);
}

bool Infratic::verifySignedTimestamp(const SignedTimestamp &ts, const std::vector<uint8_t> &data,
                                     const String &expectedSignerBase58)
{
    uint8_t claimed[32], h[32];
    if (!zkUnhex(ts.dataHash, claimed, 32)) return false;
    {
        Sha s;
        s.add(data.data(), data.size());
        s.finish(h);
    }
    if (!ctEq(h, claimed, 32)) return false;
    return verifyStatement(timeStatement(h, ts.unixTime, ts.blockhash), ts.signature, ts.signer, expectedSignerBase58);
}

bool Infratic::createRangeAttestation(const Keypair &device, int64_t value, int64_t minValue, int64_t maxValue,
                                      RangeAttestation &out, std::vector<uint8_t> &outSecret)
{
    if (minValue > maxValue || value < minValue || value > maxValue)
    {
        _logErr.println("Range attestation: value outside the range");
        return false;
    }
    std::vector<uint8_t> c, s;
    if (!commitData(i64Bytes(value), c, s)) return false;
    RangeAttestation a;
    a.commitment = zkHex(c.data(), 32);
    a.minValue = minValue;
    a.maxValue = maxValue;
    if (!signStatement(device, rangeStatement(c.data(), minValue, maxValue), a.signature, a.signer)) return false;
    out = a;
    outSecret = s;
    return true;
}

bool Infratic::verifyRangeAttestation(const RangeAttestation &att, const String &expectedSignerBase58)
{
    uint8_t c[32];
    if (!zkUnhex(att.commitment, c, 32)) return false;
    return verifyStatement(rangeStatement(c, att.minValue, att.maxValue), att.signature, att.signer,
                           expectedSignerBase58);
}

bool Infratic::openRangeAttestation(const RangeAttestation &att, int64_t value, const std::vector<uint8_t> &secret,
                                    const String &expectedSignerBase58)
{
    if (value < att.minValue || value > att.maxValue) return false;
    if (!verifyRangeAttestation(att, expectedSignerBase58)) return false;
    std::vector<uint8_t> c(32);
    if (!zkUnhex(att.commitment, c.data(), 32)) return false;
    return verifyCommitment(i64Bytes(value), secret, c);
}

// ============================================================================
// DEPRECATED NAMES THAT CANNOT BE IMPLEMENTED HONESTLY
// ============================================================================

bool Infratic::createzkSNARKProof(const std::vector<uint8_t> &, const std::vector<uint8_t> &, const String &,
                                  zkSNARKProof &outProof)
{
    outProof.proofData.clear();
    outProof.publicInputs.clear();
    outProof.isValid = false;
    _logErr.println("createzkSNARKProof: there is no zkSNARK prover on the device. Use createCommitmentAttestation.");
    return false;
}

bool Infratic::verifyzkSNARKProof(const zkSNARKProof &, const std::vector<uint8_t> &)
{
    _logErr.println("verifyzkSNARKProof: there is no zkSNARK verifier. Use verifyCommitmentAttestation.");
    return false;
}

bool Infratic::createRangeProof(int64_t, int64_t, int64_t, const String &, RangeProof &outProof)
{
    outProof.isValid = false;
    _logErr.println("createRangeProof: not a range proof. Use createRangeAttestation (signed claim).");
    return false;
}

bool Infratic::verifyRangeProof(int64_t, const String &, const RangeProof &)
{
    _logErr.println("verifyRangeProof: not a range proof. Use verifyRangeAttestation/openRangeAttestation.");
    return false;
}

namespace
{
    void legacyTimeHash(const String &data, uint64_t ts, const String &blockhash, uint8_t out[32])
    {
        Sha h;
        h.add(ZK_TAG_LEGACY_TIME, strlen(ZK_TAG_LEGACY_TIME));
        h.addU32(data.length());
        h.add(data.c_str(), data.length());
        std::vector<uint8_t> t;
        putU64(t, ts);
        h.add(t.data(), 8);
        h.addU32(blockhash.length());
        h.add(blockhash.c_str(), blockhash.length());
        h.finish(out);
    }
}

bool Infratic::createTimestampedProof(const String &data, String &outProof, uint64_t &outTimestamp,
                                      String &outBlockhash)
{
    int64_t now = 0;
    if (!getClusterTime(now) || now <= 0)
    {
        _logErr.println("Timestamped proof: cluster time unavailable");
        return false;
    }
    outTimestamp = (uint64_t)now;
    outBlockhash = getLatestBlockhash();
    if (outBlockhash.isEmpty()) outBlockhash = "NO_BLOCKHASH";
    uint8_t h[32];
    legacyTimeHash(data, outTimestamp, outBlockhash, h);
    outProof = zkHex(h, 32);
    return true;
}

bool Infratic::verifyTimestampedProof(const String &data, const String &proof, uint64_t timestamp,
                                      const String &blockhash)
{
    uint8_t claimed[32], h[32];
    if (!zkUnhex(proof, claimed, 32)) return false;
    legacyTimeHash(data, timestamp, blockhash, h);
    return ctEq(h, claimed, 32);
}

// ============================================================================
// BATCHES
// ============================================================================

bool Infratic::createBatchCommitments(const std::vector<String> &dataList, const String &,
                                      std::vector<ZKCommitment> &outCommitments)
{
    outCommitments.clear();
    for (size_t i = 0; i < dataList.size(); i++)
    {
        ZKCommitment z;
        if (!commitString(dataList[i], z.commitment, z.nonce))
        {
            outCommitments.clear();
            return false;
        }
        z.timestamp = millis();
        z.metadata = "batch_commit";
        outCommitments.push_back(z);
    }
    _logInfo.printf("Created %u batch commitments\n", (unsigned)outCommitments.size());
    return !outCommitments.empty();
}

bool Infratic::storeBatchCommitmentsOnChain(const String &privateKeyBase58, const String &fromPubkeyBase58,
                                            const std::vector<ZKCommitment> &commitments, String &outTxSignature)
{
    std::vector<String> leaves;
    for (size_t i = 0; i < commitments.size(); i++) leaves.push_back(commitments[i].commitment);
    String root;
    if (!buildMerkleTree(leaves, root)) return false;
    return storeCommitmentOnChain(privateKeyBase58, fromPubkeyBase58, root,
                                  "batch_size:" + String((unsigned long)commitments.size()), outTxSignature);
}

// ============================================================================
// ANCHOR PROGRAM STORAGE OPERATIONS
// ============================================================================

namespace
{
    struct AnchorCall
    {
        Keypair signer;
        Pubkey authority;
        Pubkey program;
        Pubkey pda;
        String pdaStr;
        uint8_t bump;
    };

    // Decodes keys, checks that the secret key belongs to `authorityPubkey` and derives the PDA
    // from seedsWithoutAuthority + authority.
    bool anchorPrepare(Infratic &sol, const String &privateKeyBase58, const String &authorityPubkey,
                       const String &programId, const std::vector<std::vector<uint8_t>> &seedsWithoutAuthority,
                       AnchorCall &c)
    {
        uint8_t privateKey[128];
        size_t privLen = sizeof(privateKey);
        if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
        {
            _logErr.println("Anchor: private key decode failed");
            return false;
        }
        c.signer = Keypair::fromPrivateKey(privateKey);
        c.authority = Pubkey::fromBase58(authorityPubkey);
        c.program = Pubkey::fromBase58(programId);
        if (c.authority.data.size() != 32 || c.program.data.size() != 32)
        {
            _logErr.println("Anchor: invalid authority or program id");
            return false;
        }
        if (c.signer.pubkey().data != c.authority.data)
        {
            _logErr.println("Anchor: private key does not belong to the authority pubkey");
            return false;
        }
        std::vector<std::vector<uint8_t>> seeds = seedsWithoutAuthority;
        seeds.push_back(c.authority.data);
        if (!sol.derivePDA(seeds, programId, c.pdaStr, c.bump)) return false;
        c.pda = Pubkey::fromBase58(c.pdaStr);
        return true;
    }

    bool anchorSend(Infratic &sol, AnchorCall &c, const std::vector<AccountMeta> &accounts,
                    const std::vector<uint8_t> &data, String &outSig)
    {
        String blockhash = sol.getLatestBlockhash();
        if (blockhash.isEmpty()) return false;

        Transaction tx;
        tx.fee_payer = c.authority;
        tx.recent_blockhash = blockhash;
        tx.add(Instruction(c.program, accounts, data));
        sol.applyPriorityFee(tx);
        if (!tx.sign({c.signer}))
        {
            _logErr.println("Anchor: signing failed");
            return false;
        }
        String b64 = tx.serializeBase64();
        std::vector<uint8_t> raw;
        if (b64.isEmpty() || !fromBase64(b64.c_str(), raw) || raw.size() > ZK_MAX_TX_BYTES)
        {
            _logErr.println("Anchor: transaction empty or larger than 1232 bytes (shorten the metadata)");
            return false;
        }
        if (!sol.sendRawTransaction(b64, outSig)) return false;
        return sol.confirmTransaction(outSig, 5000);
    }

    bool hash32(const String &hex, BorshWriter &w)
    {
        uint8_t h[32];
        if (!zkUnhex(hex, h, 32))
        {
            _logErr.println("Anchor: hash must be 64 hex chars");
            return false;
        }
        w.bytes(std::vector<uint8_t>(h, h + 32));
        return true;
    }

    std::vector<uint8_t> seedBytes(const String &s)
    {
        return bytesOf(s);
    }
}

bool Infratic::initializeZKStorage(const String &privateKeyBase58, const String &authorityPubkey,
                                   const String &programId, const String &seedName, String &outPDA,
                                   String &outTxSignature)
{
    AnchorCall c;
    if (!anchorPrepare(*this, privateKeyBase58, authorityPubkey, programId, {seedBytes(seedName)}, c)) return false;
    outPDA = c.pdaStr;

    uint64_t balance = 0;
    if (getSolBalance(outPDA, balance) && balance > 0)
    {
        _logInfo.println("ZK storage already initialized: " + outPDA);
        outTxSignature = "EXISTING_ACCOUNT";
        return true;
    }

    BorshWriter w;
    w.bytes(calculateDiscriminator("initialize_storage")).str(seedName);
    return anchorSend(*this, c,
                      {AccountMeta::writable(c.pda, false), AccountMeta::writable(c.authority, true),
                       AccountMeta{Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), false, false}},
                      w.data, outTxSignature);
}

static bool anchorCommitmentCall(Infratic &sol, const char *ixName, const String &privateKeyBase58,
                                 const String &authorityPubkey, const String &programId, const String &seedName,
                                 const String &commitment, const String &metadata, String &outTxSignature)
{
    AnchorCall c;
    if (!anchorPrepare(sol, privateKeyBase58, authorityPubkey, programId, {seedBytes(seedName)}, c)) return false;
    BorshWriter w;
    w.bytes(sol.calculateDiscriminator(ixName));
    if (!hash32(commitment, w)) return false;
    int64_t now = 0;
    if (!sol.getClusterTime(now) || now <= 0)
    {
        _logErr.println("Anchor: cluster time unavailable");
        return false;
    }
    w.str(metadata).u64((uint64_t)now);
    return anchorSend(sol, c, {AccountMeta::writable(c.pda, false), AccountMeta::signer(c.authority)}, w.data,
                      outTxSignature);
}

bool Infratic::storeCommitmentInAnchor(const String &privateKeyBase58, const String &authorityPubkey,
                                       const String &programId, const String &seedName, const String &commitment,
                                       const String &metadata, String &outTxSignature)
{
    return anchorCommitmentCall(*this, "store_commitment", privateKeyBase58, authorityPubkey, programId, seedName,
                                commitment, metadata, outTxSignature);
}

bool Infratic::updateCommitmentInAnchor(const String &privateKeyBase58, const String &authorityPubkey,
                                        const String &programId, const String &seedName,
                                        const String &newCommitment, const String &metadata, String &outTxSignature)
{
    return anchorCommitmentCall(*this, "update_commitment", privateKeyBase58, authorityPubkey, programId, seedName,
                                newCommitment, metadata, outTxSignature);
}

bool Infratic::storeMerkleRootInAnchor(const String &privateKeyBase58, const String &authorityPubkey,
                                       const String &programId, const String &seedName, const String &merkleRoot,
                                       uint32_t leafCount, const String &metadata, String &outTxSignature)
{
    AnchorCall c;
    if (!anchorPrepare(*this, privateKeyBase58, authorityPubkey, programId, {seedBytes(seedName)}, c)) return false;
    BorshWriter w;
    w.bytes(calculateDiscriminator("store_merkle_root"));
    if (!hash32(merkleRoot, w)) return false;
    w.u32(leafCount).str(metadata);
    return anchorSend(*this, c, {AccountMeta::writable(c.pda, false), AccountMeta::signer(c.authority)}, w.data,
                      outTxSignature);
}

bool Infratic::storeBatchInAnchor(const String &privateKeyBase58, const String &authorityPubkey,
                                  const String &programId, const String &batchId, const String &batchRoot,
                                  uint32_t batchSize, const String &metadata, String &outTxSignature)
{
    AnchorCall c;
    std::vector<uint8_t> tag((const uint8_t *)"batch", (const uint8_t *)"batch" + 5);
    if (!anchorPrepare(*this, privateKeyBase58, authorityPubkey, programId, {tag, seedBytes(batchId)}, c))
        return false;
    BorshWriter w;
    w.bytes(calculateDiscriminator("store_batch"));
    if (!hash32(batchRoot, w)) return false;
    w.u32(batchSize).str(metadata);
    return anchorSend(*this, c,
                      {AccountMeta::writable(c.pda, false), AccountMeta::writable(c.authority, true),
                       AccountMeta{Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), false, false}},
                      w.data, outTxSignature);
}


// ============================================================================
// X402 ESCROW - SETUP & ACCOUNT READING
// ============================================================================

void Infratic::setEscrowProgramId(const String &programId)
{
    _escrowProgramId = programId;
    _logInfo.println("✅ Escrow Program ID set: " + _escrowProgramId);
}

bool Infratic::deriveEscrowPDA(const String &orderId, const String &buyerPubkeyBase58,
                               String &outPDA, uint8_t &outBump)
{
    if (_escrowProgramId.isEmpty())
    {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return false;
    }

    Pubkey buyer = Pubkey::fromBase58(buyerPubkeyBase58);
    if (buyer.data.size() != 32 || orderId.length() > 32)
    {
        _logErr.println("❌ Escrow PDA: invalid buyer or order_id longer than 32 bytes");
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds = {
        {'e', 's', 'c', 'r', 'o', 'w'},
        std::vector<uint8_t>(orderId.begin(), orderId.end()),
        buyer.data};
    return derivePDA(seeds, _escrowProgramId, outPDA, outBump);
}

EscrowAccountResult Infratic::getEscrowAccount(const String &escrowPdaBase58, const String &commitment)
{
    _logInfo.println("\n=== Get Escrow Account Info ===");

    if (_escrowProgramId.isEmpty())
    {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, {}, "Program ID not set"};
    }

    std::vector<uint8_t> data;
    String owner;
    if (!getAccountData(escrowPdaBase58, data, commitment, &owner))
    {
        return {false, {}, "Failed to get account info (getAccountInfo fail)"};
    }

    if (owner != _escrowProgramId)
    {
        _logErr.println("❌ Account is not owned by the escrow program: " + owner);
        return {false, {}, "Account is not owned by escrow program"};
    }

    EscrowAccount account;
    if (!deserializeEscrowAccount(data, account))
    {
        return {false, {}, "Failed to decode account data (deserialize fail)"};
    }

    _logInfo.println("✅ Escrow account read successfully");
    _logInfo.println("   Buyer: " + account.buyer);
    _logInfo.println("   Status: " + String((int)account.status));

    return {true, account, ""};
}

bool Infratic::deserializeEscrowAccount(const std::vector<uint8_t> &data, EscrowAccount &outAccount)
{
    // 8 byte Anchor discriminator + fields in Rust struct order
    const size_t ANCHOR_DISCRIMINATOR_SIZE = 8;
    if (data.size() < ANCHOR_DISCRIMINATOR_SIZE)
    {
        _logErr.println("❌ Deserialize Error: data too short");
        return false;
    }

    BorshReader r(data, ANCHOR_DISCRIMINATOR_SIZE);
    outAccount.buyer = r.pubkey();
    outAccount.seller = r.pubkey();
    outAccount.amount = r.u64();
    outAccount.orderId = r.str(ESCROW_ORDER_ID_MAX);
    outAccount.status = (EscrowStatus)r.u8();
    outAccount.createdAt = (int64_t)r.u64();
    outAccount.expiresAt = (int64_t)r.u64();
    outAccount.bump = r.u8();
    outAccount.deliveryConfirmed = r.u8() != 0;
    outAccount.disputeInitiated = r.u8() != 0;
    outAccount.proofHash = r.str(ESCROW_PROOF_HASH_MAX);

    if (!r.ok)
    {
        _logErr.printf("❌ Deserialize Error: invalid escrow data (size: %u)\n", (unsigned)data.size());
        return false;
    }
    return true;
}

// ============================================================================
// ESCROW CREATE
// ============================================================================

EscrowCreateResult Infratic::escrow_create(
    const String &buyerPrivateKeyBase58,
    const String &buyerPubkeyBase58,
    const String &sellerPubkeyBase58,
    uint64_t amount,
    const String &order_id,
    int64_t expiration_duration
) {
    _logInfo.println("\n=== 1. Create Escrow ===");

    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "", 0, "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(buyerPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        _logErr.println("❌ Failed to decode buyer private key");
        return {false, "", "", 0, "Invalid buyer private key"};
    }
    
    Keypair buyerKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey buyer = Pubkey::fromBase58(buyerPubkeyBase58);
    Pubkey seller = Pubkey::fromBase58(sellerPubkeyBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    if (order_id.isEmpty() || order_id.length() > 32)
    {
        _logErr.println("❌ order_id must be 1-32 bytes (PDA seed limit)");
        return {false, "", "", 0, "Invalid order_id length"};
    }

    // 2. PDA Derivation (seeds: "escrow", order_id, buyer)
    String pdaAddress;
    uint8_t bump;
    if (!deriveEscrowPDA(order_id, buyerPubkeyBase58, pdaAddress, bump)) {
        _logErr.println("❌ Failed to derive escrow PDA address");
        return {false, "", "", 0, "PDA derivation failed"};
    }
    
    Pubkey escrowPda = Pubkey::fromBase58(pdaAddress);
    _logInfo.println("✅ PDA derived: " + pdaAddress);
    _logInfo.printf("   Bump: %d\n", bump);

    // 3. Rent: escrow account is 300 bytes (8 discriminator + 292 data)
    uint64_t RENT_LAMPORTS = 0;
    if (!getMinimumBalanceForRentExemption(ESCROW_ACCOUNT_SPACE, RENT_LAMPORTS))
    {
        RENT_LAMPORTS = 3000000; // estimate when RPC fails (~0.00298 SOL for 300 bytes)
        _logErr.println("⚠️  Could not get rent from RPC, using an estimate");
    }
    const uint64_t TX_FEE_LAMPORTS = 5000;

    _logInfo.printf("💰 Rent: %llu lamports\n", (unsigned long long)RENT_LAMPORTS);
    _logInfo.printf("💰 Transfer amount: %llu lamports\n", (unsigned long long)amount);
    _logInfo.printf("💰 TOTAL: %llu lamports\n", (unsigned long long)(RENT_LAMPORTS + amount + TX_FEE_LAMPORTS));

    // 4. Check that the buyer has enough balance
    uint64_t buyerBalance = 0;
    if (!getSolBalance(buyerPubkeyBase58, buyerBalance)) {
        return {false, pdaAddress, "", bump, "Failed to get buyer balance"};
    }
    
    uint64_t totalRequired = RENT_LAMPORTS + amount + TX_FEE_LAMPORTS;
    if (buyerBalance < totalRequired) {
        _logErr.printf("❌ Insufficient balance! Required: %llu, Available: %llu\n",
                       (unsigned long long)totalRequired, (unsigned long long)buyerBalance);
        return {false, pdaAddress, "", bump, "Insufficient buyer balance"};
    }

    // 5. Build instruction data
    std::vector<uint8_t> instructionData = calculateDiscriminator("create_escrow");
    
    // amount (u64, little-endian)
    std::vector<uint8_t> amountBytes = encodeU64LE(amount);
    instructionData.insert(instructionData.end(), amountBytes.begin(), amountBytes.end());
    
    // order_id (Anchor String: u32 length + data)
    appendBorshString(instructionData, order_id);
    
    // expiration (i64, little-endian)
    std::vector<uint8_t> expBytes = encodeI64LE(expiration_duration);
    instructionData.insert(instructionData.end(), expBytes.begin(), expBytes.end());
    
    // bump (u8)
    instructionData.push_back(bump);

    _logInfo.printf("📦 Instruction size: %u bytes\n", (unsigned)instructionData.size());

    // 6. Account order (must match the Rust program)
    // Order in the Rust program: escrow, buyer, seller, system_program
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false),  // escrow (writable, not signer)
            AccountMeta::writable(buyer, true),        // buyer (writable, signer)
            AccountMeta{seller, false, false},         // seller (readonly, not signer)
            AccountMeta{Pubkey::fromBase58(SYSTEM_PROGRAM_B58), false, false} // system_program
        },
        instructionData
    );

    // 7. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) {
        return {false, pdaAddress, "", bump, "Failed to get blockhash"};
    }

    Transaction tx;
    tx.fee_payer = buyer;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({buyerKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        _logErr.println("❌ Failed to send escrow create transaction");
        return {false, pdaAddress, "", bump, "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Escrow create transaction sent: " + txSignature);
    
    // 8. Transaction confirmation
    if (!confirmTransaction(txSignature, 15000)) { // wait 15 seconds
        _logErr.println("⚠️  Transaction not confirmed (timeout)");
        return {true, pdaAddress, txSignature, bump, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("✅ Escrow created successfully!");
    return {true, pdaAddress, txSignature, bump, ""};
}


// ============================================================================
// ESCROW CONFIRM DELIVERY
// ============================================================================

EscrowTxResult Infratic::escrow_confirmDelivery(
    const String &sellerPrivateKeyBase58,
    const String &sellerPubkeyBase58,
    const String &escrowPdaBase58,
    const String &proof_hash
) {
    _logInfo.println("\n=== 2. Confirm Delivery ===");
    
    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(sellerPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        return {false, "", "Invalid seller private key"};
    }
    
    Keypair sellerKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey seller = Pubkey::fromBase58(sellerPubkeyBase58);
    Pubkey escrowPda = Pubkey::fromBase58(escrowPdaBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    // 2. Check the escrow state first
    _logInfo.println("📋 Checking escrow state...");
    EscrowAccountResult accountCheck = getEscrowAccount(escrowPdaBase58, "confirmed");
    
    if (!accountCheck.success) {
        _logErr.println("❌ Could not read escrow account!");
        return {false, "", "Failed to read escrow account"};
    }
    
    if (accountCheck.account.status != EscrowStatus::Active) {
        _logErr.println("❌ Escrow is not active!");
        return {false, "", "Escrow is not active"};
    }
    
    if (accountCheck.account.seller != sellerPubkeyBase58) {
        _logErr.println("❌ Unauthorized! You are not the seller.");
        return {false, "", "Unauthorized: not the seller"};
    }

    // 3. Build instruction data
    if (proof_hash.length() > ESCROW_PROOF_HASH_MAX)
    {
        _logErr.println("❌ proof_hash can be at most 128 bytes");
        return {false, "", "proof_hash too long"};
    }

    std::vector<uint8_t> instructionData = calculateDiscriminator("confirm_delivery");
    appendBorshString(instructionData, proof_hash);

    _logInfo.printf("📦 Instruction size: %u bytes\n", (unsigned)instructionData.size());

    // 4. Build instruction (Rust order: escrow, seller)
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false), // escrow (writable, not signer)
            AccountMeta::signer(seller)              // seller (signer)
        },
        instructionData
    );

    // 5. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return {false, "", "Failed to get blockhash"};

    Transaction tx;
    tx.fee_payer = seller;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({sellerKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        return {false, "", "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Delivery confirmation sent: " + txSignature);
    
    if (!confirmTransaction(txSignature, 15000)) {
        return {true, txSignature, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("✅ Delivery confirmed successfully!");
    return {true, txSignature, ""};
}


// ============================================================================
// ESCROW RELEASE
// ============================================================================

EscrowTxResult Infratic::escrow_release(
    const String &buyerPrivateKeyBase58,
    const String &buyerPubkeyBase58,
    const String &sellerPubkeyBase58,
    const String &escrowPdaBase58
) {
    _logInfo.println("\n=== 3. Release Escrow ===");
    
    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(buyerPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        return {false, "", "Invalid buyer private key"};
    }
    
    Keypair buyerKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey buyer = Pubkey::fromBase58(buyerPubkeyBase58);
    Pubkey seller = Pubkey::fromBase58(sellerPubkeyBase58);
    Pubkey escrowPda = Pubkey::fromBase58(escrowPdaBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    // 2. Check the escrow state
    _logInfo.println("📋 Checking escrow state...");
    EscrowAccountResult accountCheck = getEscrowAccount(escrowPdaBase58, "confirmed");
    
    if (!accountCheck.success) {
        _logErr.println("❌ Could not read escrow account!");
        return {false, "", "Failed to read escrow account"};
    }
    
    if (accountCheck.account.status != EscrowStatus::Active) {
        _logErr.println("❌ Escrow is not active!");
        return {false, "", "Escrow is not active"};
    }
    
    if (accountCheck.account.buyer != buyerPubkeyBase58) {
        _logErr.println("❌ Unauthorized! You are not the buyer.");
        return {false, "", "Unauthorized: not the buyer"};
    }
    
    if (!accountCheck.account.deliveryConfirmed) {
        _logErr.println("⚠️  Warning: delivery is not confirmed yet!");
        // You can return here if you want
    }

    // 3. Build instruction data
    std::vector<uint8_t> instructionData = calculateDiscriminator("release_escrow");

    // 4. Build instruction (Rust order: escrow, buyer, seller)
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false), // escrow (writable, not signer)
            AccountMeta::signer(buyer),              // buyer (signer)
            AccountMeta::writable(seller, false)     // seller (writable, not signer)
        },
        instructionData
    );

    // 5. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return {false, "", "Failed to get blockhash"};

    Transaction tx;
    tx.fee_payer = buyer;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({buyerKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        return {false, "", "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Escrow released: " + txSignature);
    
    if (!confirmTransaction(txSignature, 15000)) {
        return {true, txSignature, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("✅ Payment transferred to the seller!");
    return {true, txSignature, ""};
}


// ============================================================================
// ESCROW CANCEL
// ============================================================================

EscrowTxResult Infratic::escrow_cancel(
    const String &buyerPrivateKeyBase58,
    const String &buyerPubkeyBase58,
    const String &escrowPdaBase58
) {
    _logInfo.println("\n=== 4. Cancel Escrow ===");

    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(buyerPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        return {false, "", "Invalid buyer private key"};
    }
    
    Keypair buyerKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey buyer = Pubkey::fromBase58(buyerPubkeyBase58);
    Pubkey escrowPda = Pubkey::fromBase58(escrowPdaBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    // 2. Check the escrow state
    _logInfo.println("📋 Checking escrow state...");
    EscrowAccountResult accountCheck = getEscrowAccount(escrowPdaBase58, "confirmed");
    
    if (!accountCheck.success) {
        _logErr.println("❌ Could not read escrow account!");
        return {false, "", "Failed to read escrow account"};
    }
    
    if (accountCheck.account.status != EscrowStatus::Active) {
        _logErr.println("❌ Escrow is not active!");
        return {false, "", "Escrow is not active"};
    }
    
    if (accountCheck.account.buyer != buyerPubkeyBase58) {
        _logErr.println("❌ Unauthorized! You are not the buyer.");
        return {false, "", "Unauthorized: not the buyer"};
    }
    
    // 3. Expiration check (uses cluster time; millis() is not unix time)
    int64_t currentTime = 0;
    if (getClusterTime(currentTime))
    {
        if (currentTime < accountCheck.account.expiresAt)
        {
            _logErr.println("❌ Escrow has not expired yet!");
            _logInfo.printf("   Time left: %lld seconds\n",
                            (long long)(accountCheck.account.expiresAt - currentTime));
            return {false, "", "Escrow has not expired yet"};
        }
    }
    else
    {
        _logErr.println("⚠️  Could not get cluster time, the program will check expiration");
    }

    // 4. Build instruction data
    std::vector<uint8_t> instructionData = calculateDiscriminator("cancel_escrow");

    // 5. Build instruction (Rust order: escrow, buyer)
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false), // escrow (writable, not signer)
            AccountMeta::writable(buyer, true)       // buyer (writable, signer)
        },
        instructionData
    );

    // 6. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return {false, "", "Failed to get blockhash"};

    Transaction tx;
    tx.fee_payer = buyer;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({buyerKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        return {false, "", "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Escrow cancelled: " + txSignature);
    
    if (!confirmTransaction(txSignature, 15000)) {
        return {true, txSignature, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("✅ Funds refunded to the buyer!");
    return {true, txSignature, ""};
}


// ============================================================================
// ESCROW INITIATE DISPUTE
// ============================================================================

EscrowTxResult Infratic::escrow_initiateDispute(
    const String &sellerPrivateKeyBase58,
    const String &sellerPubkeyBase58,
    const String &escrowPdaBase58,
    const String &reason,
    const String &evidence
) {
    _logInfo.println("\n=== 5. Initiate Dispute ===");

    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(sellerPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        return {false, "", "Invalid seller private key"};
    }
    
    Keypair sellerKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey seller = Pubkey::fromBase58(sellerPubkeyBase58);
    Pubkey escrowPda = Pubkey::fromBase58(escrowPdaBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    // 2. Check the escrow state
    _logInfo.println("📋 Checking escrow state...");
    EscrowAccountResult accountCheck = getEscrowAccount(escrowPdaBase58, "confirmed");
    
    if (!accountCheck.success) {
        _logErr.println("❌ Could not read escrow account!");
        return {false, "", "Failed to read escrow account"};
    }
    
    if (accountCheck.account.status != EscrowStatus::Active) {
        _logErr.println("❌ Escrow is not active!");
        return {false, "", "Escrow is not active"};
    }
    
    if (accountCheck.account.seller != sellerPubkeyBase58) {
        _logErr.println("❌ Unauthorized! You are not the seller.");
        return {false, "", "Unauthorized: not the seller"};
    }

    // 3. Build instruction data
    std::vector<uint8_t> instructionData = calculateDiscriminator("initiate_dispute");
    appendBorshString(instructionData, reason);
    appendBorshString(instructionData, evidence);

    _logInfo.printf("📦 Instruction size: %u bytes\n", (unsigned)instructionData.size());

    // 4. Build instruction (Rust order: escrow, seller)
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false), // escrow (writable, not signer)
            AccountMeta::signer(seller)              // seller (signer)
        },
        instructionData
    );

    // 5. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return {false, "", "Failed to get blockhash"};

    Transaction tx;
    tx.fee_payer = seller;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({sellerKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        return {false, "", "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Dispute initiated: " + txSignature);
    
    if (!confirmTransaction(txSignature, 15000)) {
        return {true, txSignature, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("✅ Dispute recorded!");
    return {true, txSignature, ""};
}


// ============================================================================
// ESCROW FORCE CLOSE
// ============================================================================

EscrowTxResult Infratic::escrow_forceClose(
    const String &authorityPrivateKeyBase58,
    const String &authorityPubkeyBase58,
    const String &buyerPubkeyBase58,
    const String &escrowPdaBase58
) {
    _logInfo.println("\n=== 6. Force Close Escrow ===");
    
    if (_escrowProgramId.isEmpty()) {
        _logErr.println("❌ Error: Escrow Program ID is not set.");
        return {false, "", "Program ID not set"};
    }

    // 1. Private key decode
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(authorityPrivateKeyBase58, privateKey, privLen) || privLen < 64) {
        return {false, "", "Invalid authority private key"};
    }
    
    Keypair authorityKeypair = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkeyBase58);
    Pubkey buyer = Pubkey::fromBase58(buyerPubkeyBase58);
    Pubkey escrowPda = Pubkey::fromBase58(escrowPdaBase58);
    Pubkey program = Pubkey::fromBase58(_escrowProgramId);

    // 2. Build instruction data
    std::vector<uint8_t> instructionData = calculateDiscriminator("force_close_escrow");

    // 3. Build instruction (Rust order: escrow, buyer, authority)
    Instruction ix(
        program,
        {
            AccountMeta::writable(escrowPda, false), // escrow (writable, not signer)
            AccountMeta::writable(buyer, false),     // buyer (writable, not signer)
            AccountMeta::signer(authority)           // authority (signer)
        },
        instructionData
    );

    // 4. Build and send the transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) return {false, "", "Failed to get blockhash"};

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({authorityKeypair});

    String txSignature;
    String txBase64 = tx.serializeBase64();
    
    _logInfo.println("📤 Sending transaction...");
    
    if (!sendRawTransaction(txBase64, txSignature)) {
        return {false, "", "sendRawTransaction failed"};
    }

    _logInfo.println("✅ Escrow force closed: " + txSignature);
    
    if (!confirmTransaction(txSignature, 15000)) {
        return {true, txSignature, "Transaction sent but not confirmed"};
    }
    
    _logInfo.println("🚨 Emergency! Escrow closed, funds refunded to the buyer.");
    return {true, txSignature, ""};
}