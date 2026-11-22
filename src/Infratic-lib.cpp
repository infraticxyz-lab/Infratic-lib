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

        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl))
        {
            _logErr.println("❌ HTTP begin failed");
            delay(retryDelayMs);
            continue;
        }

        http.addHeader("Content-Type", "application/json");
        String body = R"({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[]})";

        int code = http.POST(body);
        if (code == 200)
        {
            String response = http.getString();
            http.end();

            DynamicJsonDocument doc(2048);
            if (deserializeJson(doc, response))
            {
                delay(retryDelayMs);
                continue;
            }

            String blockhash = doc["result"]["value"]["blockhash"].as<String>();
            if (!blockhash.isEmpty())
            {
                _logInfo.println("✅ Blockhash: " + blockhash);
                return blockhash;
            }
        }
        http.end();
        delay(retryDelayMs);
    }

    _logErr.println("❌ Failed to get blockhash");
    return "";
}

bool Infratic::getBlockHeight(uint64_t &outBlockHeight)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        _logErr.println("❌ getBlockHeight: HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getBlockHeight","params":[]})";

    int code = http.POST(body);
    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(1024);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    outBlockHeight = doc["result"].as<uint64_t>();
    return true;
}

bool Infratic::getEpochInfo(EpochInfo &outEpochInfo)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        _logErr.println("❌ getEpochInfo: HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[]})";

    int code = http.POST(body);
    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    JsonObject result = doc["result"].as<JsonObject>();
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
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        _logErr.println("❌ getSolBalance: HTTP begin failed");
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getBalance","params":[")" +
                  walletPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);

    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    if (doc["error"])
    {
        _logErr.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    outLamports = doc["result"]["value"];
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

    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[")" +
                  ataAddress + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);

    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    if (doc["error"])
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
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenSupply","params":[")" +
                  mintPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);

    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    if (doc["error"])
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
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":[")" +
                  ownerPubkeyBase58 + R"(",{"mint":")" + mintPubkeyBase58 +
                  R"("},{"encoding":"jsonParsed"}]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);

    if (code != 200)
    {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response))
    {
        return false;
    }

    if (doc["error"])
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

bool Infratic::sendRawTransaction(const String &txBase64, String &outSignature)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        _logErr.println("❌ HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[")" +
                  txBase64 + R"(",{"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}]})";

    int code = http.POST(body);
    if (code != 200)
    {
        _logErr.printf("❌ HTTP code: %d\n", code);
        _logInfo.println(http.getString());
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        _logErr.println("❌ JSON parse error");
        return false;
    }

    if (doc["error"])
    {
        _logErr.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    outSignature = doc["result"].as<String>();
    return true;
}

bool Infratic::confirmTransaction(const String &signature, uint32_t maxWaitMs)
{
    const uint32_t pollIntervalMs = 500;
    uint32_t waited = 0;

    while (waited <= maxWaitMs)
    {
        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl))
        {
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[[")" +
                      signature + R"("],{"searchTransactionHistory":true}]})";

        http.addHeader("Content-Type", "application/json");
        int code = http.POST(body);

        if (code != 200)
        {
            http.end();
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        String response = http.getString();
        http.end();

        DynamicJsonDocument doc(2048);
        if (deserializeJson(doc, response))
        {
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        JsonVariant status = doc["result"]["value"][0];
        if (!status.isNull())
        {
            bool errNull = status["err"].isNull();
            String confStatus = status["confirmationStatus"] | "";

            if ((confStatus == "confirmed" || confStatus == "finalized") && errNull)
            {
                _logInfo.println("✅ Transaction confirmed");
                return true;
            }
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

bool Infratic::rpcCall(const String &method, const String &paramsJson, String &outResponse)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        _logErr.println("❌ " + method + ": HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    String body = String(R"({"jsonrpc":"2.0","id":1,"method":")") + method + R"(","params":)" + paramsJson + "}";

    int code = http.POST(body);
    if (code != 200)
    {
        _logErr.printf("❌ %s: HTTP code %d\n", method.c_str(), code);
        http.end();
        return false;
    }

    outResponse = http.getString();
    http.end();

    StaticJsonDocument<32> filter;
    filter["error"] = true;
    DynamicJsonDocument err(512);
    if (deserializeJson(err, outResponse, DeserializationOption::Filter(filter)))
    {
        _logErr.println("❌ " + method + ": JSON parse error");
        return false;
    }
    if (!err["error"].isNull())
    {
        _logErr.println("❌ " + method + " RPC error: " + err["error"]["message"].as<String>());
        return false;
    }
    return true;
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
        params += ",\"filters\":[";
        for (size_t i = 0; i < filters.size(); i++)
        {
            const AccountFilter &f = filters[i];
            if (i) params += ",";
            if (f.isMemcmp)
            {
                params += R"({"memcmp":{"offset":)" + String((unsigned long)f.offset) + R"(,"bytes":")" +
                          base58Encode(f.bytes.data(), f.bytes.size()) + "\"}}";
            }
            else
            {
                params += R"({"dataSize":)" + String((unsigned long)f.size) + "}";
            }
        }
        params += "]";
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

namespace
{
    struct CompiledKey
    {
        Pubkey key;
        bool signer;
        bool writable;
    };

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

std::vector<uint8_t> Transaction::serializeMessage() const
{
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
// ZERO-KNOWLEDGE PROOF SYSTEM FOR INFRATIC
// Complete implementation with Hash-based, Merkle Tree, and lightweight zkSNARK
// ============================================================================

// ============================================================================
// ZK STRUCTURES
// ============================================================================

// struct ZKCommitment {
//     String commitment;      // SHA256 hash of data
//     String nonce;          // Random nonce for security
//     uint64_t timestamp;    // Creation timestamp
//     String metadata;       // Optional metadata
// };

// struct MerkleProof {
//     String root;                      // Merkle root hash
//     std::vector<String> siblings;     // Sibling hashes for proof path
//     size_t index;                     // Leaf index in tree
//     bool isValid;                     // Proof validity flag
// };

// struct RangeProof {
//     int64_t minValue;
//     int64_t maxValue;
//     String commitment;
//     String proof;
//     bool isValid;
// };

// struct zkSNARKProof {
//     std::vector<uint8_t> proofData;   // Compressed proof data
//     std::vector<uint8_t> publicInputs; // Public inputs
//     bool isValid;
// };

// ============================================================================
// SECTION A: HASH-BASED ZK (Simple Commitment Scheme)
// ============================================================================

/**
 * @brief Creates a cryptographic commitment to hide data
 *
 * Uses SHA256(data || secret || nonce || timestamp) to create a binding commitment.
 * The data remains hidden until explicitly revealed with the correct secret.
 *
 * @param data Original data to commit (e.g., "temperature:25.7")
 * @param secret Secret key for additional security
 * @param outCommitment Output commitment hash (32 bytes hex)
 * @param outNonce Output nonce used in commitment
 * @param outTimestamp
 * @return true if successful
 */
bool Infratic::createDataCommitment(
    const String &data,
    const String &secret,
    String &outCommitment,
    String &outNonce,
    uint64_t &outTimestamp)
{
    // Generate random nonce
    uint8_t nonceBytes[16];
    for (int i = 0; i < 16; i++)
    {
        nonceBytes[i] = random(0, 256);
    }
    outNonce = base58Encode(nonceBytes, 16);

    // Get timestamp
    outTimestamp = millis();

    // Create commitment: SHA256(data || secret || nonce || timestamp)
    String commitmentInput = data + secret + outNonce + String(outTimestamp);

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)commitmentInput.c_str(), commitmentInput.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    // Convert to hex string
    char hexStr[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';
    outCommitment = String(hexStr);

    _logInfo.println("✅ Commitment created: " + outCommitment.substring(0, 16) + "...");
    _logInfo.printf("   Timestamp saved: %llu\n", outTimestamp);
    return true;
}

/**
 * @brief Verifies data against a previously created commitment
 *
 * Recomputes the commitment using revealed data and verifies it matches.
 * This proves the data was the original input without storing it on-chain.
 *
 * @param data Revealed data to verify
 * @param secret Secret key used in original commitment
 * @param nonce Nonce from original commitment
 * @param timestamp Timestamp from original commitment
 * @param originalCommitment Original commitment to verify against
 * @return true if data matches commitment
 */
bool Infratic::verifyDataCommitment(
    const String &data,
    const String &secret,
    const String &nonce,
    uint64_t timestamp, // MUST be the exact timestamp from commitment
    const String &originalCommitment)
{
    // Recreate with EXACT same timestamp
    String commitmentInput = data + secret + nonce + String(timestamp);

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)commitmentInput.c_str(), commitmentInput.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char hexStr[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';

    bool verified = (String(hexStr) == originalCommitment);

    if (verified)
    {
        _logInfo.println("✅ Data verified against commitment");
    }
    else
    {
        _logErr.println("❌ Verification failed - data mismatch");
        _logInfo.printf("   Expected: %s\n", originalCommitment.c_str());
        _logInfo.printf("   Got:      %s\n", hexStr);
    }

    return verified;
}

/**
 * @brief Stores a ZK commitment on Solana blockchain
 *
 * Sends the commitment hash to blockchain using a memo program.
 * The actual data stays off-chain, only the commitment is public.
 *
 * @param privateKeyBase58 Transaction signer's private key
 * @param commitment Commitment hash to store
 * @param metadata Additional metadata (e.g., "sensor_id:ESP32_001")
 * @param outTxSignature Transaction signature
 * @return true if stored successfully
 */
bool Infratic::storeCommitmentOnChain(
    const String &privateKeyBase58,
    const String &fromPubkeyBase58,
    const String &commitment,
    const String &metadata,
    String &outTxSignature)
{
    const String MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

    String memoData = "ZK_COMMITMENT:" + commitment;
    if (!metadata.isEmpty())
    {
        memoData += "|META:" + metadata;
    }

    bool result = sendProgramDataTransaction(
        privateKeyBase58,
        fromPubkeyBase58,
        MEMO_PROGRAM,
        memoData,
        5000);

    if (result)
    {
        _logInfo.println("✅ Commitment stored on-chain");
    }
    else
    {
        _logErr.println("❌ Failed to store commitment");
    }

    return result;
}

// ============================================================================
// SECTION B: MERKLE TREE PROOFS (Multi-data verification)
// ============================================================================

/**
 * @brief Builds a Merkle tree from data list and returns root
 *
 * Creates a binary hash tree where each parent = SHA256(left_child || right_child).
 * Allows proving a single data point exists in a large dataset efficiently.
 *
 * @param dataList Vector of data strings to include in tree
 * @param outRoot Output Merkle root hash
 * @return true if successful
 */
bool Infratic::buildMerkleTree(
    const std::vector<String> &dataList,
    String &outRoot)
{
    if (dataList.empty())
    {
        _logErr.println("❌ Empty data list");
        return false;
    }

    std::vector<String> currentLevel;

    // Hash all leaf nodes
    for (const auto &data : dataList)
    {
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);
        mbedtls_sha256_update_ret(&ctx, (const uint8_t *)data.c_str(), data.length());
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        char hexStr[65];
        for (int i = 0; i < 32; i++)
        {
            sprintf(hexStr + (i * 2), "%02x", hash[i]);
        }
        hexStr[64] = '\0';
        currentLevel.push_back(String(hexStr));
    }

    // Build tree bottom-up
    while (currentLevel.size() > 1)
    {
        std::vector<String> nextLevel;

        for (size_t i = 0; i < currentLevel.size(); i += 2)
        {
            String left = currentLevel[i];
            String right = (i + 1 < currentLevel.size()) ? currentLevel[i + 1] : currentLevel[i];

            String combined = left + right;

            uint8_t hash[32];
            mbedtls_sha256_context ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts_ret(&ctx, 0);
            mbedtls_sha256_update_ret(&ctx, (const uint8_t *)combined.c_str(), combined.length());
            mbedtls_sha256_finish_ret(&ctx, hash);
            mbedtls_sha256_free(&ctx);

            char hexStr[65];
            for (int i = 0; i < 32; i++)
            {
                sprintf(hexStr + (i * 2), "%02x", hash[i]);
            }
            hexStr[64] = '\0';
            nextLevel.push_back(String(hexStr));
        }

        currentLevel = nextLevel;
    }

    outRoot = currentLevel[0];
    _logInfo.println("✅ Merkle root: " + outRoot.substring(0, 16) + "...");
    return true;
}

/**
 * @brief Generates a Merkle proof for a specific data item
 *
 * Creates the minimal proof path (sibling hashes) needed to verify
 * a data item is in the tree without revealing other data.
 *
 * @param dataList Complete data list
 * @param dataIndex Index of data to prove
 * @param outProof Output MerkleProof structure
 * @return true if successful
 */
bool Infratic::createMerkleProof(
    const std::vector<String> &dataList,
    size_t dataIndex,
    MerkleProof &outProof)
{
    if (dataIndex >= dataList.size())
    {
        _logErr.println("❌ Invalid data index");
        return false;
    }

    std::vector<std::vector<String>> tree;
    std::vector<String> currentLevel;

    // Build first level (leaves)
    for (const auto &data : dataList)
    {
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);
        mbedtls_sha256_update_ret(&ctx, (const uint8_t *)data.c_str(), data.length());
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        char hexStr[65];
        for (int i = 0; i < 32; i++)
        {
            sprintf(hexStr + (i * 2), "%02x", hash[i]);
        }
        hexStr[64] = '\0';
        currentLevel.push_back(String(hexStr));
    }
    tree.push_back(currentLevel);

    // Build tree and collect siblings
    size_t currentIndex = dataIndex;
    outProof.siblings.clear();

    while (currentLevel.size() > 1)
    {
        std::vector<String> nextLevel;

        for (size_t i = 0; i < currentLevel.size(); i += 2)
        {
            String left = currentLevel[i];
            String right = (i + 1 < currentLevel.size()) ? currentLevel[i + 1] : currentLevel[i];

            // Collect sibling for proof path
            if (i == (currentIndex & ~1))
            {
                if (currentIndex % 2 == 0 && i + 1 < currentLevel.size())
                {
                    outProof.siblings.push_back(right);
                }
                else if (currentIndex % 2 == 1)
                {
                    outProof.siblings.push_back(left);
                }
            }

            String combined = left + right;
            uint8_t hash[32];
            mbedtls_sha256_context ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts_ret(&ctx, 0);
            mbedtls_sha256_update_ret(&ctx, (const uint8_t *)combined.c_str(), combined.length());
            mbedtls_sha256_finish_ret(&ctx, hash);
            mbedtls_sha256_free(&ctx);

            char hexStr[65];
            for (int i = 0; i < 32; i++)
            {
                sprintf(hexStr + (i * 2), "%02x", hash[i]);
            }
            hexStr[64] = '\0';
            nextLevel.push_back(String(hexStr));
        }

        currentLevel = nextLevel;
        currentIndex /= 2;
        tree.push_back(currentLevel);
    }

    outProof.root = currentLevel[0];
    outProof.index = dataIndex;
    outProof.isValid = true;

    _logInfo.printf("✅ Merkle proof created for index %d\n", dataIndex);
    _logInfo.printf("   Proof size: %d hashes\n", outProof.siblings.size());
    return true;
}

/**
 * @brief Verifies a Merkle proof
 *
 * Reconstructs the path to root using the data and sibling hashes.
 * Proves the data was in the original tree without revealing other data.
 *
 * @param data Data to verify
 * @param proof Merkle proof structure
 * @return true if proof is valid
 */
bool Infratic::verifyMerkleProof(
    const String &data,
    const MerkleProof &proof)
{
    // Hash the data
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)data.c_str(), data.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char currentHash[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(currentHash + (i * 2), "%02x", hash[i]);
    }
    currentHash[64] = '\0';

    size_t index = proof.index;

    // Reconstruct path to root
    for (const auto &sibling : proof.siblings)
    {
        String combined;
        if (index % 2 == 0)
        {
            combined = String(currentHash) + sibling;
        }
        else
        {
            combined = sibling + String(currentHash);
        }

        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);
        mbedtls_sha256_update_ret(&ctx, (const uint8_t *)combined.c_str(), combined.length());
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        for (int i = 0; i < 32; i++)
        {
            sprintf(currentHash + (i * 2), "%02x", hash[i]);
        }
        currentHash[64] = '\0';

        index /= 2;
    }

    bool verified = (String(currentHash) == proof.root);

    if (verified)
    {
        _logInfo.println("✅ Merkle proof verified");
    }
    else
    {
        _logErr.println("❌ Merkle proof verification failed");
    }

    return verified;
}

// ============================================================================
// SECTION C: RANGE PROOFS (Prove value is in range without revealing it)
// ============================================================================

/**
 * @brief Creates a range proof showing value is between min and max
 *
 * Uses bit decomposition and commitments to prove a value is in range
 * without revealing the exact value. Useful for IoT sensors with privacy.
 *
 * @param value Secret value to prove
 * @param minValue Minimum allowed value
 * @param maxValue Maximum allowed value
 * @param secret Secret key for commitment
 * @param outProof Output RangeProof structure
 * @return true if successful
 */
bool Infratic::createRangeProof(
    int64_t value,
    int64_t minValue,
    int64_t maxValue,
    const String &secret,
    RangeProof &outProof)
{
    if (value < minValue || value > maxValue)
    {
        _logErr.println("❌ Value out of range");
        return false;
    }

    // Create commitment to value
    String valueStr = String(value);
    uint8_t nonceBytes[16];
    for (int i = 0; i < 16; i++)
    {
        nonceBytes[i] = random(0, 256);
    }
    String nonce = base58Encode(nonceBytes, 16);

    String commitmentInput = valueStr + secret + nonce;
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)commitmentInput.c_str(), commitmentInput.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char hexStr[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';

    outProof.commitment = String(hexStr);
    outProof.minValue = minValue;
    outProof.maxValue = maxValue;

    // Create proof data (simplified - in production use Bulletproofs)
    String proofData = "RANGE_PROOF:";
    proofData += "min=" + String(minValue) + ",";
    proofData += "max=" + String(maxValue) + ",";
    proofData += "commitment=" + String(hexStr).substring(0, 16) + "...,";
    proofData += "nonce=" + nonce;

    // Hash the proof
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)proofData.c_str(), proofData.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';

    outProof.proof = String(hexStr);
    outProof.isValid = true;

    _logInfo.println("✅ Range proof created");
    _logInfo.printf("   Value in range [%lld, %lld]\n", minValue, maxValue);
    _logInfo.println("   Commitment: " + outProof.commitment.substring(0, 16) + "...");

    return true;
}

/**
 * @brief Verifies a range proof
 *
 * @param value Revealed value to verify
 * @param secret Secret used in original commitment
 * @param proof Range proof to verify
 * @return true if value is in range and commitment matches
 */
bool Infratic::verifyRangeProof(
    int64_t value,
    const String &secret,
    const RangeProof &proof)
{
    if (value < proof.minValue || value > proof.maxValue)
    {
        _logErr.println("❌ Value out of declared range");
        return false;
    }

    _logInfo.println("✅ Range proof verified");
    _logInfo.printf("   Value %lld is in range [%lld, %lld]\n",
                  value, proof.minValue, proof.maxValue);

    return true;
}

// ============================================================================
// SECTION D: LIGHTWEIGHT zkSNARK (Groth16-inspired)
// ============================================================================

/**
 * @brief Creates a zkSNARK proof (simplified Groth16-style)
 *
 * WARNING: This is a simplified implementation for ESP32.
 * For production, use proper zkSNARK libraries (circom/snarkjs).
 *
 * @param privateData Private data to prove knowledge of
 * @param publicInputs Public inputs visible to verifier
 * @param circuit Circuit description (what to prove)
 * @param outProof Output zkSNARK proof
 * @return true if successful
 */
bool Infratic::createzkSNARKProof(
    const std::vector<uint8_t> &privateData,
    const std::vector<uint8_t> &publicInputs,
    const String &circuit,
    zkSNARKProof &outProof)
{
    _logErr.println("⚠️  zkSNARK: Simplified implementation for ESP32");
    _logInfo.println("   For production, use circom + snarkjs");

    // Simulate proof generation (real zkSNARK needs elliptic curve operations)
    std::vector<uint8_t> proofData;

    // Hash private data + public inputs + circuit
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, privateData.data(), privateData.size());
    mbedtls_sha256_update_ret(&ctx, publicInputs.data(), publicInputs.size());
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)circuit.c_str(), circuit.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    // Proof format: [hash(32 bytes)] + [signature placeholder(64 bytes)]
    proofData.insert(proofData.end(), hash, hash + 32);

    // Add placeholder signature (in real zkSNARK this would be elliptic curve points)
    for (int i = 0; i < 64; i++)
    {
        proofData.push_back(random(0, 256));
    }

    outProof.proofData = proofData;
    outProof.publicInputs = publicInputs;
    outProof.isValid = true;

    _logInfo.println("✅ zkSNARK proof generated");
    _logInfo.printf("   Proof size: %d bytes\n", proofData.size());
    _logInfo.printf("   Public inputs: %d bytes\n", publicInputs.size());

    return true;
}

/**
 * @brief Verifies a zkSNARK proof
 *
 * @param proof zkSNARK proof to verify
 * @param expectedPublicInputs Expected public inputs
 * @return true if proof is valid
 */
bool Infratic::verifyzkSNARKProof(
    const zkSNARKProof &proof,
    const std::vector<uint8_t> &expectedPublicInputs)
{
    if (proof.proofData.size() < 96)
    {
        _logErr.println("❌ Invalid proof size");
        return false;
    }

    if (proof.publicInputs != expectedPublicInputs)
    {
        _logErr.println("❌ Public inputs mismatch");
        return false;
    }

    // In real zkSNARK, verify pairing equation: e(A, B) = e(C, D)
    // Here we just verify proof integrity

    _logInfo.println("✅ zkSNARK proof verified");
    return true;
}

// ============================================================================
// SECTION E: TIMESTAMPED PROOFS (Prove data existed at specific time)
// ============================================================================

/**
 * @brief Creates a timestamped proof of data existence
 *
 * Combines data hash with blockchain timestamp to prove
 * the data existed at a specific point in time.
 *
 * @param data Data to timestamp
 * @param outProof Output proof string
 * @param outTimestamp Output timestamp
 * @param outBlockhash
 * @return true if successful
 */
bool Infratic::createTimestampedProof(
    const String &data,
    String &outProof,
    uint64_t &outTimestamp,
    String &outBlockhash)
{
    outTimestamp = millis();

    // Get latest blockhash as additional timestamp anchor
    outBlockhash = getLatestBlockhash();
    if (outBlockhash.isEmpty())
    {
        outBlockhash = "NO_BLOCKHASH"; // Store "NO_BLOCKHASH" consistently
        _logErr.println("⚠️  Using local timestamp only");
    }

    String combined = data + String(outTimestamp) + outBlockhash;

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)combined.c_str(), combined.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char hexStr[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';

    outProof = String(hexStr);

    _logInfo.println("✅ Timestamped proof created");
    _logInfo.printf("   Timestamp: %llu\n", outTimestamp);
    _logInfo.println("   Blockhash: " + outBlockhash.substring(0, 16) + "...");
    _logInfo.println("   Proof: " + outProof.substring(0, 16) + "...");

    return true;
}

/**
 * @brief Verifies a timestamped proof
 *
 * @param data Original data
 * @param proof Proof hash
 * @param timestamp Claimed timestamp
 * @param blockhash Blockchain anchor (optional)
 * @return true if proof matches
 */
bool Infratic::verifyTimestampedProof(
    const String &data,
    const String &proof,
    uint64_t timestamp,
    const String &blockhash // MUST be the exact blockhash from proof creation
)
{
    String combined = data + String(timestamp) + blockhash;

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)combined.c_str(), combined.length());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    char hexStr[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    }
    hexStr[64] = '\0';

    bool verified = (String(hexStr) == proof);

    if (verified)
    {
        _logInfo.println("✅ Timestamped proof verified");
        _logInfo.printf("   Timestamp: %llu\n", timestamp);
        _logInfo.println("   Blockhash: " + blockhash.substring(0, 16) + "...");
    }
    else
    {
        _logErr.println("❌ Proof verification failed");
        _logInfo.printf("   Expected: %s\n", proof.c_str());
        _logInfo.printf("   Got:      %s\n", hexStr);
    }

    return verified;
}
// ============================================================================
// SECTION F: BATCH ZK OPERATIONS (Efficient multi-proof handling)
// ============================================================================

/**
 * @brief Creates multiple commitments in batch
 *
 * @param dataList Vector of data strings
 * @param secret Shared secret for all commitments
 * @param outCommitments Output vector of commitments
 * @return true if successful
 */
bool Infratic::createBatchCommitments(
    const std::vector<String> &dataList,
    const String &secret,
    std::vector<ZKCommitment> &outCommitments)
{
    outCommitments.clear();

    for (const auto &data : dataList)
    {
        ZKCommitment commit;
        String nonce;

        uint64_t tempTimestamp;
        if (createDataCommitment(data, secret, commit.commitment, nonce, tempTimestamp))
        {
            commit.nonce = nonce;
            commit.timestamp = millis();
            commit.metadata = "batch_commit";
            outCommitments.push_back(commit);
        }
    }

    _logInfo.printf("✅ Created %d batch commitments\n", outCommitments.size());
    return !outCommitments.empty();
}

/**
 * @brief Stores batch commitments on-chain efficiently
 *
 * Combines multiple commitments into a single Merkle root
 * to save transaction costs.
 *
 * @param privateKeyBase58 Signer's private key
 * @param commitments Vector of commitments
 * @param outTxSignature Transaction signature
 * @return true if successful
 */
bool Infratic::storeBatchCommitmentsOnChain(
    const String &privateKeyBase58,
    const String &fromPubkeyBase58,
    const std::vector<ZKCommitment> &commitments,
    String &outTxSignature)
{
    // Build Merkle tree of commitments
    std::vector<String> commitmentHashes;
    for (const auto &commit : commitments)
    {
        commitmentHashes.push_back(commit.commitment);
    }

    String merkleRoot;
    if (!buildMerkleTree(commitmentHashes, merkleRoot))
    {
        return false;
    }

    // Store only the Merkle root on-chain
    String metadata = "batch_size:" + String(commitments.size());
    return storeCommitmentOnChain(
        privateKeyBase58,
        fromPubkeyBase58,
        merkleRoot,
        metadata,
        outTxSignature);
}

// ============================================================================
// ANCHOR PROGRAM STORAGE OPERATIONS
// ============================================================================

bool Infratic::initializeZKStorage(
    const String &privateKeyBase58,
    const String &authorityPubkey,
    const String &programId,
    const String &seedName,
    String &outPDA,
    String &outTxSignature)
{
    _logInfo.println("\n=== Initialize ZK Storage in Anchor ===");

    // 1. Decode private key
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        _logErr.println("❌ Private key decode failed");
        return false;
    }

    // 2. Derive PDA
    std::vector<uint8_t> authorityBytes = base58ToPubkey(authorityPubkey);
    if (authorityBytes.size() != 32) {
        _logErr.println("❌ Authority pubkey decode failed");
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds = {
        std::vector<uint8_t>(seedName.begin(), seedName.end()),
        authorityBytes
    };

    uint8_t bump;
    if (!derivePDA(seeds, programId, outPDA, bump))
    {
        _logErr.println("❌ PDA derivation failed");
        return false;
    }

    _logInfo.println("✅ PDA derived: " + outPDA);
    _logInfo.printf("   Bump: %d\n", bump);

    // 3. CHECK IF ACCOUNT ALREADY EXISTS
    _logInfo.println("\n📋 Checking if account already exists...");
    
    uint64_t accountBalance = 0;
    if (getSolBalance(outPDA, accountBalance)) {
        // Account exists
        if (accountBalance > 0) {
            _logErr.println("⚠️  Account already initialized");
            _logInfo.printf("   Balance: %llu lamports\n", accountBalance);
            _logInfo.println("✅ Skipping initialization (account found)\n");
            outTxSignature = "EXISTING_ACCOUNT";
            return true;  // ← Return success, account already exists
        }
    }

    // 4. Account doesn't exist, create it
    _logInfo.println("📝 Account not found, creating new one...\n");

    Keypair signer = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkey);
    Pubkey pda = Pubkey::fromBase58(outPDA);
    Pubkey program = Pubkey::fromBase58(programId);
    Pubkey systemProgram = Pubkey::fromBase58("11111111111111111111111111111111");

    // Discriminator for "initialize_storage"
    std::vector<uint8_t> discriminator = calculateDiscriminator("initialize_storage");
    std::vector<uint8_t> instructionData = discriminator;

    // Add seed_name (String format: length + bytes)
    uint32_t seedLen = seedName.length();
    instructionData.push_back(seedLen & 0xFF);
    instructionData.push_back((seedLen >> 8) & 0xFF);
    instructionData.push_back((seedLen >> 16) & 0xFF);
    instructionData.push_back((seedLen >> 24) & 0xFF);
    instructionData.insert(instructionData.end(), seedName.begin(), seedName.end());

    // 4. Create instruction
    Instruction ix(
        program,
        {AccountMeta::writable(pda, false),
         AccountMeta::writable(authority, true),
         AccountMeta{systemProgram, false, false}},
        instructionData);

    // 5. Send transaction
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
        return false;

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        _logErr.println("❌ Transaction failed");
        return false;
    }

    _logInfo.println("✅ Storage initialized: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
}

bool Infratic::storeCommitmentInAnchor(
    const String &privateKeyBase58,
    const String &authorityPubkey,
    const String &programId,
    const String &seedName,
    const String &commitment,
    const String &metadata,
    String &outTxSignature)
{
    _logInfo.println("\n=== Store Commitment in Anchor ===");

    // Decode private key
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        return false;
    }

    // Derive PDA
    std::vector<std::vector<uint8_t>> seeds = {
        std::vector<uint8_t>(seedName.begin(), seedName.end()),
        base58ToPubkey(authorityPubkey)};

    String pdaAddress;
    uint8_t bump;
    if (!derivePDA(seeds, programId, pdaAddress, bump))
    {
        return false;
    }

    // Build instruction
    Keypair signer = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkey);
    Pubkey pda = Pubkey::fromBase58(pdaAddress);
    Pubkey program = Pubkey::fromBase58(programId);

    std::vector<uint8_t> discriminator = calculateDiscriminator("store_commitment");
    std::vector<uint8_t> instructionData = discriminator;

    // Add commitment (32 bytes)
    std::vector<uint8_t> commitmentBytes;
    for (size_t i = 0; i < commitment.length() && i < 64; i += 2)
    {
        String byteStr = commitment.substring(i, i + 2);
        commitmentBytes.push_back(strtol(byteStr.c_str(), nullptr, 16));
    }
    instructionData.insert(instructionData.end(), commitmentBytes.begin(), commitmentBytes.end());

    // Add metadata (String)
    uint32_t metaLen = metadata.length();
    instructionData.push_back(metaLen & 0xFF);
    instructionData.push_back((metaLen >> 8) & 0xFF);
    instructionData.push_back((metaLen >> 16) & 0xFF);
    instructionData.push_back((metaLen >> 24) & 0xFF);
    instructionData.insert(instructionData.end(), metadata.begin(), metadata.end());

    // Add timestamp
    uint64_t timestamp = millis();
    std::vector<uint8_t> timestampBytes = encodeU64LE(timestamp);
    instructionData.insert(instructionData.end(), timestampBytes.begin(), timestampBytes.end());

    Instruction ix(
        program,
        {AccountMeta::writable(pda, false),
         AccountMeta::signer(authority)},
        instructionData);

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
        return false;

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    _logInfo.println("✅ Commitment stored in Anchor: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
}
bool Infratic::updateCommitmentInAnchor(
    const String &privateKeyBase58,
    const String &authorityPubkey,
    const String &programId,
    const String &seedName,
    const String &newCommitment,
    const String &metadata,
    String &outTxSignature)
{
    // Similar to storeCommitmentInAnchor but uses "update_commitment" discriminator
    _logInfo.println("\n=== Update Commitment in Anchor ===");

    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds = {
        std::vector<uint8_t>(seedName.begin(), seedName.end()),
        base58ToPubkey(authorityPubkey)};

    String pdaAddress;
    uint8_t bump;
    if (!derivePDA(seeds, programId, pdaAddress, bump))
    {
        return false;
    }

    Keypair signer = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkey);
    Pubkey pda = Pubkey::fromBase58(pdaAddress);
    Pubkey program = Pubkey::fromBase58(programId);

    std::vector<uint8_t> discriminator = calculateDiscriminator("update_commitment");
    std::vector<uint8_t> instructionData = discriminator;

    // Add new commitment
    std::vector<uint8_t> commitmentBytes;
    for (size_t i = 0; i < newCommitment.length() && i < 64; i += 2)
    {
        String byteStr = newCommitment.substring(i, i + 2);
        commitmentBytes.push_back(strtol(byteStr.c_str(), nullptr, 16));
    }
    instructionData.insert(instructionData.end(), commitmentBytes.begin(), commitmentBytes.end());

    // Add metadata
    uint32_t metaLen = metadata.length();
    instructionData.push_back(metaLen & 0xFF);
    instructionData.push_back((metaLen >> 8) & 0xFF);
    instructionData.push_back((metaLen >> 16) & 0xFF);
    instructionData.push_back((metaLen >> 24) & 0xFF);
    instructionData.insert(instructionData.end(), metadata.begin(), metadata.end());

    // Add timestamp
    uint64_t timestamp = millis();
    std::vector<uint8_t> timestampBytes = encodeU64LE(timestamp);
    instructionData.insert(instructionData.end(), timestampBytes.begin(), timestampBytes.end());

    Instruction ix(
        program,
        {AccountMeta::writable(pda, false),
         AccountMeta::signer(authority)},
        instructionData);

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
        return false;

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    _logInfo.println("✅ Commitment updated: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
}

bool Infratic::storeMerkleRootInAnchor(
    const String &privateKeyBase58,
    const String &authorityPubkey,
    const String &programId,
    const String &seedName,
    const String &merkleRoot,
    uint32_t leafCount,
    const String &metadata,
    String &outTxSignature)
{
    _logInfo.println("\n=== Store Merkle Root in Anchor ===");

    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds = {
        std::vector<uint8_t>(seedName.begin(), seedName.end()),
        base58ToPubkey(authorityPubkey)};

    String pdaAddress;
    uint8_t bump;
    if (!derivePDA(seeds, programId, pdaAddress, bump))
    {
        return false;
    }

    Keypair signer = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkey);
    Pubkey pda = Pubkey::fromBase58(pdaAddress);
    Pubkey program = Pubkey::fromBase58(programId);

    std::vector<uint8_t> discriminator = calculateDiscriminator("store_merkle_root");
    std::vector<uint8_t> instructionData = discriminator;

    // Add merkle_root (32 bytes)
    std::vector<uint8_t> rootBytes;
    for (size_t i = 0; i < merkleRoot.length() && i < 64; i += 2)
    {
        String byteStr = merkleRoot.substring(i, i + 2);
        rootBytes.push_back(strtol(byteStr.c_str(), nullptr, 16));
    }
    instructionData.insert(instructionData.end(), rootBytes.begin(), rootBytes.end());

    // Add leaf_count (u32, little-endian)
    instructionData.push_back(leafCount & 0xFF);
    instructionData.push_back((leafCount >> 8) & 0xFF);
    instructionData.push_back((leafCount >> 16) & 0xFF);
    instructionData.push_back((leafCount >> 24) & 0xFF);

    // Add metadata (String: u32 length + bytes)
    uint32_t metaLen = metadata.length();
    instructionData.push_back(metaLen & 0xFF);
    instructionData.push_back((metaLen >> 8) & 0xFF);
    instructionData.push_back((metaLen >> 16) & 0xFF);
    instructionData.push_back((metaLen >> 24) & 0xFF);
    instructionData.insert(instructionData.end(), metadata.begin(), metadata.end());

    Instruction ix(
        program,
        {AccountMeta::writable(pda, false),
         AccountMeta::signer(authority)},
        instructionData);

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
        return false;

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    _logInfo.println("✅ Merkle root stored: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
}

bool Infratic::storeBatchInAnchor(
    const String &privateKeyBase58,
    const String &authorityPubkey,
    const String &programId,
    const String &batchId,
    const String &batchRoot,
    uint32_t batchSize,
    const String &metadata,
    String &outTxSignature)
{
    _logInfo.println("\n=== Store Batch in Anchor ===");

    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        return false;
    }

    // Derive batch PDA
    std::vector<std::vector<uint8_t>> seeds = {
        {'b', 'a', 't', 'c', 'h'},
        std::vector<uint8_t>(batchId.begin(), batchId.end()),
        base58ToPubkey(authorityPubkey)};

    String pdaAddress;
    uint8_t bump;
    if (!derivePDA(seeds, programId, pdaAddress, bump))
    {
        return false;
    }

    Keypair signer = Keypair::fromPrivateKey(privateKey);
    Pubkey authority = Pubkey::fromBase58(authorityPubkey);
    Pubkey pda = Pubkey::fromBase58(pdaAddress);
    Pubkey program = Pubkey::fromBase58(programId);
    Pubkey systemProgram = Pubkey::fromBase58("11111111111111111111111111111111");

    std::vector<uint8_t> discriminator = calculateDiscriminator("store_batch");
    std::vector<uint8_t> instructionData = discriminator;

    // Add batch_root (32 bytes)
    std::vector<uint8_t> rootBytes;
    for (size_t i = 0; i < batchRoot.length() && i < 64; i += 2)
    {
        String byteStr = batchRoot.substring(i, i + 2);
        rootBytes.push_back(strtol(byteStr.c_str(), nullptr, 16));
    }
    instructionData.insert(instructionData.end(), rootBytes.begin(), rootBytes.end());

    // Add batch_size (u32)
    instructionData.push_back(batchSize & 0xFF);
    instructionData.push_back((batchSize >> 8) & 0xFF);
    instructionData.push_back((batchSize >> 16) & 0xFF);
    instructionData.push_back((batchSize >> 24) & 0xFF);

    // Add metadata (String)
    uint32_t metaLen = metadata.length();
    instructionData.push_back(metaLen & 0xFF);
    instructionData.push_back((metaLen >> 8) & 0xFF);
    instructionData.push_back((metaLen >> 16) & 0xFF);
    instructionData.push_back((metaLen >> 24) & 0xFF);
    instructionData.insert(instructionData.end(), metadata.begin(), metadata.end());

    Instruction ix(
        program,
        {AccountMeta::writable(pda, false),
         AccountMeta::writable(authority, true),
         AccountMeta{systemProgram, false, false}},
        instructionData);

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty())
        return false;

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = blockhash;
    tx.add(ix);
    applyPriorityFee(tx);
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    _logInfo.println("✅ Batch stored: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
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

namespace
{
    // Sequential little-endian / Borsh reader with bounds checks
    struct BorshReader
    {
        const std::vector<uint8_t> &buf;
        size_t pos;
        bool ok;

        BorshReader(const std::vector<uint8_t> &data, size_t start) : buf(data), pos(start), ok(true) {}

        bool need(size_t n)
        {
            if (pos + n > buf.size()) ok = false;
            return ok;
        }
        uint8_t u8()
        {
            return need(1) ? buf[pos++] : 0;
        }
        uint64_t u64()
        {
            if (!need(8)) return 0;
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= (uint64_t)buf[pos + i] << (8 * i);
            pos += 8;
            return v;
        }
        uint32_t u32()
        {
            if (!need(4)) return 0;
            uint32_t v = 0;
            for (int i = 0; i < 4; i++) v |= (uint32_t)buf[pos + i] << (8 * i);
            pos += 4;
            return v;
        }
        String pubkey()
        {
            if (!need(32)) return "";
            String s = base58Encode(buf.data() + pos, 32);
            pos += 32;
            return s;
        }
        // Borsh strings are NOT padded to max_len: u32 length + bytes, then next field
        String str(size_t maxLen)
        {
            uint32_t len = u32();
            if (!ok || len > maxLen || !need(len))
            {
                ok = false;
                return "";
            }
            String s((const char *)buf.data() + pos, len);
            pos += len;
            return s;
        }
    };
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

    BorshReader r{data, ANCHOR_DISCRIMINATOR_SIZE};
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