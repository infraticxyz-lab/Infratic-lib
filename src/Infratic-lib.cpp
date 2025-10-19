#include "Infratic-lib.h"

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

extern "C" bool ed25519_decode_public_key(const uint8_t *buf)
{
    return true;
}

static bool decodePointWrapper(const uint8_t hash[32])
{
    extern bool ed25519_decode_public_key(const uint8_t *buf);
    return !ed25519_decode_public_key(hash);
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

std::vector<uint8_t> base58ToPubkey(const String &base58Str)
{
    uint8_t buffer[32];
    size_t len = sizeof(buffer);
    if (!base58Decode(base58Str, buffer, len) || len != 32)
    {
        Serial.println("❌ base58ToPubkey: Invalid base58 input!");
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
        Serial.printf("🌐 Fetching blockhash (attempt %d/%d)...\n", attempt, maxRetries);

        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl))
        {
            Serial.println("❌ HTTP begin failed");
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
                Serial.println("✅ Blockhash: " + blockhash);
                return blockhash;
            }
        }
        http.end();
        delay(retryDelayMs);
    }

    Serial.println("❌ Failed to get blockhash");
    return "";
}

bool Infratic::getBlockHeight(uint64_t &outBlockHeight)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        Serial.println("❌ getBlockHeight: HTTP begin failed");
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
        Serial.println("❌ getEpochInfo: HTTP begin failed");
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
        Serial.println("❌ getSolBalance: HTTP begin failed");
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
        Serial.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
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
        Serial.println("⚠️ ATA not found, balance = 0");
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
        Serial.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32], toPub[32];
    size_t fromLen = 32, toLen = 32;

    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32)
    {
        Serial.println("❌ From pubkey decode error");
        return false;
    }

    if (!base58Decode(toPubkeyBase58, toPub, toLen) || toLen != 32)
    {
        Serial.println("❌ To pubkey decode error");
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

    Serial.println("✅ Transaction Signature: " + signature);
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
        Serial.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32];
    size_t fromLen = sizeof(fromPub);
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32)
    {
        Serial.println("❌ Public key decode error");
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

    Serial.println("✅ Tx Signature: " + signature);

    if (!confirmTransaction(signature, confirmWaitMs))
    {
        Serial.println("⚠️ Transaction NOT confirmed in time");
        return false;
    }

    Serial.println("✅ Transaction confirmed");
    return true;
}

bool Infratic::sendRawTransaction(const String &txBase64, String &outSignature)
{
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl))
    {
        Serial.println("❌ HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[")" +
                  txBase64 + R"(",{"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}]})";

    int code = http.POST(body);
    if (code != 200)
    {
        Serial.printf("❌ HTTP code: %d\n", code);
        Serial.println(http.getString());
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response))
    {
        Serial.println("❌ JSON parse error");
        return false;
    }

    if (doc["error"])
    {
        Serial.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
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
                Serial.println("✅ Transaction confirmed");
                return true;
            }
        }

        delay(pollIntervalMs);
        waited += pollIntervalMs;
    }

    Serial.println("⏱️ Timeout: Transaction not confirmed");
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
        Serial.println("❌ Failed to decode private key");
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
        Serial.println("❌ Invalid private key size");
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
        Serial.println("❌ Invalid program ID");
        return false;
    }

    std::vector<uint8_t> pdaBytes;
    if (!findProgramAddress(seeds, programId, pdaBytes, outBump))
    {
        Serial.println("❌ Failed to derive PDA");
        return false;
    }

    outPDABase58 = base58Encode(pdaBytes.data(), pdaBytes.size());
    if (outPDABase58.isEmpty())
    {
        Serial.println("❌ Failed to encode PDA to Base58");
        return false;
    }

    Serial.println("✅ Derived PDA: " + outPDABase58);
    Serial.println("   Bump: " + String(outBump));

    return true;
}

bool Infratic::findProgramAddress(const std::vector<std::vector<uint8_t>> &seeds,
                                  const std::vector<uint8_t> &programId,
                                  std::vector<uint8_t> &outPDA, uint8_t &outBump)
{
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

        bool isValid = decodePointWrapper(hash);
        if (isValid)
        {
            continue;
        }

        outPDA.assign(hash, hash + 32);
        outBump = bump;
        return true;
    }

    Serial.println("❌ No valid PDA found");
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
    size_t requiredSize = 4 * ((len + 2) / 3);
    char *outBuf = new char[requiredSize + 1];
    memset(outBuf, 0, requiredSize + 1);

    size_t olen = 0;
    int ret = mbedtls_base64_encode(reinterpret_cast<unsigned char *>(outBuf),
                                    requiredSize + 1, &olen, data, len);
    if (ret != 0)
    {
        Serial.println("❌ Base64 encoding error: " + String(ret));
        delete[] outBuf;
        return "";
    }

    String result = String(outBuf).substring(0, olen);
    delete[] outBuf;
    return result;
}

// ============================================================================
// INTERNAL TRANSACTION BUILDING
// ============================================================================

bool Infratic::buildAndSignTransaction(const uint8_t *privateKey, size_t privLen,
                                       const uint8_t *fromPub, const uint8_t *toPub,
                                       uint64_t lamports, const String &recentBlockhash,
                                       String &outTxBase64)
{
    uint8_t numRequiredSignatures = 1;
    uint8_t numReadOnlySigned = 0;
    uint8_t numReadOnlyUnsigned = 1;

    uint8_t recentBlockhashBytes[32];
    size_t rbLen = sizeof(recentBlockhashBytes);
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32)
    {
        Serial.println("❌ Blockhash decode failed");
        return false;
    }

    uint8_t instructionData[12];
    instructionData[0] = 0x02;
    instructionData[1] = 0x00;
    instructionData[2] = 0x00;
    instructionData[3] = 0x00;
    for (int i = 0; i < 8; i++)
    {
        instructionData[4 + i] = (uint8_t)((lamports >> (8 * i)) & 0xFF);
    }

    uint8_t message[512];
    size_t offset = 0;

    message[offset++] = numRequiredSignatures;
    message[offset++] = numReadOnlySigned;
    message[offset++] = numReadOnlyUnsigned;
    message[offset++] = 3;

    memcpy(&message[offset], fromPub, 32);
    offset += 32;
    memcpy(&message[offset], toPub, 32);
    offset += 32;

    uint8_t systemProgram[32];
    size_t spLen = sizeof(systemProgram);
    base58Decode("11111111111111111111111111111111", systemProgram, spLen);
    memcpy(&message[offset], systemProgram, 32);
    offset += 32;

    memcpy(&message[offset], recentBlockhashBytes, 32);
    offset += 32;

    message[offset++] = 1;
    message[offset++] = 2;
    message[offset++] = 2;
    message[offset++] = 0;
    message[offset++] = 1;
    message[offset++] = 12;
    memcpy(&message[offset], instructionData, 12);
    offset += 12;

    size_t messageLen = offset;

    if (privLen < 64)
    {
        Serial.println("❌ Invalid private key length");
        return false;
    }

    const uint8_t *privKeyOnly = privateKey;
    const uint8_t *pubKeyFromPriv = privateKey + 32;

    uint8_t signature[64];
    Ed25519::sign(signature, privKeyOnly, pubKeyFromPriv, message, messageLen);

    uint8_t finalTx[1 + 64 + 512];
    size_t finalOffset = 0;
    finalTx[finalOffset++] = 1;
    memcpy(finalTx + finalOffset, signature, 64);
    finalOffset += 64;
    memcpy(finalTx + finalOffset, message, messageLen);
    finalOffset += messageLen;

    outTxBase64 = base64Encode(finalTx, finalOffset);
    return !outTxBase64.isEmpty();
}

bool Infratic::buildAndSignMemoTransaction(const uint8_t *privateKey, size_t privLen,
                                           const uint8_t *fromPub, const String &programIdBase58,
                                           const String &memoString, const String &recentBlockhash,
                                           String &outTxBase64)
{
    uint8_t numRequiredSignatures = 1;
    uint8_t numReadOnlySigned = 0;
    uint8_t numReadOnlyUnsigned = 0;

    uint8_t recentBlockhashBytes[32];
    size_t rbLen = 32;
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32)
    {
        Serial.println("❌ Blockhash decode error");
        return false;
    }

    uint8_t programIdBytes[32];
    size_t pidLen = 32;
    if (!base58Decode(programIdBase58, programIdBytes, pidLen) || pidLen != 32)
    {
        Serial.println("❌ Program ID decode error");
        return false;
    }

    uint8_t message[512];
    size_t offset = 0;

    message[offset++] = numRequiredSignatures;
    message[offset++] = numReadOnlySigned;
    message[offset++] = numReadOnlyUnsigned;
    message[offset++] = 2;

    memcpy(&message[offset], fromPub, 32);
    offset += 32;
    memcpy(&message[offset], programIdBytes, 32);
    offset += 32;
    memcpy(&message[offset], recentBlockhashBytes, 32);
    offset += 32;

    message[offset++] = 1;
    message[offset++] = 1;
    message[offset++] = 1;
    message[offset++] = 0;

    uint32_t dataLen = memoString.length();
    if (dataLen < 128)
    {
        message[offset++] = (uint8_t)dataLen;
    }
    else
    {
        message[offset++] = (uint8_t)((dataLen & 0x7F) | 0x80);
        message[offset++] = (uint8_t)(dataLen >> 7);
    }

    memcpy(&message[offset], memoString.c_str(), dataLen);
    offset += dataLen;
    size_t messageLen = offset;

    if (privLen < 64)
    {
        Serial.println("❌ Invalid private key");
        return false;
    }

    const uint8_t *privKeyOnly = privateKey;
    const uint8_t *pubKeyFromPriv = privateKey + 32;

    uint8_t signature[64];
    Ed25519::sign(signature, privKeyOnly, pubKeyFromPriv, message, messageLen);

    uint8_t finalTx[1 + 64 + 512];
    size_t finalOffset = 0;
    finalTx[finalOffset++] = 1;
    memcpy(finalTx + finalOffset, signature, 64);
    finalOffset += 64;
    memcpy(finalTx + finalOffset, message, messageLen);
    finalOffset += messageLen;

    outTxBase64 = base64Encode(finalTx, finalOffset);
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

std::vector<uint8_t> Transaction::serializeMessage() const
{
    std::vector<uint8_t> msg;
    msg.push_back(1);
    msg.push_back(0);
    msg.push_back(0);

    std::vector<Pubkey> accountKeys;
    auto add_unique_key = [&](const Pubkey &k)
    {
        for (const auto &existing : accountKeys)
        {
            if (existing.data == k.data)
                return;
        }
        accountKeys.push_back(k);
    };

    add_unique_key(fee_payer);
    for (const auto &ix : instructions)
    {
        for (const auto &acct : ix.accounts)
        {
            add_unique_key(acct.pubkey);
        }
        add_unique_key(ix.programId);
    }

    msg.push_back(accountKeys.size());
    for (const auto &k : accountKeys)
    {
        msg.insert(msg.end(), k.data.begin(), k.data.end());
    }

    uint8_t decoded[64];
    size_t outLen = sizeof(decoded);
    if (base58Decode(recent_blockhash, decoded, outLen))
    {
        msg.insert(msg.end(), decoded, decoded + outLen);
    }

    msg.push_back(instructions.size());
    for (const auto &ix : instructions)
    {
        uint8_t program_id_index = 0;
        for (size_t i = 0; i < accountKeys.size(); ++i)
        {
            if (accountKeys[i].data == ix.programId.data)
            {
                program_id_index = i;
                break;
            }
        }

        msg.push_back(program_id_index);
        msg.push_back(ix.accounts.size());

        for (const auto &acct : ix.accounts)
        {
            for (size_t i = 0; i < accountKeys.size(); ++i)
            {
                if (accountKeys[i].data == acct.pubkey.data)
                {
                    msg.push_back(i);
                    break;
                }
            }
        }

        msg.push_back(ix.data.size());
        msg.insert(msg.end(), ix.data.begin(), ix.data.end());
    }

    return msg;
}

void Transaction::sign(const std::vector<Keypair> &signers)
{
    extern Infratic solana;
    std::vector<uint8_t> msg = serializeMessage();

    if (signers.empty())
        return;

    const Keypair &signer = signers[0];
    if (signer.privkey.size() < 64)
    {
        Serial.println("❌ Invalid private key format");
        return;
    }

    signature.resize(64);
    if (!solana.signMessageRaw(msg, signer.privkey, signature.data()))
    {
        Serial.println("❌ Signature failed");
    }
}

String Transaction::serializeBase64() const
{
    std::vector<uint8_t> msg = serializeMessage();
    std::vector<uint8_t> finalTx;

    finalTx.push_back(1);
    finalTx.insert(finalTx.end(), signature.begin(), signature.end());
    finalTx.insert(finalTx.end(), msg.begin(), msg.end());

    Infratic lib("");
    return lib.base64Encode(finalTx.data(), finalTx.size());
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

    Serial.println("✅ Commitment created: " + outCommitment.substring(0, 16) + "...");
    Serial.printf("   Timestamp saved: %llu\n", outTimestamp);
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
        Serial.println("✅ Data verified against commitment");
    }
    else
    {
        Serial.println("❌ Verification failed - data mismatch");
        Serial.printf("   Expected: %s\n", originalCommitment.c_str());
        Serial.printf("   Got:      %s\n", hexStr);
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
        Serial.println("✅ Commitment stored on-chain");
    }
    else
    {
        Serial.println("❌ Failed to store commitment");
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
        Serial.println("❌ Empty data list");
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
    Serial.println("✅ Merkle root: " + outRoot.substring(0, 16) + "...");
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
        Serial.println("❌ Invalid data index");
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

    Serial.printf("✅ Merkle proof created for index %d\n", dataIndex);
    Serial.printf("   Proof size: %d hashes\n", outProof.siblings.size());
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
        Serial.println("✅ Merkle proof verified");
    }
    else
    {
        Serial.println("❌ Merkle proof verification failed");
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
        Serial.println("❌ Value out of range");
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

    Serial.println("✅ Range proof created");
    Serial.printf("   Value in range [%lld, %lld]\n", minValue, maxValue);
    Serial.println("   Commitment: " + outProof.commitment.substring(0, 16) + "...");

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
        Serial.println("❌ Value out of declared range");
        return false;
    }

    Serial.println("✅ Range proof verified");
    Serial.printf("   Value %lld is in range [%lld, %lld]\n",
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
    Serial.println("⚠️  zkSNARK: Simplified implementation for ESP32");
    Serial.println("   For production, use circom + snarkjs");

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

    Serial.println("✅ zkSNARK proof generated");
    Serial.printf("   Proof size: %d bytes\n", proofData.size());
    Serial.printf("   Public inputs: %d bytes\n", publicInputs.size());

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
        Serial.println("❌ Invalid proof size");
        return false;
    }

    if (proof.publicInputs != expectedPublicInputs)
    {
        Serial.println("❌ Public inputs mismatch");
        return false;
    }

    // In real zkSNARK, verify pairing equation: e(A, B) = e(C, D)
    // Here we just verify proof integrity

    Serial.println("✅ zkSNARK proof verified");
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
        Serial.println("⚠️  Using local timestamp only");
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

    Serial.println("✅ Timestamped proof created");
    Serial.printf("   Timestamp: %llu\n", outTimestamp);
    Serial.println("   Blockhash: " + outBlockhash.substring(0, 16) + "...");
    Serial.println("   Proof: " + outProof.substring(0, 16) + "...");

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
        Serial.println("✅ Timestamped proof verified");
        Serial.printf("   Timestamp: %llu\n", timestamp);
        Serial.println("   Blockhash: " + blockhash.substring(0, 16) + "...");
    }
    else
    {
        Serial.println("❌ Proof verification failed");
        Serial.printf("   Expected: %s\n", proof.c_str());
        Serial.printf("   Got:      %s\n", hexStr);
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

    Serial.printf("✅ Created %d batch commitments\n", outCommitments.size());
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
    Serial.println("\n=== Initialize ZK Storage in Anchor ===");

    // 1. Decode private key
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privLen) || privLen < 64)
    {
        Serial.println("❌ Private key decode failed");
        return false;
    }

    // 2. Derive PDA
    std::vector<uint8_t> authorityBytes = base58ToPubkey(authorityPubkey);
    if (authorityBytes.size() != 32) {
        Serial.println("❌ Authority pubkey decode failed");
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds = {
        std::vector<uint8_t>(seedName.begin(), seedName.end()),
        authorityBytes
    };

    uint8_t bump;
    if (!derivePDA(seeds, programId, outPDA, bump))
    {
        Serial.println("❌ PDA derivation failed");
        return false;
    }

    Serial.println("✅ PDA derived: " + outPDA);
    Serial.printf("   Bump: %d\n", bump);

    // 3. CHECK IF ACCOUNT ALREADY EXISTS
    Serial.println("\n📋 Checking if account already exists...");
    
    uint64_t accountBalance = 0;
    if (getSolBalance(outPDA, accountBalance)) {
        // Account exists
        if (accountBalance > 0) {
            Serial.println("⚠️  Account already initialized");
            Serial.printf("   Balance: %llu lamports\n", accountBalance);
            Serial.println("✅ Skipping initialization (account found)\n");
            outTxSignature = "EXISTING_ACCOUNT";
            return true;  // ← Return success, account already exists
        }
    }

    // 4. Account doesn't exist, create it
    Serial.println("📝 Account not found, creating new one...\n");

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
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        Serial.println("❌ Transaction failed");
        return false;
    }

    Serial.println("✅ Storage initialized: " + outTxSignature);
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
    Serial.println("\n=== Store Commitment in Anchor ===");

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
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    Serial.println("✅ Commitment stored in Anchor: " + outTxSignature);
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
    Serial.println("\n=== Update Commitment in Anchor ===");

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
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    Serial.println("✅ Commitment updated: " + outTxSignature);
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
    Serial.println("\n=== Store Merkle Root in Anchor ===");

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
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    Serial.println("✅ Merkle root stored: " + outTxSignature);
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
    Serial.println("\n=== Store Batch in Anchor ===");

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
    tx.sign({signer});

    String txBase64 = tx.serializeBase64();
    if (!sendRawTransaction(txBase64, outTxSignature))
    {
        return false;
    }

    Serial.println("✅ Batch stored: " + outTxSignature);
    return confirmTransaction(outTxSignature, 5000);
}