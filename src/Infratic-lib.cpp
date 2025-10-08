#include "Infratic-lib.h"

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

extern "C" bool ed25519_decode_public_key(const uint8_t* buf) {
    return true;
}

static bool decodePointWrapper(const uint8_t hash[32]) {
    extern bool ed25519_decode_public_key(const uint8_t* buf);
    return !ed25519_decode_public_key(hash);
}

std::vector<uint8_t> encodeU64LE(uint64_t value) {
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; i++) {
        result[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    return result;
}

std::vector<uint8_t> base58ToPubkey(const String& base58Str) {
    uint8_t buffer[32];
    size_t len = sizeof(buffer);
    if (!base58Decode(base58Str, buffer, len) || len != 32) {
        Serial.println("❌ base58ToPubkey: Invalid base58 input!");
        return {};
    }
    return std::vector<uint8_t>(buffer, buffer + 32);
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================

Infratic::Infratic(const String& rpcUrl) {
    _rpcUrl = rpcUrl;
}

// ============================================================================
// BLOCKCHAIN QUERIES
// ============================================================================

String Infratic::getLatestBlockhash() {
    const int maxRetries = 3;
    const int retryDelayMs = 500;

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        Serial.printf("🌐 Fetching blockhash (attempt %d/%d)...\n", attempt, maxRetries);

        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl)) {
            Serial.println("❌ HTTP begin failed");
            delay(retryDelayMs);
            continue;
        }

        http.addHeader("Content-Type", "application/json");
        String body = R"({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[]})";

        int code = http.POST(body);
        if (code == 200) {
            String response = http.getString();
            http.end();

            DynamicJsonDocument doc(2048);
            if (deserializeJson(doc, response)) {
                delay(retryDelayMs);
                continue;
            }

            String blockhash = doc["result"]["value"]["blockhash"].as<String>();
            if (!blockhash.isEmpty()) {
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

bool Infratic::getBlockHeight(uint64_t& outBlockHeight) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        Serial.println("❌ getBlockHeight: HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getBlockHeight","params":[]})";
    
    int code = http.POST(body);
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(1024);
    if (deserializeJson(doc, response)) {
        return false;
    }

    outBlockHeight = doc["result"].as<uint64_t>();
    return true;
}

bool Infratic::getEpochInfo(EpochInfo& outEpochInfo) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        Serial.println("❌ getEpochInfo: HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[]})";
    
    int code = http.POST(body);
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response)) {
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

bool Infratic::getSolBalance(const String& walletPubkeyBase58, uint64_t& outLamports) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        Serial.println("❌ getSolBalance: HTTP begin failed");
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getBalance","params":[")" +
                  walletPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response)) {
        return false;
    }

    if (doc["error"]) {
        Serial.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    outLamports = doc["result"]["value"];
    return true;
}

bool Infratic::getSplTokenBalance(const String& walletPubkeyBase58, const String& tokenMintBase58, 
                                   uint64_t& outBalance) {
    String ataAddress;
    if (!findAssociatedTokenAccount(walletPubkeyBase58, tokenMintBase58, ataAddress)) {
        Serial.println("⚠️ ATA not found, balance = 0");
        outBalance = 0;
        return true;
    }

    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[")" +
                  ataAddress + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response)) {
        return false;
    }

    if (doc["error"]) {
        return false;
    }

    String amountStr = doc["result"]["value"]["amount"].as<String>();
    if (amountStr.isEmpty()) {
        return false;
    }

    outBalance = strtoull(amountStr.c_str(), nullptr, 10);
    return true;
}

bool Infratic::getTokenDecimals(const String& mintPubkeyBase58, uint8_t& outDecimals) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenSupply","params":[")" +
                  mintPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response)) {
        return false;
    }

    if (doc["error"]) {
        return false;
    }

    JsonVariant decimals = doc["result"]["value"]["decimals"];
    if (decimals.isNull()) {
        return false;
    }

    outDecimals = decimals.as<uint8_t>();
    return true;
}

// ============================================================================
// TOKEN ACCOUNT OPERATIONS
// ============================================================================

bool Infratic::findAssociatedTokenAccount(const String& ownerPubkeyBase58, 
                                          const String& mintPubkeyBase58, 
                                          String& outATA) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        return false;
    }

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":[")" +
                  ownerPubkeyBase58 + R"(",{"mint":")" + mintPubkeyBase58 + 
                  R"("},{"encoding":"jsonParsed"}]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    
    if (code != 200) {
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(4096);
    if (deserializeJson(doc, response)) {
        return false;
    }

    if (doc["error"]) {
        return false;
    }

    JsonArray arr = doc["result"]["value"].as<JsonArray>();
    if (!arr || arr.size() == 0) {
        return false;
    }

    outATA = arr[0]["pubkey"].as<String>();
    return true;
}

// ============================================================================
// TRANSACTION OPERATIONS
// ============================================================================

bool Infratic::sendSol(const String& privateKeyBase58, const String& fromPubkeyBase58,
                       const String& toPubkeyBase58, uint64_t lamports) {
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen)) {
        Serial.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32], toPub[32];
    size_t fromLen = 32, toLen = 32;
    
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32) {
        Serial.println("❌ From pubkey decode error");
        return false;
    }

    if (!base58Decode(toPubkeyBase58, toPub, toLen) || toLen != 32) {
        Serial.println("❌ To pubkey decode error");
        return false;
    }

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) {
        return false;
    }

    String txBase64;
    if (!buildAndSignTransaction(privateKey, privateKeyLen, fromPub, toPub, lamports, blockhash, txBase64)) {
        return false;
    }

    String signature;
    if (!sendRawTransaction(txBase64, signature)) {
        return false;
    }

    Serial.println("✅ Transaction Signature: " + signature);
    return true;
}

bool Infratic::sendProgramDataTransaction(const String& privateKeyBase58, 
                                          const String& fromPubkeyBase58,
                                          const String& programIdBase58, 
                                          const String& dataString,
                                          uint32_t confirmWaitMs) {
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64) {
        Serial.println("❌ Private key decode error");
        return false;
    }

    uint8_t fromPub[32];
    size_t fromLen = sizeof(fromPub);
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32) {
        Serial.println("❌ Public key decode error");
        return false;
    }

    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) {
        return false;
    }

    String txBase64;
    if (!buildAndSignMemoTransaction(privateKey, privateKeyLen, fromPub, programIdBase58, 
                                     dataString, blockhash, txBase64)) {
        return false;
    }

    String signature;
    if (!sendRawTransaction(txBase64, signature)) {
        return false;
    }

    Serial.println("✅ Tx Signature: " + signature);

    if (!confirmTransaction(signature, confirmWaitMs)) {
        Serial.println("⚠️ Transaction NOT confirmed in time");
        return false;
    }

    Serial.println("✅ Transaction confirmed");
    return true;
}

bool Infratic::sendRawTransaction(const String& txBase64, String& outSignature) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        Serial.println("❌ HTTP begin failed");
        return false;
    }

    http.addHeader("Content-Type", "application/json");

    String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[")" +
                  txBase64 + R"(",{"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}]})";

    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("❌ HTTP code: %d\n", code);
        Serial.println(http.getString());
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response)) {
        Serial.println("❌ JSON parse error");
        return false;
    }

    if (doc["error"]) {
        Serial.println("❌ RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    outSignature = doc["result"].as<String>();
    return true;
}

bool Infratic::confirmTransaction(const String& signature, uint32_t maxWaitMs) {
    const uint32_t pollIntervalMs = 500;
    uint32_t waited = 0;

    while (waited <= maxWaitMs) {
        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl)) {
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        String body = String() + R"({"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[[")" +
                      signature + R"("],{"searchTransactionHistory":true}]})";

        http.addHeader("Content-Type", "application/json");
        int code = http.POST(body);
        
        if (code != 200) {
            http.end();
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        String response = http.getString();
        http.end();

        DynamicJsonDocument doc(2048);
        if (deserializeJson(doc, response)) {
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        JsonVariant status = doc["result"]["value"][0];
        if (!status.isNull()) {
            bool errNull = status["err"].isNull();
            String confStatus = status["confirmationStatus"] | "";

            if ((confStatus == "confirmed" || confStatus == "finalized") && errNull) {
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

bool Infratic::signMessageFromBase58(const std::vector<uint8_t>& message, 
                                     const String& privateKeyBase58,
                                     uint8_t outSignature[64]) {
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64) {
        Serial.println("❌ Failed to decode private key");
        return false;
    }

    const uint8_t* priv = privateKey;
    const uint8_t* pub = privateKey + 32;

    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}

bool Infratic::signMessageRaw(const std::vector<uint8_t>& message, 
                              const std::vector<uint8_t>& privateKey,
                              uint8_t outSignature[64]) {
    if (privateKey.size() < 64) {
        Serial.println("❌ Invalid private key size");
        return false;
    }

    const uint8_t* priv = privateKey.data();
    const uint8_t* pub = privateKey.data() + 32;

    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}

// ============================================================================
// PDA OPERATIONS
// ============================================================================

bool Infratic::derivePDA(const std::vector<std::vector<uint8_t>>& seeds, 
                         const String& programIdBase58,
                         String& outPDABase58, uint8_t& outBump) {
    std::vector<uint8_t> programId = base58ToPubkey(programIdBase58);
    if (programId.size() != 32) {
        Serial.println("❌ Invalid program ID");
        return false;
    }

    std::vector<uint8_t> pdaBytes;
    if (!findProgramAddress(seeds, programId, pdaBytes, outBump)) {
        Serial.println("❌ Failed to derive PDA");
        return false;
    }

    outPDABase58 = base58Encode(pdaBytes.data(), pdaBytes.size());
    if (outPDABase58.isEmpty()) {
        Serial.println("❌ Failed to encode PDA to Base58");
        return false;
    }
    
    Serial.println("✅ Derived PDA: " + outPDABase58);
    Serial.println("   Bump: " + String(outBump));
    
    return true;
}

bool Infratic::findProgramAddress(const std::vector<std::vector<uint8_t>>& seeds,
                                   const std::vector<uint8_t>& programId,
                                   std::vector<uint8_t>& outPDA, uint8_t& outBump) {
    const std::string marker = "ProgramDerivedAddress";

    for (int bump = 255; bump >= 0; --bump) {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);

        for (const auto& seed : seeds) {
            mbedtls_sha256_update_ret(&ctx, seed.data(), seed.size());
        }

        uint8_t bumpByte = static_cast<uint8_t>(bump);
        mbedtls_sha256_update_ret(&ctx, &bumpByte, 1);
        mbedtls_sha256_update_ret(&ctx, programId.data(), programId.size());
        mbedtls_sha256_update_ret(&ctx, (const uint8_t*)marker.c_str(), marker.size());

        uint8_t hash[32];
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        bool isValid = decodePointWrapper(hash);
        if (isValid) {
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

std::vector<uint8_t> Infratic::calculateDiscriminator(const std::string& functionName) {
    std::string input = "global:" + functionName;

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t*)input.c_str(), input.size());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    return std::vector<uint8_t>(hash, hash + 8);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

String Infratic::base64Encode(const uint8_t* data, size_t len) {
    size_t requiredSize = 4 * ((len + 2) / 3);
    char* outBuf = new char[requiredSize + 1];
    memset(outBuf, 0, requiredSize + 1);
    
    size_t olen = 0;
    int ret = mbedtls_base64_encode(reinterpret_cast<unsigned char*>(outBuf), 
                                     requiredSize + 1, &olen, data, len);
    if (ret != 0) {
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

bool Infratic::buildAndSignTransaction(const uint8_t* privateKey, size_t privLen,
                                        const uint8_t* fromPub, const uint8_t* toPub,
                                        uint64_t lamports, const String& recentBlockhash,
                                        String& outTxBase64) {
    uint8_t numRequiredSignatures = 1;
    uint8_t numReadOnlySigned = 0;
    uint8_t numReadOnlyUnsigned = 1;

    uint8_t recentBlockhashBytes[32];
    size_t rbLen = sizeof(recentBlockhashBytes);
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32) {
        Serial.println("❌ Blockhash decode failed");
        return false;
    }

    uint8_t instructionData[12];
    instructionData[0] = 0x02;
    instructionData[1] = 0x00;
    instructionData[2] = 0x00;
    instructionData[3] = 0x00;
    for (int i = 0; i < 8; i++) {
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

    if (privLen < 64) {
        Serial.println("❌ Invalid private key length");
        return false;
    }

    const uint8_t* privKeyOnly = privateKey;
    const uint8_t* pubKeyFromPriv = privateKey + 32;

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

bool Infratic::buildAndSignMemoTransaction(const uint8_t* privateKey, size_t privLen,
                                            const uint8_t* fromPub, const String& programIdBase58,
                                            const String& memoString, const String& recentBlockhash,
                                            String& outTxBase64) {
    uint8_t numRequiredSignatures = 1;
    uint8_t numReadOnlySigned = 0;
    uint8_t numReadOnlyUnsigned = 0;

    uint8_t recentBlockhashBytes[32];
    size_t rbLen = 32;
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32) {
        Serial.println("❌ Blockhash decode error");
        return false;
    }

    uint8_t programIdBytes[32];
    size_t pidLen = 32;
    if (!base58Decode(programIdBase58, programIdBytes, pidLen) || pidLen != 32) {
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
    if (dataLen < 128) {
        message[offset++] = (uint8_t)dataLen;
    } else {
        message[offset++] = (uint8_t)((dataLen & 0x7F) | 0x80);
        message[offset++] = (uint8_t)(dataLen >> 7);
    }

    memcpy(&message[offset], memoString.c_str(), dataLen);
    offset += dataLen;
    size_t messageLen = offset;

    if (privLen < 64) {
        Serial.println("❌ Invalid private key");
        return false;
    }

    const uint8_t* privKeyOnly = privateKey;
    const uint8_t* pubKeyFromPriv = privateKey + 32;

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

Pubkey Pubkey::fromBase58(const String& str) {
    Pubkey pk;
    pk.data = base58ToPubkey(str);
    return pk;
}

Keypair Keypair::fromPrivateKey(const uint8_t* key64) {
    Keypair kp;
    kp.privkey = std::vector<uint8_t>(key64, key64 + 64);
    kp.pubkey_ = Pubkey{std::vector<uint8_t>(key64 + 32, key64 + 64)};
    return kp;
}

const Pubkey& Keypair::pubkey() const {
    return pubkey_;
}

AccountMeta AccountMeta::signer(const Pubkey& key) {
    return AccountMeta{key, true, false};
}

AccountMeta AccountMeta::writable(const Pubkey& key, bool isSigner) {
    return AccountMeta{key, isSigner, true};
}

Instruction::Instruction(const Pubkey& pid, const std::vector<AccountMeta>& accts, 
                        const std::vector<uint8_t>& d)
    : programId(pid), accounts(accts), data(d) {}

void Transaction::add(const Instruction& ix) {
    instructions.push_back(ix);
}

std::vector<uint8_t> Transaction::serializeMessage() const {
    std::vector<uint8_t> msg;
    msg.push_back(1); 
    msg.push_back(0); 
    msg.push_back(0);

    std::vector<Pubkey> accountKeys;
    auto add_unique_key = [&](const Pubkey& k) {
        for (const auto& existing : accountKeys) {
            if (existing.data == k.data) return;
        }
        accountKeys.push_back(k);
    };

    add_unique_key(fee_payer);
    for (const auto& ix : instructions) {
        for (const auto& acct : ix.accounts) {
            add_unique_key(acct.pubkey);
        }
        add_unique_key(ix.programId);
    }

    msg.push_back(accountKeys.size());
    for (const auto& k : accountKeys) {
        msg.insert(msg.end(), k.data.begin(), k.data.end());
    }

    uint8_t decoded[64];
    size_t outLen = sizeof(decoded);
    if (base58Decode(recent_blockhash, decoded, outLen)) {
        msg.insert(msg.end(), decoded, decoded + outLen);
    }

    msg.push_back(instructions.size());
    for (const auto& ix : instructions) {
        uint8_t program_id_index = 0;
        for (size_t i = 0; i < accountKeys.size(); ++i) {
            if (accountKeys[i].data == ix.programId.data) {
                program_id_index = i;
                break;
            }
        }

        msg.push_back(program_id_index);
        msg.push_back(ix.accounts.size());
        
        for (const auto& acct : ix.accounts) {
            for (size_t i = 0; i < accountKeys.size(); ++i) {
                if (accountKeys[i].data == acct.pubkey.data) {
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

void Transaction::sign(const std::vector<Keypair>& signers) {
    extern Infratic solana;
    std::vector<uint8_t> msg = serializeMessage();

    if (signers.empty()) return;
    
    const Keypair& signer = signers[0];
    if (signer.privkey.size() < 64) {
        Serial.println("❌ Invalid private key format");
        return;
    }

    signature.resize(64);
    if (!solana.signMessageRaw(msg, signer.privkey, signature.data())) {
        Serial.println("❌ Signature failed");
    }
}

String Transaction::serializeBase64() const {
    std::vector<uint8_t> msg = serializeMessage();
    std::vector<uint8_t> finalTx;
    
    finalTx.push_back(1);
    finalTx.insert(finalTx.end(), signature.begin(), signature.end());
    finalTx.insert(finalTx.end(), msg.begin(), msg.end());

    Infratic lib("");
    return lib.base64Encode(finalTx.data(), finalTx.size());
}