#include <Arduino.h>
#include <WiFi.h>
#include "Infratic-lib.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

const String SOLANA_RPC_URL = "https://api.devnet.solana.com";

const String PRIVATE_KEY_BASE58 = "YOUR_PRIVATE_KEY_BASE58";
const String PUBLIC_KEY_BASE58 = "YOUR_PUBLIC_KEY_BASE58";
const String RECIPIENT_PUBKEY_BASE58 = "RECIPIENT_PUBKEY_BASE58";
const String PROGRAM_ID_BASE58 = "YOUR_PROGRAM_ID_BASE58";

// Token mint (example: USDC Devnet)
const String TOKEN_MINT_BASE58 = "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr";

Infratic solana(SOLANA_RPC_URL);

// ============================================================================
// BLOCKCHAIN QUERY EXAMPLES
// ============================================================================

void example_getLatestBlockhash() {
    Serial.println("\n=== Get Latest Blockhash ===");
    
    String blockhash = solana.getLatestBlockhash();
    if (!blockhash.isEmpty()) {
        Serial.println("✅ Blockhash: " + blockhash);
    } else {
        Serial.println("❌ Failed to get blockhash");
    }
}

void example_getBlockHeight() {
    Serial.println("\n=== Get Block Height ===");
    
    uint64_t blockHeight = 0;
    if (solana.getBlockHeight(blockHeight)) {
        Serial.print("✅ Block Height: ");
        Serial.println((unsigned long)blockHeight);
    } else {
        Serial.println("❌ Failed to get block height");
    }
}

void example_getEpochInfo() {
    Serial.println("\n=== Get Epoch Info ===");
    
    EpochInfo info;
    if (solana.getEpochInfo(info)) {
        Serial.println("✅ Epoch Info:");
        Serial.printf("   Absolute Slot: %llu\n", info.absoluteSlot);
        Serial.printf("   Block Height : %llu\n", info.blockHeight);
        Serial.printf("   Epoch        : %llu\n", info.epoch);
        Serial.printf("   Slot Index   : %llu\n", info.slotIndex);
        Serial.printf("   Slots/Epoch  : %llu\n", info.slotsInEpoch);
    } else {
        Serial.println("❌ Failed to get epoch info");
    }
}

// ============================================================================
// BALANCE QUERY EXAMPLES
// ============================================================================

void example_getSolBalance() {
    Serial.println("\n=== Get SOL Balance ===");
    
    uint64_t lamports = 0;
    if (solana.getSolBalance(PUBLIC_KEY_BASE58, lamports)) {
        Serial.print("✅ Balance: ");
        Serial.print((unsigned long)lamports);
        Serial.println(" lamports");
        Serial.print("   (~");
        Serial.print((float)lamports / 1e9, 9);
        Serial.println(" SOL)");
    } else {
        Serial.println("❌ Failed to get SOL balance");
    }
}

void example_getSplTokenBalance() {
    Serial.println("\n=== Get SPL Token Balance ===");
    
    uint64_t rawBalance = 0;
    if (solana.getSplTokenBalance(PUBLIC_KEY_BASE58, TOKEN_MINT_BASE58, rawBalance)) {
        Serial.print("✅ Token Balance: ");
        Serial.println((unsigned long)rawBalance);
        
        uint8_t decimals = 0;
        if (solana.getTokenDecimals(TOKEN_MINT_BASE58, decimals)) {
            float readable = (float)rawBalance / pow(10, decimals);
            Serial.print("   (~");
            Serial.print(readable, decimals);
            Serial.println(" tokens)");
        }
    } else {
        Serial.println("❌ Failed to get token balance");
    }
}

void example_getTokenDecimals() {
    Serial.println("\n=== Get Token Decimals ===");
    
    uint8_t decimals = 0;
    if (solana.getTokenDecimals(TOKEN_MINT_BASE58, decimals)) {
        Serial.print("✅ Token Decimals: ");
        Serial.println(decimals);
    } else {
        Serial.println("❌ Failed to get token decimals");
    }
}

// ============================================================================
// TOKEN ACCOUNT EXAMPLES
// ============================================================================

void example_findAssociatedTokenAccount() {
    Serial.println("\n=== Find Associated Token Account ===");
    
    String ata;
    if (solana.findAssociatedTokenAccount(PUBLIC_KEY_BASE58, TOKEN_MINT_BASE58, ata)) {
        Serial.println("✅ ATA Found: " + ata);
    } else {
        Serial.println("❌ ATA not found");
    }
}

// ============================================================================
// TRANSACTION EXAMPLES
// ============================================================================

void example_sendSol() {
    Serial.println("\n=== Send SOL Transaction ===");
    
    uint64_t lamports = 1000000; // 0.001 SOL
    
    if (solana.sendSol(PRIVATE_KEY_BASE58, PUBLIC_KEY_BASE58, 
                       RECIPIENT_PUBKEY_BASE58, lamports)) {
        Serial.println("✅ SOL transaction sent successfully");
    } else {
        Serial.println("❌ Failed to send SOL transaction");
    }
}

void example_sendProgramData() {
    Serial.println("\n=== Send Program Data ===");
    
    String customData = "Infratic test message!";
    
    if (solana.sendProgramDataTransaction(PRIVATE_KEY_BASE58, PUBLIC_KEY_BASE58,
                                         PROGRAM_ID_BASE58, customData, 7000)) {
        Serial.println("✅ Program data sent successfully");
    } else {
        Serial.println("❌ Failed to send program data");
    }
}

void example_confirmTransaction() {
    Serial.println("\n=== Confirm Transaction ===");
    
    String txSignature = "PASTE_YOUR_TX_SIGNATURE_HERE";
    
    if (solana.confirmTransaction(txSignature, 5000)) {
        Serial.println("✅ Transaction confirmed");
    } else {
        Serial.println("❌ Transaction not confirmed");
    }
}

// ============================================================================
// CRYPTOGRAPHIC EXAMPLES
// ============================================================================

void example_signMessageFromBase58() {
    Serial.println("\n=== Sign Message (Base58) ===");
    
    std::vector<uint8_t> message = {'I', 'o', 'T', 'x', 'C', 'h', 'a', 'i', 'n'};
    uint8_t signature[64];
    
    if (solana.signMessageFromBase58(message, PRIVATE_KEY_BASE58, signature)) {
        Serial.print("✅ Signature: ");
        for (int i = 0; i < 64; i++) {
            if (signature[i] < 16) Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    } else {
        Serial.println("❌ Failed to sign message");
    }
}

void example_signMessageRaw() {
    Serial.println("\n=== Sign Message (Raw) ===");
    
    std::vector<uint8_t> message = {'R', 'a', 'w', 'T', 'e', 's', 't'};
    uint8_t signature[64];
    
    // Decode Base58 private key to raw bytes
    uint8_t rawPrivKey[128];
    size_t privLen = sizeof(rawPrivKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, rawPrivKey, privLen) || privLen < 64) {
        Serial.println("❌ Failed to decode private key");
        return;
    }
    
    std::vector<uint8_t> privKeyVec(rawPrivKey, rawPrivKey + 64);
    
    if (solana.signMessageRaw(message, privKeyVec, signature)) {
        Serial.print("✅ Signature: ");
        for (int i = 0; i < 64; i++) {
            if (signature[i] < 16) Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    } else {
        Serial.println("❌ Failed to sign message");
    }
}

// ============================================================================
// PDA EXAMPLES
// ============================================================================

void example_derivePDA() {
    Serial.println("\n=== Derive PDA ===");
    
    std::vector<std::vector<uint8_t>> seeds = {
        {'t', 'e', 'm', 'p', '_', 'd', 'a', 't', 'a'},
        base58ToPubkey(PUBLIC_KEY_BASE58)
    };
    
    String pda;
    uint8_t bump;
    
    if (solana.derivePDA(seeds, PROGRAM_ID_BASE58, pda, bump)) {
        Serial.println("✅ PDA: " + pda);
        Serial.println("   Bump: " + String(bump));
    } else {
        Serial.println("❌ Failed to derive PDA");
    }
}

// ============================================================================
// ANCHOR FRAMEWORK EXAMPLES
// ============================================================================

void example_calculateDiscriminator() {
    Serial.println("\n=== Calculate Anchor Discriminator ===");
    
    String functionName = "update_temperature";
    std::vector<uint8_t> discriminator = solana.calculateDiscriminator(functionName.c_str());
    
    Serial.print("✅ Discriminator for '" + functionName + "': ");
    for (uint8_t b : discriminator) {
        if (b < 16) Serial.print("0");
        Serial.print(b, HEX);
    }
    Serial.println();
}

void example_anchorTransaction() {
    Serial.println("\n=== Anchor Transaction Example ===");
    
    // Decode private key
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, privateKey, privLen) || privLen < 64) {
        Serial.println("❌ Private key decode failed");
        return;
    }
    
    // Setup accounts
    Pubkey authority = Pubkey::fromBase58(PUBLIC_KEY_BASE58);
    Keypair signer = Keypair::fromPrivateKey(privateKey);
    std::vector<uint8_t> programId = base58ToPubkey(PROGRAM_ID_BASE58);
    
    // Derive PDA
    std::vector<std::vector<uint8_t>> seeds = {
        {'t', 'e', 'm', 'p', '_', 'd', 'a', 't', 'a'},
        base58ToPubkey(PUBLIC_KEY_BASE58)
    };
    
    String pdaBase58;
    uint8_t bump;
    if (!solana.derivePDA(seeds, PROGRAM_ID_BASE58, pdaBase58, bump)) {
        Serial.println("❌ Failed to derive PDA");
        return;
    }
    
    Pubkey pda = Pubkey::fromBase58(pdaBase58);
    
    // Build instruction data
    std::vector<uint8_t> discriminator = solana.calculateDiscriminator("update_temperature");
    std::vector<uint8_t> data = discriminator;
    
    // Add payload (temperature and humidity as u64 LE)
    int64_t temperature = 42;
    int64_t humidity = 55;
    std::vector<uint8_t> tempEncoded = encodeU64LE((uint64_t)temperature);
    std::vector<uint8_t> humidityEncoded = encodeU64LE((uint64_t)humidity);
    data.insert(data.end(), tempEncoded.begin(), tempEncoded.end());
    data.insert(data.end(), humidityEncoded.begin(), humidityEncoded.end());
    
    // Create instruction
    Instruction ix(
        Pubkey{programId},
        {
            AccountMeta::writable(pda, false),
            AccountMeta::signer(authority)
        },
        data
    );
    
    // Build and send transaction
    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = solana.getLatestBlockhash();
    
    if (tx.recent_blockhash.isEmpty()) {
        Serial.println("❌ Failed to get blockhash");
        return;
    }
    
    tx.add(ix);
    tx.sign({signer});
    String txBase64 = tx.serializeBase64();
    
    String txSig;
    if (solana.sendRawTransaction(txBase64, txSig)) {
        Serial.println("✅ Anchor tx sent! Signature: " + txSig);
    } else {
        Serial.println("❌ Anchor tx failed");
    }
}

// ============================================================================
// UTILITY EXAMPLES
// ============================================================================

void example_base64Encode() {
    Serial.println("\n=== Base64 Encode ===");
    
    const char* data = "Infratic Library Test";
    String encoded = solana.base64Encode((const uint8_t*)data, strlen(data));
    
    Serial.println("✅ Original: " + String(data));
    Serial.println("   Base64  : " + encoded);
}

void example_base58ToPubkey() {
    Serial.println("\n=== Base58 to Pubkey ===");
    
    std::vector<uint8_t> pubkeyVec = base58ToPubkey(PUBLIC_KEY_BASE58);
    
    if (pubkeyVec.size() == 32) {
        Serial.print("✅ Decoded Public Key (hex): ");
        for (uint8_t b : pubkeyVec) {
            if (b < 16) Serial.print("0");
            Serial.print(b, HEX);
        }
        Serial.println();
    } else {
        Serial.println("❌ Invalid public key");
    }
}

// ============================================================================
// COMBINED TEST SUITE
// ============================================================================

void runAllTests() {
    Serial.println("\n╔════════════════════════════════════════╗");
    Serial.println("║   Infratic Library - Test Suite      ║");
    Serial.println("╚════════════════════════════════════════╝\n");
    
    // Blockchain Queries
    Serial.println("┌─ BLOCKCHAIN QUERIES ─────────────────┐");
    example_getLatestBlockhash();
    delay(500);
    example_getBlockHeight();
    delay(500);
    example_getEpochInfo();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // Balance Queries
    Serial.println("┌─ BALANCE QUERIES ────────────────────┐");
    example_getSolBalance();
    delay(500);
    example_getSplTokenBalance();
    delay(500);
    example_getTokenDecimals();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // Token Accounts
    Serial.println("┌─ TOKEN ACCOUNTS ─────────────────────┐");
    example_findAssociatedTokenAccount();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // Cryptography
    Serial.println("┌─ CRYPTOGRAPHY ───────────────────────┐");
    example_signMessageFromBase58();
    delay(500);
    example_signMessageRaw();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // PDA Operations
    Serial.println("┌─ PDA OPERATIONS ─────────────────────┐");
    example_derivePDA();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // Anchor Framework
    Serial.println("┌─ ANCHOR FRAMEWORK ───────────────────┐");
    example_calculateDiscriminator();
    Serial.println("└──────────────────────────────────────┘\n");
    
    // Utilities
    Serial.println("┌─ UTILITIES ──────────────────────────┐");
    example_base64Encode();
    delay(500);
    example_base58ToPubkey();
    Serial.println("└──────────────────────────────────────┘\n");
    
    Serial.println("╔════════════════════════════════════════╗");
    Serial.println("║   Test Suite Completed                 ║");
    Serial.println("╚════════════════════════════════════════╝\n");
    
    // Uncomment these to test transactions (they will spend SOL!)
    // Serial.println("⚠️  TRANSACTION TESTS (DISABLED BY DEFAULT) ⚠️");
    // example_sendSol();
    // delay(2000);
    // example_sendProgramData();
    // delay(2000);
    // example_anchorTransaction();
}

// ============================================================================
// SETUP AND LOOP
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n\n");
    Serial.println("╔════════════════════════════════════════╗");
    Serial.println("║   Infratic - Solana ESP32 Library    ║");
    Serial.println("║   Starting Up...                       ║");
    Serial.println("╚════════════════════════════════════════╝\n");
    
    // Connect to WiFi
    Serial.print("📡 Connecting to WiFi");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println();
        Serial.println("✅ WiFi connected!");
        Serial.print("   IP Address: ");
        Serial.println(WiFi.localIP());
        Serial.print("   Signal Strength: ");
        Serial.print(WiFi.RSSI());
        Serial.println(" dBm\n");
        
        delay(1000);
        
        // Run all tests
        runAllTests();
        
    } else {
        Serial.println();
        Serial.println("❌ WiFi connection failed!");
        Serial.println("   Please check your credentials and try again.");
    }
}

void loop() {
    // Keep the connection alive
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("⚠️  WiFi disconnected! Reconnecting...");
        WiFi.reconnect();
        delay(5000);
    }
    
    delay(10000); // Check every 10 seconds
}

// ============================================================================
// INDIVIDUAL TEST FUNCTIONS (Call these separately if needed)
// ============================================================================

/*
 * You can call individual test functions from setup() like this:
 * 
 * void setup() {
 *     Serial.begin(115200);
 *     WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
 *     while (WiFi.status() != WL_CONNECTED) delay(500);
 *     
 *     // Run only specific tests
 *     example_getSolBalance();
 *     example_derivePDA();
 *     example_calculateDiscriminator();
 * }
 */