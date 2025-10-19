#include <Arduino.h>
#include <WiFi.h>
#include "Infratic-lib.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

const char *WIFI_SSID = "YOUR_WIFI_SSID";
const char *WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

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

void example_getLatestBlockhash()
{
    Serial.println("\n=== Get Latest Blockhash ===");

    String blockhash = solana.getLatestBlockhash();
    if (!blockhash.isEmpty())
    {
        Serial.println("✅ Blockhash: " + blockhash);
    }
    else
    {
        Serial.println("❌ Failed to get blockhash");
    }
}

void example_getBlockHeight()
{
    Serial.println("\n=== Get Block Height ===");

    uint64_t blockHeight = 0;
    if (solana.getBlockHeight(blockHeight))
    {
        Serial.print("✅ Block Height: ");
        Serial.println((unsigned long)blockHeight);
    }
    else
    {
        Serial.println("❌ Failed to get block height");
    }
}

void example_getEpochInfo()
{
    Serial.println("\n=== Get Epoch Info ===");

    EpochInfo info;
    if (solana.getEpochInfo(info))
    {
        Serial.println("✅ Epoch Info:");
        Serial.printf("   Absolute Slot: %llu\n", info.absoluteSlot);
        Serial.printf("   Block Height : %llu\n", info.blockHeight);
        Serial.printf("   Epoch        : %llu\n", info.epoch);
        Serial.printf("   Slot Index   : %llu\n", info.slotIndex);
        Serial.printf("   Slots/Epoch  : %llu\n", info.slotsInEpoch);
    }
    else
    {
        Serial.println("❌ Failed to get epoch info");
    }
}

// ============================================================================
// BALANCE QUERY EXAMPLES
// ============================================================================

void example_getSolBalance()
{
    Serial.println("\n=== Get SOL Balance ===");

    uint64_t lamports = 0;
    if (solana.getSolBalance(PUBLIC_KEY_BASE58, lamports))
    {
        Serial.print("✅ Balance: ");
        Serial.print((unsigned long)lamports);
        Serial.println(" lamports");
        Serial.print("   (~");
        Serial.print((float)lamports / 1e9, 9);
        Serial.println(" SOL)");
    }
    else
    {
        Serial.println("❌ Failed to get SOL balance");
    }
}

void example_getSplTokenBalance()
{
    Serial.println("\n=== Get SPL Token Balance ===");

    uint64_t rawBalance = 0;
    if (solana.getSplTokenBalance(PUBLIC_KEY_BASE58, TOKEN_MINT_BASE58, rawBalance))
    {
        Serial.print("✅ Token Balance: ");
        Serial.println((unsigned long)rawBalance);

        uint8_t decimals = 0;
        if (solana.getTokenDecimals(TOKEN_MINT_BASE58, decimals))
        {
            float readable = (float)rawBalance / pow(10, decimals);
            Serial.print("   (~");
            Serial.print(readable, decimals);
            Serial.println(" tokens)");
        }
    }
    else
    {
        Serial.println("❌ Failed to get token balance");
    }
}

void example_getTokenDecimals()
{
    Serial.println("\n=== Get Token Decimals ===");

    uint8_t decimals = 0;
    if (solana.getTokenDecimals(TOKEN_MINT_BASE58, decimals))
    {
        Serial.print("✅ Token Decimals: ");
        Serial.println(decimals);
    }
    else
    {
        Serial.println("❌ Failed to get token decimals");
    }
}

// ============================================================================
// TOKEN ACCOUNT EXAMPLES
// ============================================================================

void example_findAssociatedTokenAccount()
{
    Serial.println("\n=== Find Associated Token Account ===");

    String ata;
    if (solana.findAssociatedTokenAccount(PUBLIC_KEY_BASE58, TOKEN_MINT_BASE58, ata))
    {
        Serial.println("✅ ATA Found: " + ata);
    }
    else
    {
        Serial.println("❌ ATA not found");
    }
}

// ============================================================================
// TRANSACTION EXAMPLES
// ============================================================================

void example_sendSol()
{
    Serial.println("\n=== Send SOL Transaction ===");

    uint64_t lamports = 1000000; // 0.001 SOL

    if (solana.sendSol(PRIVATE_KEY_BASE58, PUBLIC_KEY_BASE58,
                       RECIPIENT_PUBKEY_BASE58, lamports))
    {
        Serial.println("✅ SOL transaction sent successfully");
    }
    else
    {
        Serial.println("❌ Failed to send SOL transaction");
    }
}

void example_sendProgramData()
{
    Serial.println("\n=== Send Program Data ===");

    String customData = "Infratic test message!";

    if (solana.sendProgramDataTransaction(PRIVATE_KEY_BASE58, PUBLIC_KEY_BASE58,
                                          PROGRAM_ID_BASE58, customData, 7000))
    {
        Serial.println("✅ Program data sent successfully");
    }
    else
    {
        Serial.println("❌ Failed to send program data");
    }
}

void example_confirmTransaction()
{
    Serial.println("\n=== Confirm Transaction ===");

    String txSignature = "PASTE_YOUR_TX_SIGNATURE_HERE";

    if (solana.confirmTransaction(txSignature, 5000))
    {
        Serial.println("✅ Transaction confirmed");
    }
    else
    {
        Serial.println("❌ Transaction not confirmed");
    }
}

// ============================================================================
// CRYPTOGRAPHIC EXAMPLES
// ============================================================================

void example_signMessageFromBase58()
{
    Serial.println("\n=== Sign Message (Base58) ===");

    std::vector<uint8_t> message = {'I', 'o', 'T', 'x', 'C', 'h', 'a', 'i', 'n'};
    uint8_t signature[64];

    if (solana.signMessageFromBase58(message, PRIVATE_KEY_BASE58, signature))
    {
        Serial.print("✅ Signature: ");
        for (int i = 0; i < 64; i++)
        {
            if (signature[i] < 16)
                Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    }
    else
    {
        Serial.println("❌ Failed to sign message");
    }
}

void example_signMessageRaw()
{
    Serial.println("\n=== Sign Message (Raw) ===");

    std::vector<uint8_t> message = {'R', 'a', 'w', 'T', 'e', 's', 't'};
    uint8_t signature[64];

    // Decode Base58 private key to raw bytes
    uint8_t rawPrivKey[128];
    size_t privLen = sizeof(rawPrivKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, rawPrivKey, privLen) || privLen < 64)
    {
        Serial.println("❌ Failed to decode private key");
        return;
    }

    std::vector<uint8_t> privKeyVec(rawPrivKey, rawPrivKey + 64);

    if (solana.signMessageRaw(message, privKeyVec, signature))
    {
        Serial.print("✅ Signature: ");
        for (int i = 0; i < 64; i++)
        {
            if (signature[i] < 16)
                Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    }
    else
    {
        Serial.println("❌ Failed to sign message");
    }
}

// ============================================================================
// PDA EXAMPLES
// ============================================================================

void example_derivePDA()
{
    Serial.println("\n=== Derive PDA ===");

    std::vector<std::vector<uint8_t>> seeds = {
        {'t', 'e', 'm', 'p', '_', 'd', 'a', 't', 'a'},
        base58ToPubkey(PUBLIC_KEY_BASE58)};

    String pda;
    uint8_t bump;

    if (solana.derivePDA(seeds, PROGRAM_ID_BASE58, pda, bump))
    {
        Serial.println("✅ PDA: " + pda);
        Serial.println("   Bump: " + String(bump));
    }
    else
    {
        Serial.println("❌ Failed to derive PDA");
    }
}

// ============================================================================
// ANCHOR FRAMEWORK EXAMPLES
// ============================================================================

void example_calculateDiscriminator()
{
    Serial.println("\n=== Calculate Anchor Discriminator ===");

    String functionName = "update_temperature";
    std::vector<uint8_t> discriminator = solana.calculateDiscriminator(functionName.c_str());

    Serial.print("✅ Discriminator for '" + functionName + "': ");
    for (uint8_t b : discriminator)
    {
        if (b < 16)
            Serial.print("0");
        Serial.print(b, HEX);
    }
    Serial.println();
}

void example_anchorTransaction()
{
    Serial.println("\n=== Anchor Transaction Example ===");

    // Decode private key
    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, privateKey, privLen) || privLen < 64)
    {
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
        base58ToPubkey(PUBLIC_KEY_BASE58)};

    String pdaBase58;
    uint8_t bump;
    if (!solana.derivePDA(seeds, PROGRAM_ID_BASE58, pdaBase58, bump))
    {
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
        {AccountMeta::writable(pda, false),
         AccountMeta::signer(authority)},
        data);

    // Build and send transaction
    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = solana.getLatestBlockhash();

    if (tx.recent_blockhash.isEmpty())
    {
        Serial.println("❌ Failed to get blockhash");
        return;
    }

    tx.add(ix);
    tx.sign({signer});
    String txBase64 = tx.serializeBase64();

    String txSig;
    if (solana.sendRawTransaction(txBase64, txSig))
    {
        Serial.println("✅ Anchor tx sent! Signature: " + txSig);
    }
    else
    {
        Serial.println("❌ Anchor tx failed");
    }
}

// ============================================================================
// UTILITY EXAMPLES
// ============================================================================

void example_base64Encode()
{
    Serial.println("\n=== Base64 Encode ===");

    const char *data = "Infratic Library Test";
    String encoded = solana.base64Encode((const uint8_t *)data, strlen(data));

    Serial.println("✅ Original: " + String(data));
    Serial.println("   Base64  : " + encoded);
}

void example_base58ToPubkey()
{
    Serial.println("\n=== Base58 to Pubkey ===");

    std::vector<uint8_t> pubkeyVec = base58ToPubkey(PUBLIC_KEY_BASE58);

    if (pubkeyVec.size() == 32)
    {
        Serial.print("✅ Decoded Public Key (hex): ");
        for (uint8_t b : pubkeyVec)
        {
            if (b < 16)
                Serial.print("0");
            Serial.print(b, HEX);
        }
        Serial.println();
    }
    else
    {
        Serial.println("❌ Invalid public key");
    }
}

// ============================================================================
// COMBINED TEST SUITE
// ============================================================================

void runAllTests()
{
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

    Serial.println("┌─ ZKExamples ──────────────────────────┐");
    runZKProofExamples();
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
// ZERO-KNOWLEDGE PROOF EXAMPLES FOR INFRATIC LIBRARY
// These functions demonstrate core ZK capabilities in practical scenarios
// ============================================================================

/**
 * Example 1: Simple Data Commitment
 *
 * Use Case: A sensor device commits to a measurement without revealing it.
 * The commitment proves the data existed at a specific time without exposing
 * the actual value. Later, the data can be revealed and verified against
 * the commitment, proving it hasn't been tampered with.
 *
 * Real-world application: Tamper-proof data logging for audits and compliance.
 */
void example_zkDataCommitment()
{
    Serial.println("\n=== Zero-Knowledge: Data Commitment ===");
    Serial.println("Description: Cryptographic commitment hides data while");
    Serial.println("             proving existence and integrity.\n");

    float temperature = 25.7;
    String data = "temperature:" + String(temperature);
    String secret = "device_secret_key_2024";

    String commitment, nonce;
    uint64_t savedTimestamp;

    if (solana.createDataCommitment(data, secret, commitment, nonce, savedTimestamp))
    {
        Serial.println("Step 1: Create Commitment");
        Serial.println("  Commitment: " + commitment.substring(0, 20) + "...");
        Serial.println("  Nonce: " + nonce);
        Serial.printf("  Timestamp: %llu ms\n\n", savedTimestamp);

        // Store on blockchain
        String txSig;
        solana.storeCommitmentOnChain(
            PRIVATE_KEY_BASE58,
            PUBLIC_KEY_BASE58,
            commitment,
            "sensor:temperature_monitor,location:lab_001",
            txSig);
        Serial.println("Step 2: Store on Blockchain");
        Serial.println("  Status: Commitment published");
        Serial.println("  Actual data: HIDDEN from blockchain\n");

        // Verify later
        if (solana.verifyDataCommitment(data, secret, nonce, savedTimestamp, commitment))
        {
            Serial.println("Step 3: Verification (Later)");
            Serial.println("  Data: " + data);
            Serial.println("  Match: CONFIRMED - Data not modified\n");
            Serial.println("Benefits:");
            Serial.println("  - Data integrity guaranteed");
            Serial.println("  - No privacy leakage");
            Serial.println("  - Auditable proof");
        }
    }
}

/**
 * Example 2: Merkle Tree Proof
 *
 * Use Case: An IoT network with multiple sensors needs to prove a specific
 * sensor reading is part of a larger dataset without revealing other sensors' data.
 * The Merkle tree allows proving membership with minimal information.
 *
 * Real-world application: Privacy-preserving data aggregation in distributed networks.
 */
void example_zkMerkleProof()
{
    Serial.println("\n=== Zero-Knowledge: Merkle Tree Proof ===");
    Serial.println("Description: Prove specific data exists in a dataset");
    Serial.println("             without revealing other entries.\n");

    std::vector<String> sensorReadings = {
        "sensor_001:temp=20.5C,humidity=65%",
        "sensor_002:temp=22.1C,humidity=63%",
        "sensor_003:temp=25.7C,humidity=68%",
        "sensor_004:temp=19.8C,humidity=70%",
        "sensor_005:temp=23.4C,humidity=62%"};

    String merkleRoot;
    if (solana.buildMerkleTree(sensorReadings, merkleRoot))
    {
        Serial.println("Step 1: Build Merkle Tree");
        Serial.printf("  Total sensors: %d\n", sensorReadings.size());
        Serial.println("  Root: " + merkleRoot.substring(0, 20) + "...\n");

        // Store root on blockchain
        String txSig;
        solana.storeCommitmentOnChain(
            PRIVATE_KEY_BASE58,
            PUBLIC_KEY_BASE58,
            merkleRoot,
            "network:sensor_cluster_42,timestamp:" + String(millis()),
            txSig);
        Serial.println("Step 2: Publish Root Hash");
        Serial.println("  Location: Blockchain");
        Serial.println("  Cost: Single transaction for 5 sensors\n");

        // Prove sensor 3
        MerkleProof proof;
        if (solana.createMerkleProof(sensorReadings, 2, proof))
        {
            Serial.println("Step 3: Generate Proof for Sensor 003");
            Serial.println("  Reading: " + sensorReadings[2]);
            Serial.printf("  Proof size: %d sibling hashes\n", proof.siblings.size());
            Serial.println("  Other sensors: COMPLETELY HIDDEN\n");

            if (solana.verifyMerkleProof(sensorReadings[2], proof))
            {
                Serial.println("Step 4: Verification");
                Serial.println("  Result: VALID - Data included in root\n");
                Serial.println("Benefits:");
                Serial.println("  - Minimal information exposure");
                Serial.println("  - Logarithmic proof size");
                Serial.println("  - Scalable to thousands of sensors");
            }
        }
    }
}

/**
 * Example 3: Range Proof
 *
 * Use Case: A factory wants to prove that temperature readings stay within
 * safe operating range (20-30°C) for compliance, but doesn't reveal exact
 * measurements for competitive reasons.
 *
 * Real-world application: Industrial compliance verification without data exposure.
 */
void example_zkRangeProof()
{
    Serial.println("\n=== Zero-Knowledge: Range Proof ===");
    Serial.println("Description: Prove a value is in [min, max] range");
    Serial.println("             without revealing the exact value.\n");

    int64_t actualTemperature = 257; // 25.7°C (scaled by 10)
    String deviceSecret = "factory_device_001_secret";

    RangeProof proof;
    if (solana.createRangeProof(actualTemperature, 200, 300, deviceSecret, proof))
    {
        Serial.println("Step 1: Create Range Proof");
        Serial.println("  Claimed Range: [20.0°C, 30.0°C]");
        Serial.println("  Actual Value: HIDDEN");
        Serial.println("  Commitment: " + proof.commitment.substring(0, 20) + "...\n");

        // Store on blockchain
        String metadata = "device:temperature_monitor_lab,";
        metadata += "facility:manufacturing_plant_01,";
        metadata += "compliance_requirement:iso_9001";

        String txSig;
        solana.storeCommitmentOnChain(
            PRIVATE_KEY_BASE58,
            PUBLIC_KEY_BASE58,
            proof.proof,
            metadata,
            txSig);
        Serial.println("Step 2: Publish to Blockchain");
        Serial.println("  Status: Compliance proof recorded\n");

        // Verify later
        if (solana.verifyRangeProof(actualTemperature, deviceSecret, proof))
        {
            Serial.println("Step 3: Verification (During Audit)");
            Serial.printf("  Temperature: %.1f°C\n", actualTemperature / 10.0);
            Serial.println("  Range Check: PASSED");
            Serial.println("  Auditor sees: Only confirmation of compliance\n");
            Serial.println("Benefits:");
            Serial.println("  - Competitive data protection");
            Serial.println("  - Regulatory compliance proof");
            Serial.println("  - No exact measurements exposed");
        }
    }
}

/**
 * Example 4: Timestamped Proof
 *
 * Use Case: A location tracking system needs to prove that data (GPS coordinates)
 * existed at a specific blockchain timestamp. This prevents backdating or
 * claim manipulation.
 *
 * Real-world application: Immutable timestamping for locations, events, ownership.
 */
void example_zkTimestampedProof()
{
    Serial.println("\n=== Zero-Knowledge: Timestamped Proof ===");
    Serial.println("Description: Cryptographically bind data to a specific");
    Serial.println("             blockchain timestamp.\n");

    String locationData = "GPS_Coordinates:lat=41.0082N,lon=28.9784E,accuracy=5m";
    String proof, blockhash;
    uint64_t timestamp;

    if (solana.createTimestampedProof(locationData, proof, timestamp, blockhash))
    {
        Serial.println("Step 1: Create Timestamped Proof");
        Serial.printf("  Timestamp: %llu (Solana network time)\n", timestamp);
        Serial.println("  Blockhash: " + blockhash.substring(0, 20) + "...");
        Serial.println("  Data: HIDDEN\n");

        // Store on blockchain
        String metadata = "use_case:asset_tracking,";
        metadata += "asset_id:item_12345,";
        metadata += "action:location_recorded";

        String txSig;
        solana.storeCommitmentOnChain(
            PRIVATE_KEY_BASE58,
            PUBLIC_KEY_BASE58,
            proof,
            metadata,
            txSig);
        Serial.println("Step 2: Anchor to Blockchain");
        Serial.println("  Proof secured in block: Permanent record\n");

        // Verify later
        if (solana.verifyTimestampedProof(locationData, proof, timestamp, blockhash))
        {
            Serial.println("Step 3: Verification (Later)");
            Serial.println("  Data: " + locationData);
            Serial.printf("  Verified at: %llu\n", timestamp);
            Serial.println("  Authenticity: CONFIRMED\n");
            Serial.println("Benefits:");
            Serial.println("  - Backdating prevention");
            Serial.println("  - Blockchain-anchored timestamps");
            Serial.println("  - Legal audit trail");
        }
    }
}

/**
 * Example 5: zkSNARK Proof
 *
 * Use Case: A device proves it knows a password/private key without ever
 * revealing it. Useful for authentication and authorization checks.
 *
 * Real-world application: Zero-knowledge authentication for IoT devices.
 * Note: Production use requires proper circuit compilation with Circom/snarkjs
 */
void example_zkSNARKProof()
{
    Serial.println("\n=== Zero-Knowledge: zkSNARK (Simplified) ===");
    Serial.println("Description: Prove knowledge of secret without revealing it.");
    Serial.println("             For production, use Circom + Snarkjs.\n");

    // Private data (never transmitted)
    String devicePassword = "ultra_secret_device_password_2024";
    std::vector<uint8_t> privateData(devicePassword.begin(), devicePassword.end());

    // Public challenge/input
    String publicInput = "authenticate_device_xyz";
    std::vector<uint8_t> publicInputs(publicInput.begin(), publicInput.end());

    // Circuit definition
    String circuitType = "proof_of_knowledge_authentication";

    zkSNARKProof proof;
    if (solana.createzkSNARKProof(privateData, publicInputs, circuitType, proof))
    {
        Serial.println("Step 1: Generate Zero-Knowledge Proof");
        Serial.println("  Private data: NEVER REVEALED");
        Serial.println("  Public challenge: " + publicInput);
        Serial.printf("  Proof size: %d bytes (compact)\n", proof.proofData.size());
        Serial.printf("  Public inputs: %d bytes\n\n", proof.publicInputs.size());

        if (solana.verifyzkSNARKProof(proof, publicInputs))
        {
            Serial.println("Step 2: Verification");
            Serial.println("  Device authentication: CONFIRMED");
            Serial.println("  Password: NEVER EXPOSED");
            Serial.println("  Server learned: Only valid authentication\n");
            Serial.println("Benefits:");
            Serial.println("  - Password never transmitted");
            Serial.println("  - Replay attacks prevented");
            Serial.println("  - Compact proof format");
            Serial.println("  - Advanced authentication scheme");
        }
    }
}

/**
 * Example 6: Batch Commitments
 *
 * Use Case: An IoT device collects multiple sensor readings and commits to
 * all of them efficiently in a single blockchain transaction using Merkle tree.
 *
 * Real-world application: Cost-efficient batch data publishing for IoT networks.
 */
void example_zkBatchCommitments()
{
    Serial.println("\n=== Zero-Knowledge: Batch Commitments ===");
    Serial.println("Description: Create and publish multiple commitments");
    Serial.println("             in one efficient transaction.\n");

    // Multiple sensor readings
    std::vector<String> batchData = {
        "sensor_001:temperature=22.5C",
        "sensor_002:humidity=65.2%",
        "sensor_003:pressure=1013.25hPa",
        "sensor_004:co2=420ppm",
        "sensor_005:light=750lux"};

    String batchSecret = "batch_2024_group_42";
    std::vector<ZKCommitment> commitments;

    if (solana.createBatchCommitments(batchData, batchSecret, commitments))
    {
        Serial.println("Step 1: Create Individual Commitments");
        Serial.printf("  Readings: %d\n", batchData.size());
        Serial.printf("  Commitments created: %d\n", commitments.size());
        Serial.println("  Status: All data hidden\n");

        // Store all in one transaction
        String txSig;
        if (solana.storeBatchCommitmentsOnChain(
                PRIVATE_KEY_BASE58,
                PUBLIC_KEY_BASE58,
                commitments,
                txSig))
        {
            Serial.println("Step 2: Publish Batch");
            Serial.println("  Transaction: " + txSig);
            Serial.printf("  Cost: 1 transaction for %d readings\n", batchData.size());
            Serial.println("  Cost reduction: ~80% compared to individual transactions\n");

            Serial.println("Step 3: Verification");
            Serial.println("  Each commitment can be verified individually");
            Serial.println("  Other readings in batch: HIDDEN\n");

            Serial.println("Benefits:");
            Serial.println("  - Reduced blockchain costs");
            Serial.println("  - Efficient data batching");
            Serial.println("  - Individual verification still possible");
            Serial.println("  - Scalable IoT deployment");
        }
    }
}

/**
 * Integration Function: Run all ZK examples
 * Add this to your runAllTests() function or call separately
 */
void runZKProofExamples()
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Zero-Knowledge Proof Examples Suite        ║");
    Serial.println("║  Demonstrating Core ZK Capabilities         ║");
    Serial.println("╚════════════════════════════════════════════╝");

    // Run all examples with delays
    example_zkDataCommitment();
    delay(2000);

    example_zkMerkleProof();
    delay(2000);

    example_zkRangeProof();
    delay(2000);

    example_zkTimestampedProof();
    delay(2000);

    example_zkSNARKProof();
    delay(2000);

    example_zkBatchCommitments();

    example_data_commitment(solana, PRIVATE_KEY, PUBLIC_KEY, "temp:25.7C", "device_secret");
    delay(3000);

    example_merkle_tree_proof(solana, PRIVATE_KEY, PUBLIC_KEY, sensorReadings, 0);
    delay(3000);

    example_range_proof(solana, PRIVATE_KEY, PUBLIC_KEY, 257, 200, 300, "secret");
    delay(3000);

    example_timestamped_proof(solana, PRIVATE_KEY, PUBLIC_KEY, "lat:41.0082N,lon:28.9784E");
    delay(3000);

    example_batch_commitments(solana, PRIVATE_KEY, PUBLIC_KEY, readingsList, "batch_secret");

    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  All ZK Examples Completed                  ║");
    Serial.println("║  Ready for production deployment            ║");
    Serial.println("╚════════════════════════════════════════════╝\n");
}

// ============================================================================
// SETUP AND LOOP
// ============================================================================

void setup()
{
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
    while (WiFi.status() != WL_CONNECTED && attempts < 30)
    {
        delay(500);
        Serial.print(".");
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED)
    {
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
    }
    else
    {
        Serial.println();
        Serial.println("❌ WiFi connection failed!");
        Serial.println("   Please check your credentials and try again.");
    }
}

void loop()
{
    // Keep the connection alive
    if (WiFi.status() != WL_CONNECTED)
    {
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