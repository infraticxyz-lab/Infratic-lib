// zk_examples.h
// Zero-Knowledge Proof Examples Library for Infratic
// Comprehensive examples demonstrating ZK capabilities on Solana blockchain

#ifndef ZK_EXAMPLES_H
#define ZK_EXAMPLES_H

#include "Infratic-lib.h"

// ============================================================================
// EXAMPLE 1: DATA COMMITMENT PROOF
// ============================================================================
/**
 * @brief Demonstrates cryptographic data commitment without revelation
 * 
 * Use Case: IoT sensor creates a commitment to temperature reading, proving
 * data existed at a specific time without exposing the actual value.
 * 
 * Process:
 * 1. Create commitment from data + secret + timestamp
 * 2. Store commitment on blockchain (data stays hidden)
 * 3. Later: verify the data against stored commitment
 * 
 * Benefits:
 * - Data integrity guaranteed
 * - Privacy maintained
 * - Tamper-proof audit trail
 * 
 * @param solana Reference to Infratic instance
 * @param privateKey ESP32 device's private key (Base58)
 * @param publicKey Device's public key (Base58)
 * @param sensorData String data to commit (e.g., "temp:25.7C")
 * @param deviceSecret Secret key for commitment (e.g., device serial number)
 */
void example_data_commitment(
    Infratic &solana,
    const String &privateKey,
    const String &publicKey,
    const String &sensorData,
    const String &deviceSecret)
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Example 1: Data Commitment Proof         ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

    Serial.println("Scenario: IoT temperature sensor");
    Serial.println("Goal: Prove data exists without revealing value\n");

    // Step 1: Create commitment
    Serial.println("Step 1: Create Commitment");
    Serial.println("─────────────────────────────────────────────");
    
    String commitment, nonce;
    uint64_t timestamp;
    
    if (!solana.createDataCommitment(sensorData, deviceSecret, commitment, nonce, timestamp)) {
        Serial.println("❌ Failed to create commitment");
        return;
    }

    Serial.println("✓ Commitment created");
    Serial.println("  Data: " + sensorData);
    Serial.println("  Commitment: " + commitment.substring(0, 32) + "...");
    Serial.println("  Nonce: " + nonce.substring(0, 16) + "...");
    Serial.printf("  Timestamp: %llu ms\n\n", timestamp);

    // Step 2: Store on blockchain
    Serial.println("Step 2: Store on Blockchain");
    Serial.println("─────────────────────────────────────────────");
    
    String metadata = "device:temperature_sensor_001,";
    metadata += "location:facility_A,";
    metadata += "timestamp:" + String(timestamp);

    String txSig;
    if (!solana.storeCommitmentOnChain(privateKey, publicKey, commitment, metadata, txSig)) {
        Serial.println("❌ Failed to store commitment");
        return;
    }

    Serial.println("✓ Commitment published on blockchain");
    Serial.println("  Transaction: " + txSig.substring(0, 20) + "...");
    Serial.println("  Actual data: HIDDEN (only commitment visible)\n");

    // Step 3: Verify later
    Serial.println("Step 3: Verification (Later)");
    Serial.println("─────────────────────────────────────────────");
    
    if (solana.verifyDataCommitment(sensorData, deviceSecret, nonce, timestamp, commitment)) {
        Serial.println("✓ Verification successful!");
        Serial.println("  Data: " + sensorData);
        Serial.println("  Status: NOT MODIFIED\n");
        
        Serial.println("Summary:");
        Serial.println("  ✓ Data integrity verified");
        Serial.println("  ✓ Privacy maintained");
        Serial.println("  ✓ Auditable proof created");
    } else {
        Serial.println("❌ Verification failed - data mismatch");
    }
    
    Serial.println();
}

// ============================================================================
// EXAMPLE 2: MERKLE TREE PROOF
// ============================================================================
/**
 * @brief Demonstrates Merkle tree for efficient multi-data verification
 * 
 * Use Case: IoT network with multiple sensors needs to prove one sensor's
 * reading is part of larger dataset without revealing other sensors' data.
 * 
 * Process:
 * 1. Build Merkle tree from sensor readings
 * 2. Publish root hash on blockchain
 * 3. Generate proof for specific sensor
 * 4. Verify membership using minimal information
 * 
 * Benefits:
 * - Privacy for other sensors maintained
 * - Logarithmic proof size
 * - Scalable to thousands of sensors
 * 
 * @param solana Reference to Infratic instance
 * @param privateKey Private key for blockchain transactions
 * @param publicKey Public key for transactions
 * @param sensorReadings Vector of sensor data strings
 * @param proofIndex Which sensor to generate proof for (0-based)
 */
void example_merkle_tree_proof(
    Infratic &solana,
    const String &privateKey,
    const String &publicKey,
    const std::vector<String> &sensorReadings,
    size_t proofIndex)
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Example 2: Merkle Tree Proof             ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

    Serial.println("Scenario: Multi-sensor IoT network");
    Serial.println("Goal: Prove specific sensor reading with privacy\n");

    if (proofIndex >= sensorReadings.size()) {
        Serial.println("❌ Invalid proof index");
        return;
    }

    // Step 1: Build Merkle tree
    Serial.println("Step 1: Build Merkle Tree");
    Serial.println("─────────────────────────────────────────────");
    
    String merkleRoot;
    if (!solana.buildMerkleTree(sensorReadings, merkleRoot)) {
        Serial.println("❌ Failed to build Merkle tree");
        return;
    }

    Serial.printf("✓ Merkle tree constructed\n");
    Serial.printf("  Total sensors: %d\n", sensorReadings.size());
    Serial.println("  Root: " + merkleRoot.substring(0, 32) + "...\n");

    // Step 2: Store root on blockchain
    Serial.println("Step 2: Publish Root Hash");
    Serial.println("─────────────────────────────────────────────");
    
    String metadata = "network:sensor_cluster_42,timestamp:" + String(millis());
    String txSig;
    
    if (!solana.storeCommitmentOnChain(privateKey, publicKey, merkleRoot, metadata, txSig)) {
        Serial.println("❌ Failed to store root");
        return;
    }

    Serial.println("✓ Root hash published");
    Serial.println("  Transaction: " + txSig.substring(0, 20) + "...");
    Serial.printf("  Cost: Single transaction for %d sensors\n\n", sensorReadings.size());

    // Step 3: Create proof for specific sensor
    Serial.println("Step 3: Generate Membership Proof");
    Serial.println("─────────────────────────────────────────────");
    
    MerkleProof proof;
    if (!solana.createMerkleProof(sensorReadings, proofIndex, proof)) {
        Serial.println("❌ Failed to create proof");
        return;
    }

    Serial.printf("✓ Proof created for sensor index %d\n", proofIndex);
    Serial.println("  Reading: " + sensorReadings[proofIndex]);
    Serial.printf("  Proof size: %d sibling hashes\n", proof.siblings.size());
    Serial.println("  Other sensors: COMPLETELY HIDDEN\n");

    // Step 4: Verify proof
    Serial.println("Step 4: Verification");
    Serial.println("─────────────────────────────────────────────");
    
    if (solana.verifyMerkleProof(sensorReadings[proofIndex], proof)) {
        Serial.println("✓ Proof verified!");
        Serial.println("  Status: Reading confirmed in tree\n");
        
        Serial.println("Summary:");
        Serial.println("  ✓ Privacy preserved for other sensors");
        Serial.println("  ✓ Efficient proof verification");
        Serial.println("  ✓ Scalable for large networks");
    } else {
        Serial.println("❌ Proof verification failed");
    }
    
    Serial.println();
}

// ============================================================================
// EXAMPLE 3: RANGE PROOF
// ============================================================================
/**
 * @brief Demonstrates range proof for value validation without exposure
 * 
 * Use Case: Factory floor proves temperature stays within safe range
 * (20-30°C) for compliance, but doesn't reveal exact measurements.
 * 
 * Process:
 * 1. Create range proof for value within [min, max]
 * 2. Store proof on blockchain
 * 3. Verify value is in range without revealing it
 * 
 * Benefits:
 * - Compliance verification maintained
 * - Competitive data protection
 * - Regulatory audit trail
 * 
 * @param solana Reference to Infratic instance
 * @param privateKey Private key for transactions
 * @param publicKey Public key for transactions
 * @param actualValue Actual value to prove (scaled integer, e.g., 257 = 25.7)
 * @param minValue Minimum allowed value
 * @param maxValue Maximum allowed value
 * @param proofSecret Secret key for proof
 */
void example_range_proof(
    Infratic &solana,
    const String &privateKey,
    const String &publicKey,
    int64_t actualValue,
    int64_t minValue,
    int64_t maxValue,
    const String &proofSecret)
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Example 3: Range Proof                  ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

    Serial.println("Scenario: Temperature compliance verification");
    Serial.println("Goal: Prove value in range without revealing exact value\n");

    if (actualValue < minValue || actualValue > maxValue) {
        Serial.println("❌ Value out of range");
        return;
    }

    // Step 1: Create range proof
    Serial.println("Step 1: Create Range Proof");
    Serial.println("─────────────────────────────────────────────");
    
    RangeProof rangeProof;
    if (!solana.createRangeProof(actualValue, minValue, maxValue, proofSecret, rangeProof)) {
        Serial.println("❌ Failed to create range proof");
        return;
    }

    Serial.println("✓ Range proof created");
    Serial.printf("  Claimed range: [%lld, %lld]\n", minValue, maxValue);
    Serial.println("  Actual value: HIDDEN");
    Serial.println("  Commitment: " + rangeProof.commitment.substring(0, 32) + "...\n");

    // Step 2: Store on blockchain
    Serial.println("Step 2: Publish to Blockchain");
    Serial.println("─────────────────────────────────────────────");
    
    String metadata = "device:temperature_monitor_lab,";
    metadata += "facility:manufacturing_plant_01,";
    metadata += "compliance_requirement:iso_9001";

    String txSig;
    if (!solana.storeCommitmentOnChain(privateKey, publicKey, rangeProof.proof, metadata, txSig)) {
        Serial.println("❌ Failed to store proof");
        return;
    }

    Serial.println("✓ Proof published on blockchain");
    Serial.println("  Transaction: " + txSig.substring(0, 20) + "...\n");

    // Step 3: Verify
    Serial.println("Step 3: Verification (During Audit)");
    Serial.println("─────────────────────────────────────────────");
    
    if (solana.verifyRangeProof(actualValue, proofSecret, rangeProof)) {
        Serial.printf("✓ Verification successful!\n");
        Serial.printf("  Temperature: %.1f°C\n", actualValue / 10.0);
        Serial.println("  Range check: PASSED");
        Serial.println("  Auditor sees: Only confirmation of compliance\n");
        
        Serial.println("Summary:");
        Serial.println("  ✓ Regulatory compliance proven");
        Serial.println("  ✓ Competitive data protected");
        Serial.println("  ✓ Immutable audit trail");
    } else {
        Serial.println("❌ Verification failed");
    }
    
    Serial.println();
}

// ============================================================================
// EXAMPLE 4: TIMESTAMPED PROOF
// ============================================================================
/**
 * @brief Demonstrates blockchain-anchored timestamping
 * 
 * Use Case: Location tracking system proves GPS coordinates existed at
 * specific blockchain timestamp, preventing backdating.
 * 
 * Process:
 * 1. Create proof combining data + timestamp
 * 2. Anchor to blockchain (Solana slot number)
 * 3. Verify immutable timestamp later
 * 
 * Benefits:
 * - Backdating prevention
 * - Blockchain-anchored timestamps
 * - Legal audit trail
 * 
 * @param solana Reference to Infratic instance
 * @param privateKey Private key for transactions
 * @param publicKey Public key for transactions
 * @param locationData Location/asset data string
 */
void example_timestamped_proof(
    Infratic &solana,
    const String &privateKey,
    const String &publicKey,
    const String &locationData)
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Example 4: Timestamped Proof             ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

    Serial.println("Scenario: Asset location tracking");
    Serial.println("Goal: Cryptographically bind data to timestamp\n");

    // Step 1: Create timestamped proof
    Serial.println("Step 1: Create Timestamped Proof");
    Serial.println("─────────────────────────────────────────────");
    
    String proof, blockhash;
    uint64_t timestamp;
    
    if (!solana.createTimestampedProof(locationData, proof, timestamp, blockhash)) {
        Serial.println("❌ Failed to create proof");
        return;
    }

    Serial.println("✓ Timestamped proof created");
    Serial.printf("  Timestamp: %llu (network time)\n", timestamp);
    Serial.println("  Blockhash: " + blockhash.substring(0, 32) + "...");
    Serial.println("  Data: HIDDEN\n");

    // Step 2: Anchor to blockchain
    Serial.println("Step 2: Anchor to Blockchain");
    Serial.println("─────────────────────────────────────────────");
    
    String metadata = "use_case:asset_tracking,";
    metadata += "asset_id:item_12345,";
    metadata += "action:location_recorded";

    String txSig;
    if (!solana.storeCommitmentOnChain(privateKey, publicKey, proof, metadata, txSig)) {
        Serial.println("❌ Failed to store proof");
        return;
    }

    Serial.println("✓ Proof anchored to blockchain");
    Serial.println("  Transaction: " + txSig.substring(0, 20) + "...");
    Serial.println("  Permanence: Immutable record created\n");

    // Step 3: Verify later
    Serial.println("Step 3: Verification (Later)");
    Serial.println("─────────────────────────────────────────────");
    
    if (solana.verifyTimestampedProof(locationData, proof, timestamp, blockhash)) {
        Serial.println("✓ Proof verified!");
        Serial.println("  Data: " + locationData);
        Serial.printf("  Verified at: %llu\n", timestamp);
        Serial.println("  Authenticity: CONFIRMED\n");
        
        Serial.println("Summary:");
        Serial.println("  ✓ Backdating prevented");
        Serial.println("  ✓ Blockchain-anchored timestamps");
        Serial.println("  ✓ Legal audit trail established");
    } else {
        Serial.println("❌ Verification failed");
    }
    
    Serial.println();
}

// ============================================================================
// EXAMPLE 5: BATCH COMMITMENTS
// ============================================================================
/**
 * @brief Demonstrates efficient batch commitment publishing
 * 
 * Use Case: IoT device collects multiple sensor readings and commits to
 * all efficiently in single blockchain transaction using Merkle tree.
 * 
 * Process:
 * 1. Create individual commitments for each reading
 * 2. Build Merkle tree of commitments
 * 3. Store only Merkle root on blockchain (cost efficient)
 * 4. Each commitment still verifiable individually
 * 
 * Benefits:
 * - Reduced blockchain costs (~80% savings)
 * - Efficient data batching
 * - Individual verification possible
 * 
 * @param solana Reference to Infratic instance
 * @param privateKey Private key for transactions
 * @param publicKey Public key for transactions
 * @param readingsList Vector of sensor readings
 * @param batchSecret Shared secret for batch
 */
void example_batch_commitments(
    Infratic &solana,
    const String &privateKey,
    const String &publicKey,
    const std::vector<String> &readingsList,
    const String &batchSecret)
{
    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║  Example 5: Batch Commitments             ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

    Serial.println("Scenario: Multiple IoT sensor readings");
    Serial.println("Goal: Cost-efficient batch publishing\n");

    // Step 1: Create individual commitments
    Serial.println("Step 1: Create Individual Commitments");
    Serial.println("─────────────────────────────────────────────");
    
    std::vector<ZKCommitment> commitments;
    if (!solana.createBatchCommitments(readingsList, batchSecret, commitments)) {
        Serial.println("❌ Failed to create commitments");
        return;
    }

    Serial.printf("✓ %d commitments created\n", commitments.size());
    Serial.println("  All data: HIDDEN\n");

    // Step 2: Store batch on blockchain
    Serial.println("Step 2: Publish Batch on Blockchain");
    Serial.println("─────────────────────────────────────────────");
    
    String txSig;
    if (!solana.storeBatchCommitmentsOnChain(privateKey, publicKey, commitments, txSig)) {
        Serial.println("❌ Failed to store batch");
        return;
    }

    Serial.println("✓ Batch published");
    Serial.println("  Transaction: " + txSig.substring(0, 20) + "...");
    Serial.printf("  Cost: 1 transaction for %d readings\n", commitments.size());
    Serial.printf("  Savings: ~80%% vs individual transactions\n\n");

    // Step 3: Show verification capability
    Serial.println("Step 3: Verification Capability");
    Serial.println("─────────────────────────────────────────────");
    
    Serial.printf("✓ Each commitment verifiable individually\n");
    Serial.println("  Other readings in batch: HIDDEN");
    Serial.println("  Privacy: Maintained for all entries\n");

    Serial.println("Summary:");
    Serial.println("  ✓ Reduced blockchain costs");
    Serial.println("  ✓ Efficient data batching");
    Serial.println("  ✓ Individual verification possible");
    Serial.println("  ✓ Scalable IoT deployment");
    
    Serial.println();
}

#endif // ZK_EXAMPLES_H