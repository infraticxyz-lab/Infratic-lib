// zk_examples.h
// Examples for the commitment, Merkle and attestation helpers of Infratic.
//
// Read this first: none of these is zero-knowledge in the cryptographic sense.
//  - a commitment hides data (while its secret is private) and binds you to it
//  - a Merkle proof shows that one item belongs to a set with a known root
//  - an attestation is an Ed25519 signature: it shows WHO says something, not that it is true
// For real zkSNARKs or range proofs use a proof system (circom/snarkjs, Bulletproofs) off the device.

#ifndef ZK_EXAMPLES_H
#define ZK_EXAMPLES_H

#include "Infratic-lib.h"

// 1. Commit to a reading, publish only the commitment, open it later.
void example_data_commitment(Infratic &solana, const String &privateKey, const String &publicKey,
                             const String &sensorData)
{
    String commitment, secret;
    if (!Infratic::commitString(sensorData, commitment, secret))
        return;
    // keep `secret` private (e.g. in NVS); the chain only sees the commitment
    String txSig;
    if (!solana.storeCommitmentOnChain(privateKey, publicKey, commitment, "sensor:temp_001", txSig))
    {
        Serial.println("could not store the commitment");
        return;
    }
    Serial.println("Commitment " + commitment + " in tx " + txSig);

    // later, to an auditor: reveal data + secret, they recompute the hash
    bool ok = Infratic::verifyCommitmentString(sensorData, secret, commitment);
    Serial.println(ok ? "opening matches the commitment" : "opening does NOT match");
    // The block time of txSig is the time the commitment existed at the latest.
}

// 2. Publish one Merkle root for many readings, prove a single one later.
void example_merkle_tree_proof(Infratic &solana, const String &privateKey, const String &publicKey,
                               const std::vector<String> &readings, size_t index)
{
    String root;
    if (!Infratic::buildMerkleTree(readings, root))
        return;
    String txSig;
    solana.storeCommitmentOnChain(privateKey, publicKey, root, "n:" + String((unsigned long)readings.size()), txSig);

    MerkleProof proof;
    if (!Infratic::createMerkleProof(readings, index, proof))
        return;
    // The verifier takes the root from a source it trusts (the chain), NOT from the proof.
    // The proof contains log2(n) hashes; it does not contain the other readings, but the
    // sibling hashes of unrelated readings are visible. Readings with little entropy can be guessed:
    // commit to them with a secret first (example 1) and use the commitments as leaves.
    bool ok = Infratic::verifyMerkleProof(readings[index], proof, root);
    Serial.println(ok ? "reading is part of the published root" : "proof invalid");
}

// 3. "Value is in range" as a signed claim (NOT a cryptographic range proof).
void example_range_attestation(const Keypair &device, int64_t value, int64_t minValue, int64_t maxValue)
{
    RangeAttestation att;
    std::vector<uint8_t> secret;
    if (!Infratic::createRangeAttestation(device, value, minValue, maxValue, att, secret))
        return; // value outside the range: the device refuses to sign
    // send `att` to the verifier. They see commitment + range + signature, not the value.
    // They must trust the device key (att.signer) that the claim is true.
    bool ok = Infratic::verifyRangeAttestation(att, device.publicBase58());
    Serial.println(ok ? "signed range claim is valid" : "invalid");
    // during an audit the value and secret can be revealed and checked:
    ok = Infratic::openRangeAttestation(att, value, secret, device.publicBase58());
    Serial.println(ok ? "opening matches the commitment and the range" : "opening invalid");
}

// 4. Signed timestamp: the device key vouches for "hash of this data, at this cluster time".
void example_signed_timestamp(Infratic &solana, const Keypair &device, const String &data)
{
    std::vector<uint8_t> bytes((const uint8_t *)data.c_str(), (const uint8_t *)data.c_str() + data.length());
    SignedTimestamp ts;
    if (!solana.createSignedTimestamp(device, bytes, ts))
    {
        Serial.println("cluster time unavailable");
        return;
    }
    // Only as trustworthy as the device and its RPC node. For a time nobody has to trust,
    // publish the hash on chain (example 1) and use that transaction's block time.
    bool ok = Infratic::verifySignedTimestamp(ts, bytes, device.publicBase58());
    Serial.println(ok ? "timestamp signature valid, unix time " + String((long)ts.unixTime) : "invalid");
}

// 5. Commitment attestation (replaces the old "zkSNARK" placeholder).
void example_commitment_attestation(const Keypair &device, const String &commitmentHex)
{
    CommitmentAttestation att;
    std::vector<uint8_t> pub = {'o', 'k'};
    if (!Infratic::createCommitmentAttestation(device, commitmentHex, "temp-sensor/v1", pub, att))
        return;
    // Anyone with the device public key can check it. It proves the device vouched for this
    // commitment and these public values; it proves nothing about the hidden data.
    bool ok = Infratic::verifyCommitmentAttestation(att, device.publicBase58());
    Serial.println(ok ? "attestation valid" : "attestation invalid");
}

// 6. Batch: one commitment per reading, one transaction for the Merkle root over all of them.
void example_batch_commitments(Infratic &solana, const String &privateKey, const String &publicKey,
                               const std::vector<String> &readings)
{
    std::vector<ZKCommitment> commitments;
    if (!solana.createBatchCommitments(readings, "", commitments))
        return;
    // store commitments[i].nonce (the opening secret of reading i) privately
    String txSig;
    if (solana.storeBatchCommitmentsOnChain(privateKey, publicKey, commitments, txSig))
        Serial.println("Merkle root of " + String((unsigned long)commitments.size()) + " commitments in tx " + txSig);
}

#endif
