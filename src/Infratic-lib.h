#ifndef INFRATIC_LIB_H
#define INFRATIC_LIB_H

#include <Arduino.h>
#include <vector>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <Ed25519.h>
#include <SHA512.h>

#include "base58.h"

// Forward declarations
std::vector<uint8_t> base58ToPubkey(const String& base58Str);
std::vector<uint8_t> encodeU64LE(uint64_t value);

// ============================================================================
// STRUCTURES
// ============================================================================

struct EpochInfo {
    uint64_t absoluteSlot;
    uint64_t blockHeight;
    uint64_t epoch;
    uint64_t slotIndex;
    uint64_t slotsInEpoch;
};

struct Pubkey {
    std::vector<uint8_t> data;
    static Pubkey fromBase58(const String& str);
};

struct Keypair {
    Pubkey pubkey_;
    std::vector<uint8_t> privkey;
    
    static Keypair fromPrivateKey(const uint8_t* key64);
    const Pubkey& pubkey() const;
};

struct AccountMeta {
    Pubkey pubkey;
    bool isSigner;
    bool isWritable;
    
    static AccountMeta signer(const Pubkey& key);
    static AccountMeta writable(const Pubkey& key, bool isSigner = false);
};

struct Instruction {
    Pubkey programId;
    std::vector<AccountMeta> accounts;
    std::vector<uint8_t> data;
    
    Instruction(const Pubkey& pid, const std::vector<AccountMeta>& accts, const std::vector<uint8_t>& d);
};

struct Transaction {
    String recent_blockhash;
    Pubkey fee_payer;
    std::vector<Instruction> instructions;
    std::vector<uint8_t> signature;
    
    void add(const Instruction& ix);
    std::vector<uint8_t> serializeMessage() const;
    void sign(const std::vector<Keypair>& signers);
    String serializeBase64() const;
};

// ============================================================================
// MAIN LIBRARY CLASS
// ============================================================================

class Infratic {
public:
    explicit Infratic(const String& rpcUrl);
    
    // ========================================================================
    // BLOCKCHAIN QUERIES
    // ========================================================================
    
    /**
     * @brief Fetches the latest blockhash from Solana cluster
     * @return Latest blockhash in Base58 format, or empty string on failure
     */
    String getLatestBlockhash();
    
    /**
     * @brief Gets the current block height
     * @param outBlockHeight Output parameter for block height
     * @return true if successful
     */
    bool getBlockHeight(uint64_t& outBlockHeight);
    
    /**
     * @brief Gets current epoch information
     * @param outEpochInfo Output parameter for epoch data
     * @return true if successful
     */
    bool getEpochInfo(EpochInfo& outEpochInfo);
    
    // ========================================================================
    // BALANCE QUERIES
    // ========================================================================
    
    /**
     * @brief Gets SOL balance for a wallet
     * @param walletPubkeyBase58 Wallet public key in Base58
     * @param outLamports Output parameter for balance in lamports
     * @return true if successful
     */
    bool getSolBalance(const String& walletPubkeyBase58, uint64_t& outLamports);
    
    /**
     * @brief Gets SPL token balance for a wallet
     * @param walletPubkeyBase58 Wallet public key in Base58
     * @param tokenMintBase58 Token mint address in Base58
     * @param outBalance Output parameter for token balance
     * @return true if successful
     */
    bool getSplTokenBalance(const String& walletPubkeyBase58, const String& tokenMintBase58, uint64_t& outBalance);
    
    /**
     * @brief Gets token decimals from mint
     * @param mintPubkeyBase58 Token mint address in Base58
     * @param outDecimals Output parameter for decimals
     * @return true if successful
     */
    bool getTokenDecimals(const String& mintPubkeyBase58, uint8_t& outDecimals);
    
    // ========================================================================
    // TOKEN ACCOUNT OPERATIONS
    // ========================================================================
    
    /**
     * @brief Finds Associated Token Account for owner and mint
     * @param ownerPubkeyBase58 Owner's public key in Base58
     * @param mintPubkeyBase58 Token mint's public key in Base58
     * @param outATA Output parameter for ATA address
     * @return true if ATA found
     */
    bool findAssociatedTokenAccount(const String& ownerPubkeyBase58, const String& mintPubkeyBase58, String& outATA);
    
    // ========================================================================
    // TRANSACTION OPERATIONS
    // ========================================================================
    
    /**
     * @brief Sends SOL transfer transaction
     * @param privateKeyBase58 Sender's private key in Base58
     * @param fromPubkeyBase58 Sender's public key in Base58
     * @param toPubkeyBase58 Recipient's public key in Base58
     * @param lamports Amount to transfer
     * @return true if successful
     */
    bool sendSol(const String& privateKeyBase58, const String& fromPubkeyBase58, 
                 const String& toPubkeyBase58, uint64_t lamports);
    
    /**
     * @brief Sends program data transaction (memo or custom)
     * @param privateKeyBase58 Sender's private key in Base58
     * @param fromPubkeyBase58 Sender's public key in Base58
     * @param programIdBase58 Target program ID in Base58
     * @param dataString Data to send
     * @param confirmWaitMs Milliseconds to wait for confirmation
     * @return true if successful
     */
    bool sendProgramDataTransaction(const String& privateKeyBase58, const String& fromPubkeyBase58,
                                   const String& programIdBase58, const String& dataString, 
                                   uint32_t confirmWaitMs = 5000);
    
    /**
     * @brief Sends raw transaction to network
     * @param txBase64 Base64 encoded transaction
     * @param outSignature Output parameter for transaction signature
     * @return true if successful
     */
    bool sendRawTransaction(const String& txBase64, String& outSignature);
    
    /**
     * @brief Confirms transaction on blockchain
     * @param signature Transaction signature in Base58
     * @param maxWaitMs Maximum wait time in milliseconds
     * @return true if confirmed
     */
    bool confirmTransaction(const String& signature, uint32_t maxWaitMs = 5000);
    
    // ========================================================================
    // CRYPTOGRAPHIC OPERATIONS
    // ========================================================================
    
    /**
     * @brief Signs message with Base58-encoded private key
     * @param message Message bytes to sign
     * @param privateKeyBase58 Private key in Base58
     * @param outSignature Output buffer for 64-byte signature
     * @return true if successful
     */
    bool signMessageFromBase58(const std::vector<uint8_t>& message, const String& privateKeyBase58, 
                               uint8_t outSignature[64]);
    
    /**
     * @brief Signs message with raw binary private key
     * @param message Message bytes to sign
     * @param privateKey 64-byte private key vector
     * @param outSignature Output buffer for 64-byte signature
     * @return true if successful
     */
    bool signMessageRaw(const std::vector<uint8_t>& message, const std::vector<uint8_t>& privateKey, 
                       uint8_t outSignature[64]);
    
    // ========================================================================
    // PDA OPERATIONS
    // ========================================================================
    
    /**
     * @brief Derives Program Derived Address
     * @param seeds Vector of seed byte arrays
     * @param programIdBase58 Program ID in Base58
     * @param outPDABase58 Output parameter for PDA in Base58
     * @param outBump Output parameter for bump seed
     * @return true if successful
     */
    bool derivePDA(const std::vector<std::vector<uint8_t>>& seeds, const String& programIdBase58,
                   String& outPDABase58, uint8_t& outBump);
    
    /**
     * @brief Low-level PDA derivation
     * @param seeds Vector of seed byte arrays
     * @param programId 32-byte program ID
     * @param outPDA Output parameter for 32-byte PDA
     * @param outBump Output parameter for bump seed
     * @return true if successful
     */
    bool findProgramAddress(const std::vector<std::vector<uint8_t>>& seeds, 
                           const std::vector<uint8_t>& programId,
                           std::vector<uint8_t>& outPDA, uint8_t& outBump);
    
    // ========================================================================
    // ANCHOR FRAMEWORK SUPPORT
    // ========================================================================
    
    /**
     * @brief Calculates Anchor instruction discriminator
     * @param functionName Name of the Anchor function
     * @return 8-byte discriminator vector
     */
    std::vector<uint8_t> calculateDiscriminator(const std::string& functionName);
    
    // ========================================================================
    // UTILITY FUNCTIONS
    // ========================================================================
    
    /**
     * @brief Encodes data to Base64
     * @param data Pointer to data buffer
     * @param len Length of data
     * @return Base64 encoded string
     */
    String base64Encode(const uint8_t* data, size_t len);

private:
    String _rpcUrl;
    
    // Internal transaction building functions
    bool buildAndSignTransaction(const uint8_t* privateKey, size_t privLen,
                                const uint8_t* fromPub, const uint8_t* toPub,
                                uint64_t lamports, const String& recentBlockhash,
                                String& outTxBase64);
    
    bool buildAndSignMemoTransaction(const uint8_t* privateKey, size_t privLen,
                                    const uint8_t* fromPub, const String& programIdBase58,
                                    const String& memoString, const String& recentBlockhash,
                                    String& outTxBase64);
};

#endif // INFRATIC_LIB_H