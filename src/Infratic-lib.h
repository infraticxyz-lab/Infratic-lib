#ifndef INFRATIC_LIB_H
#define INFRATIC_LIB_H

#include <Arduino.h>
#include <vector>
#include <memory>
#include <functional>
#include <WiFi.h> // WiFiClient (arduino-esp32 3.x moved it out of WiFiClientSecure.h)
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <Ed25519.h>
#include <SHA512.h>

#include "base58.h"
#include "infratic_metadata.h"

#define INFRATIC_VERSION "1.3.0"

// Well-known program IDs
#define INFRATIC_SYSTEM_PROGRAM_ID "11111111111111111111111111111111"
#define INFRATIC_TOKEN_PROGRAM_ID "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
#define INFRATIC_TOKEN_2022_PROGRAM_ID "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
#define INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
#define INFRATIC_COMPUTE_BUDGET_PROGRAM_ID "ComputeBudget111111111111111111111111111111"
#define INFRATIC_SYSVAR_RECENT_BLOCKHASHES_ID "SysvarRecentB1ockHashes11111111111111111111"
#define INFRATIC_SYSVAR_RENT_ID "SysvarRent111111111111111111111111111111111"
#define INFRATIC_ADDRESS_LOOKUP_TABLE_PROGRAM_ID "AddressLookupTab1e1111111111111111111111111"
#define INFRATIC_ED25519_PROGRAM_ID "Ed25519SigVerify111111111111111111111111111"
#define INFRATIC_SYSVAR_INSTRUCTIONS_ID "Sysvar1nstructions1111111111111111111111111"

/** Log levels for Infratic::setLogLevel() */
enum InfraticLogLevel : uint8_t
{
    INFRATIC_LOG_NONE = 0,  // no Serial output
    INFRATIC_LOG_ERROR = 1, // only errors and warnings
    INFRATIC_LOG_INFO = 2   // everything (default)
};

// ============================================================================
// ENCODING HELPERS
// ============================================================================

std::vector<uint8_t> encodeU64LE(uint64_t value);
std::vector<uint8_t> encodeU64BE(uint64_t value); // e.g. Rust u64::to_be_bytes() PDA seeds
std::vector<uint8_t> encodeU32LE(uint32_t value);
std::vector<uint8_t> encodeI64LE(int64_t value);
std::vector<uint8_t> base58ToPubkey(const String &base58Str);

/** @brief Appends a Solana compact-u16 length (used in tx serialization) */
void appendCompactU16(std::vector<uint8_t> &buffer, uint16_t value);

/** @brief Appends an Anchor/Borsh string: u32 LE length + UTF-8 bytes */
void appendBorshString(std::vector<uint8_t> &buffer, const String &str);

// ============================================================================
// STRUCTURES
// ============================================================================

struct EpochInfo
{
    uint64_t absoluteSlot;
    uint64_t blockHeight;
    uint64_t epoch;
    uint64_t slotIndex;
    uint64_t slotsInEpoch;
};

struct Pubkey
{
    std::vector<uint8_t> data;
    static Pubkey fromBase58(const String &str);
};

struct Keypair
{
    Pubkey pubkey_;
    std::vector<uint8_t> privkey;

    static Keypair fromPrivateKey(const uint8_t *key64);
    /** @brief From a Base58 64-byte secret key (Phantom/Solana CLI format). Empty privkey on error. */
    static Keypair fromBase58(const String &secretKeyBase58);
    /** @brief Derives the keypair from a 32-byte ed25519 seed */
    static Keypair fromSeed(const uint8_t seed[32]);
    /** @brief New random keypair (ESP32 hardware RNG, keep WiFi/BT on for full entropy) */
    static Keypair generate();
    /** @brief 64-byte secret key as Base58 (same format as fromBase58) */
    String secretBase58() const;
    /** @brief Public key as Base58 */
    String publicBase58() const;
    /**
     * @brief Derives a wallet from a BIP39 mnemonic, Phantom / Solflare compatible
     * Path m/44'/501'/account'/0'. Empty privkey if the mnemonic is invalid.
     */
    static Keypair fromMnemonic(const String &mnemonic, uint32_t account = 0, const String &passphrase = "");
    const Pubkey &pubkey() const;
};

// ============================================================================
// ON-DEVICE KEYS (BIP39 + encrypted storage)
// ============================================================================

/** BIP39 mnemonic helpers (English wordlist) */
class Mnemonic
{
public:
    /** @brief New random mnemonic, 12 or 24 words (ESP32 hardware RNG) */
    static String generate(uint8_t words = 12);
    static bool fromEntropy(const std::vector<uint8_t> &entropy, String &outMnemonic);
    /** @brief Checks words and checksum, returns the entropy */
    static bool toEntropy(const String &mnemonic, std::vector<uint8_t> &outEntropy);
    static bool isValid(const String &mnemonic);
    /** @brief 64-byte BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) */
    static bool toSeed(const String &mnemonic, const String &passphrase, uint8_t outSeed[64]);
    /** @brief SLIP-0010 ed25519 derivation, all indexes hardened */
    static bool deriveEd25519(const uint8_t seed[64], const std::vector<uint32_t> &path, uint8_t outKey[32]);
};

/**
 * PIN protected key storage in NVS (flash). The secret is encrypted with
 * AES-256-GCM using a key derived from the PIN (PBKDF2-HMAC-SHA256).
 * After too many wrong PINs the wallet is wiped.
 */
class KeyStore
{
public:
    /** @param name Wallet slot name, max 12 characters */
    explicit KeyStore(const String &name = "wallet");

    bool exists();
    /** @brief Stores a mnemonic (as BIP39 entropy). Overwrites the slot. */
    bool saveMnemonic(const String &mnemonic, const String &pin);
    /** @brief Stores a single 32-byte ed25519 seed (non-HD key) */
    bool saveSeed(const uint8_t seed[32], const String &pin);
    /** @brief Decrypts and returns the keypair (account index is used for mnemonics) */
    bool unlock(const String &pin, Keypair &outKeypair, uint32_t account = 0, const String &passphrase = "");
    /** @brief Returns the stored mnemonic (only for mnemonic slots), e.g. to show a backup */
    bool unlockMnemonic(const String &pin, String &outMnemonic);
    bool changePin(const String &oldPin, const String &newPin);
    bool wipe();

    uint8_t failedAttempts();
    /** @brief Wipe after this many wrong PINs in a row (0 = never, default 10) */
    void setMaxAttempts(uint8_t attempts) { _maxAttempts = attempts; }
    /** @brief PBKDF2 rounds for new saves (default 20000, ~1-2 s on ESP32) */
    void setKdfIterations(uint32_t iterations) { _iterations = iterations; }

private:
    String _name;
    uint8_t _maxAttempts = 10;
    uint32_t _iterations = 20000;
    bool save(uint8_t type, const std::vector<uint8_t> &secret, const String &pin);
    bool decrypt(const String &pin, uint8_t &outType, std::vector<uint8_t> &outSecret);
};

/**
 * @brief Helpers for battery powered devices: fast WiFi reconnect after deep sleep,
 *        sleeping with the radio off, and a boot counter kept in RTC memory.
 */
class LowPower
{
public:
    // Counts boots since power on (1 = cold boot). Call once at the start of setup().
    static uint32_t begin();
    static uint32_t bootCount();
    static bool wokeFromTimer();

    // Connects with the channel and BSSID remembered from the last connect (skips the scan,
    // usually well under a second), falls back to a normal connect if that fails.
    static bool connectWiFi(const char *ssid, const char *password, uint32_t timeoutMs = 10000);
    static bool lastConnectWasFast();
    static void forgetWiFi();

    // Turns WiFi off and enters deep sleep. On the device this does not return, setup() runs again on wake.
    static void sleep(uint64_t seconds);
};

/**
 * @brief Small persistent queue in NVS (survives deep sleep and power loss).
 *        Collect readings on every wake, send them together every few wakes.
 *        When full, the oldest entry is dropped.
 */
class DataQueue
{
public:
    explicit DataQueue(const String &name = "queue", uint16_t capacity = 32); // name: max 9 chars
    bool push(const std::vector<uint8_t> &data);
    bool push(const String &text);
    uint16_t size();
    bool peek(uint16_t index, std::vector<uint8_t> &out); // 0 = oldest
    bool pop(uint16_t count = 1);
    void clear();

private:
    String _name;
    uint16_t _capacity;
    bool load(uint16_t &head, uint16_t &count);
    bool store(uint16_t head, uint16_t count);
    String slot(uint16_t i) const;
};

struct AccountMeta
{
    Pubkey pubkey;
    bool isSigner;
    bool isWritable;

    static AccountMeta signer(const Pubkey &key);
    static AccountMeta writable(const Pubkey &key, bool isSigner = false);
};

struct Instruction
{
    Pubkey programId;
    std::vector<AccountMeta> accounts;
    std::vector<uint8_t> data;

    Instruction(const Pubkey &pid, const std::vector<AccountMeta> &accts, const std::vector<uint8_t> &d);
};

#include "infratic_instructions.h" // SystemProgram, SplToken, MemoProgram builders

/** Address Lookup Table contents (see Infratic::getAddressLookupTable) */
struct AddressLookupTable
{
    Pubkey key;
    std::vector<Pubkey> addresses;
};

struct Transaction
{
    int version = -1;                              // -1 = legacy, 0 = versioned (v0)
    std::vector<AddressLookupTable> lookupTables; // v0 only: accounts loaded from these tables
    String recent_blockhash;
    Pubkey fee_payer;
    std::vector<Instruction> instructions;
    std::vector<uint8_t> signature;               // fee payer signature (first one)
    std::vector<std::vector<uint8_t>> signatures; // all signatures in message order

    void add(const Instruction &ix);

    /**
     * @brief Builds the legacy message. Accounts are ordered as Solana expects:
     * fee payer, writable signers, readonly signers, writable, readonly.
     */
    std::vector<uint8_t> serializeMessage() const;
    /** @brief v0 message with address table lookups (used when version == 0) */
    std::vector<uint8_t> serializeMessageV0() const;

    /**
     * @brief Signs with every keypair that is a required signer.
     * @return false if a required signer is missing or the message is invalid
     */
    bool sign(const std::vector<Keypair> &signers);
    String serializeBase64() const;
};

// ============================================================================
// ZK STRUCTURES (Add to Infratic-lib.h before class declaration)
// ============================================================================

struct ZKCommitment
{
    String commitment;  // SHA256 hash of data
    String nonce;       // Random nonce for security
    uint64_t timestamp; // Creation timestamp
    String metadata;    // Optional metadata
};

struct MerkleProof
{
    String root;                  // Merkle root hash
    std::vector<String> siblings; // Sibling hashes for proof path
    size_t index;                 // Leaf index in tree
    bool isValid;                 // Proof validity flag
};

struct RangeProof
{
    int64_t minValue;
    int64_t maxValue;
    String commitment;
    String proof;
    bool isValid;
};

struct zkSNARKProof
{
    std::vector<uint8_t> proofData;    // Compressed proof data
    std::vector<uint8_t> publicInputs; // Public inputs
    bool isValid;
};

// ============================================================================
// X402 ESCROW STRUCTURES
// ============================================================================

// Escrow account size on chain: 8 + 32 + 32 + 8 + (4+64) + 1 + 8 + 8 + 1 + 1 + 1 + (4+128)
static const size_t ESCROW_ACCOUNT_SPACE = 300;
static const size_t ESCROW_ORDER_ID_MAX = 64;
static const size_t ESCROW_PROOF_HASH_MAX = 128;

// Escrow Status Enum
enum class EscrowStatus : uint8_t
{
    Active = 0,
    Completed = 1,
    Cancelled = 2,
    Disputed = 3,
    ForceClosed = 4
};

// Escrow account (data read from the chain)
struct EscrowAccount
{
    String buyer;                               // Buyer pubkey (base58)
    String seller;                              // Seller pubkey (base58)
    uint64_t amount = 0;                        // Escrow amount (lamports)
    String orderId;                             // Order ID (max 64 chars)
    EscrowStatus status = EscrowStatus::Active; // Escrow status
    int64_t createdAt = 0;                      // Creation time (unix)
    int64_t expiresAt = 0;                      // Expiration time (unix)
    uint8_t bump = 0;                           // PDA bump seed
    bool deliveryConfirmed = false;             // Delivery confirmed
    bool disputeInitiated = false;              // Dispute state
    String proofHash;                           // Delivery proof hash
};

// Function results
struct EscrowCreateResult
{
    bool success;
    String escrowPDA;    // Created escrow PDA address
    String txSignature;  // Transaction signature
    uint8_t bump;        // PDA bump
    String errorMessage; // Error message (if any)
};

struct EscrowTxResult
{
    bool success;
    String txSignature;
    String errorMessage;
};

struct EscrowAccountResult
{
    bool success;
    EscrowAccount account;
    String errorMessage;
};
// Durable nonce account (80 bytes): version, state, authority, nonce, fee calculator
static const size_t NONCE_ACCOUNT_SPACE = 80;

struct NonceInfo
{
    String authority;                  // nonce authority (base58)
    String nonce;                      // value to use as recent_blockhash
    uint64_t lamportsPerSignature = 0; // fee calculator
};

// ============================================================================
// BORSH (Anchor serialization)
// ============================================================================

/** Sequential little-endian / Borsh reader with bounds checks. `ok` turns false on any overrun. */
class BorshReader
{
public:
    BorshReader(const std::vector<uint8_t> &data, size_t start = 0) : buf(data), pos(start), ok(true) {}

    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    int64_t i64();
    bool boolean();
    String pubkey();                       // 32 bytes -> base58
    std::vector<uint8_t> bytes(size_t n);  // fixed size array
    String str(size_t maxLen = 65535);     // u32 length + utf8 (not padded)
    std::vector<uint8_t> vecU8();          // u32 length + bytes
    size_t remaining() const { return pos < buf.size() ? buf.size() - pos : 0; }

    const std::vector<uint8_t> &buf;
    size_t pos;
    bool ok;

private:
    bool need(size_t n);
};

/** Builds Borsh encoded instruction arguments. */
class BorshWriter
{
public:
    BorshWriter &u8(uint8_t v);
    BorshWriter &u16(uint16_t v);
    BorshWriter &u32(uint32_t v);
    BorshWriter &u64(uint64_t v);
    BorshWriter &i64(int64_t v);
    BorshWriter &boolean(bool v);
    BorshWriter &pubkey(const String &base58);
    BorshWriter &bytes(const std::vector<uint8_t> &v); // fixed size, no length prefix
    BorshWriter &str(const String &s);
    BorshWriter &vecU8(const std::vector<uint8_t> &v);

    std::vector<uint8_t> data;
};

/** An Anchor event (emit!) found in transaction logs */
struct AnchorEvent
{
    String programId;
    std::vector<uint8_t> discriminator; // first 8 bytes
    std::vector<uint8_t> data;          // fields after the discriminator

    /** @brief True if this is the event with the given Rust struct name */
    bool is(const String &eventName) const;
    BorshReader reader() const { return BorshReader(data); }
};

// ============================================================================
// TRANSACTION ERRORS
// ============================================================================

/** Details of the last failed transaction (see Infratic::lastTxError) */
struct TxError
{
    bool hasError = false;
    int instructionIndex = -1; // failing instruction, -1 if not instruction specific
    int64_t customCode = -1;   // program error code (e.g. Anchor 6000+), -1 if none
    String name;               // e.g. "InsufficientFunds", Anchor error name, "BlockhashExpired"
    String message;            // Anchor error message or RPC message
    String raw;                // raw error JSON
    std::vector<String> logs;  // program logs when available
};

struct SimulationResult
{
    bool success = false;
    uint64_t unitsConsumed = 0;
    std::vector<String> logs;
    TxError error;
};

// ============================================================================
// RPC RESULT STRUCTURES
// ============================================================================

/** @brief getProgramAccounts filter (dataSize or memcmp) */
struct AccountFilter
{
    bool isMemcmp = false;
    size_t size = 0;            // dataSize filter
    size_t offset = 0;          // memcmp offset
    std::vector<uint8_t> bytes; // memcmp bytes

    static AccountFilter dataSize(size_t size);
    static AccountFilter memcmp(size_t offset, const std::vector<uint8_t> &bytes);
};

struct ProgramAccount
{
    String pubkey;
    std::vector<uint8_t> data;
    uint64_t lamports = 0;
};

struct SignatureInfo
{
    String signature;
    uint64_t slot = 0;
    int64_t blockTime = 0;
    bool failed = false; // transaction had an error
};

// ============================================================================
// WEBSOCKET SUBSCRIPTION CALLBACKS
// ============================================================================

// handle = value returned by the *Subscribe call (stays the same after reconnects)
typedef std::function<void(int handle, const std::vector<uint8_t> &data, uint64_t lamports, uint64_t slot)> AccountChangeCallback;
typedef std::function<void(int handle, const String &pubkey, const std::vector<uint8_t> &data, uint64_t slot)> ProgramAccountCallback;
typedef std::function<void(int handle, const String &signature, const std::vector<String> &logs, bool failed, uint64_t slot)> LogsCallback;
typedef std::function<void(int handle, const String &signature, bool failed)> SignatureCallback;

struct InfraticWsState; // internal

// ============================================================================
// MAIN LIBRARY CLASS
// ============================================================================

class Infratic
{
public:
    explicit Infratic(const String &rpcUrl);

    /** @brief Sets library Serial output level (default INFRATIC_LOG_INFO) */
    static void setLogLevel(uint8_t level);

    // ========================================================================
    // BLOCKCHAIN QUERIES
    // ========================================================================

    /**
     * @brief Fetches the latest blockhash from Solana cluster
     * @return Latest blockhash in Base58 format, or empty string on failure
     */
    String getLatestBlockhash();

    /**
     * @brief Latest blockhash plus the last block height it is valid for
     * @return true if successful
     */
    bool getLatestBlockhash(String &outBlockhash, uint64_t &outLastValidBlockHeight);

    /**
     * @brief Gets the current block height
     * @param outBlockHeight Output parameter for block height
     * @return true if successful
     */
    bool getBlockHeight(uint64_t &outBlockHeight);

    /**
     * @brief Gets current epoch information
     * @param outEpochInfo Output parameter for epoch data
     * @return true if successful
     */
    bool getEpochInfo(EpochInfo &outEpochInfo);

    // ========================================================================
    // BALANCE QUERIES
    // ========================================================================

    /**
     * @brief Gets SOL balance for a wallet
     * @param walletPubkeyBase58 Wallet public key in Base58
     * @param outLamports Output parameter for balance in lamports
     * @return true if successful
     */
    bool getSolBalance(const String &walletPubkeyBase58, uint64_t &outLamports);

    /**
     * @brief Gets SPL token balance for a wallet
     * @param walletPubkeyBase58 Wallet public key in Base58
     * @param tokenMintBase58 Token mint address in Base58
     * @param outBalance Output parameter for token balance
     * @return true if successful
     */
    bool getSplTokenBalance(const String &walletPubkeyBase58, const String &tokenMintBase58, uint64_t &outBalance);

    /**
     * @brief Gets token decimals from mint
     * @param mintPubkeyBase58 Token mint address in Base58
     * @param outDecimals Output parameter for decimals
     * @return true if successful
     */
    bool getTokenDecimals(const String &mintPubkeyBase58, uint8_t &outDecimals);

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
    bool findAssociatedTokenAccount(const String &ownerPubkeyBase58, const String &mintPubkeyBase58, String &outATA);

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
    bool sendSol(const String &privateKeyBase58, const String &fromPubkeyBase58,
                 const String &toPubkeyBase58, uint64_t lamports);

    /**
     * @brief Sends program data transaction (memo or custom)
     * @param privateKeyBase58 Sender's private key in Base58
     * @param fromPubkeyBase58 Sender's public key in Base58
     * @param programIdBase58 Target program ID in Base58
     * @param dataString Data to send
     * @param confirmWaitMs Milliseconds to wait for confirmation
     * @return true if successful
     */
    bool sendProgramDataTransaction(const String &privateKeyBase58, const String &fromPubkeyBase58,
                                    const String &programIdBase58, const String &dataString,
                                    uint32_t confirmWaitMs = 5000);

    /**
     * @brief Sends raw transaction to network
     * @param txBase64 Base64 encoded transaction
     * @param outSignature Output parameter for transaction signature
     * @return true if successful
     */
    bool sendRawTransaction(const String &txBase64, String &outSignature, bool skipPreflight = false);

    /**
     * @brief Confirms transaction on blockchain
     * @param signature Transaction signature in Base58
     * @param maxWaitMs Maximum wait time in milliseconds
     * @return true if confirmed
     */
    bool confirmTransaction(const String &signature, uint32_t maxWaitMs = 5000);

    /**
     * @brief Sends and keeps re-sending until confirmed, failed or the blockhash expired
     * @param lastValidBlockHeight From getLatestBlockhash (0 = unknown, e.g. durable nonce)
     * @param timeoutMs Overall timeout
     */
    bool sendAndConfirm(const String &txBase64, uint64_t lastValidBlockHeight, String &outSignature,
                        uint32_t timeoutMs = 30000);

    /** @brief Runs the transaction without sending it (logs, compute units, error) */
    bool simulateTransaction(const String &txBase64, SimulationResult &outResult, bool sigVerify = false);

    /** @brief Error of the last failed send / confirm / simulate */
    const TxError &lastTxError() const { return _lastTxError; }

    /**
     * @brief Fills fee payer / blockhash if empty, signs, sends and waits for confirmation
     * @param tx Transaction (fee_payer defaults to the first signer)
     * @param signers Every required signer
     * @param outSignature Transaction signature
     * @param confirmWaitMs 0 = don't wait for confirmation
     * @return true if sent (and confirmed when confirmWaitMs > 0)
     */
    bool signAndSend(Transaction &tx, const std::vector<Keypair> &signers, String &outSignature,
                     uint32_t confirmWaitMs = 15000);

    // ========================================================================
    // PRIORITY FEES (Compute Budget)
    // ========================================================================

    /**
     * @brief Adds a priority fee to every transaction the library builds
     * @param microLamportsPerUnit Price per compute unit (0 = off)
     * @param computeUnitLimit Optional compute unit limit (0 = runtime default)
     */
    void setPriorityFee(uint64_t microLamportsPerUnit, uint32_t computeUnitLimit = 0);

    /** @brief Inserts the configured compute budget instructions (used internally, also for custom txs) */
    void applyPriorityFee(Transaction &tx) const;

    static Instruction setComputeUnitLimitIx(uint32_t units);
    static Instruction setComputeUnitPriceIx(uint64_t microLamportsPerUnit);

    /**
     * @brief Suggests a priority fee from getRecentPrioritizationFees
     * @param writableAccounts Accounts the tx will write (empty = global)
     * @param percentile 0-100, e.g. 75 = pay more than 75% of recent slots
     */
    bool estimatePriorityFee(const std::vector<String> &writableAccounts, uint64_t &outMicroLamports,
                             uint8_t percentile = 75);

    // ========================================================================
    // WEBSOCKET SUBSCRIPTIONS (push notifications instead of polling)
    // ========================================================================

    /** @brief WebSocket endpoint, default: RPC URL with https->wss (port 8899->8900 for localnet) */
    void setWsUrl(const String &wsUrl);
    bool wsConnect();
    void wsDisconnect();
    bool wsConnected() const;
    /** @brief Reconnect and re-subscribe automatically when the socket drops (default on) */
    void setWsAutoReconnect(bool enabled);
    /** @brief Largest WebSocket message kept in RAM (default 64 KB) */
    void setWsMaxMessageSize(size_t bytes);

    /** @return handle (>= 0) or -1 */
    int accountSubscribe(const String &accountBase58, const String &commitment = "confirmed");
    int programSubscribe(const String &programIdBase58, const std::vector<AccountFilter> &filters = {},
                         const String &commitment = "confirmed");
    /** @param mentionsBase58 Only logs of transactions mentioning this address ("all" = everything) */
    int logsSubscribe(const String &mentionsBase58, const String &commitment = "confirmed");
    /** @brief One-shot: fires once when the signature is confirmed (or failed) */
    int signatureSubscribe(const String &signature, const String &commitment = "confirmed");
    bool unsubscribe(int handle);

    void onAccountChange(AccountChangeCallback cb);
    void onProgramAccountChange(ProgramAccountCallback cb);
    void onLogs(LogsCallback cb);
    void onSignature(SignatureCallback cb);

    /** @brief Call often from loop(): reads messages, runs callbacks, keeps the socket alive */
    void wsLoop();

    // ========================================================================
    // DEVICE SIGNATURES (Ed25519 program)
    // ========================================================================

    /**
     * @brief Instruction for the native Ed25519 program: the runtime checks that
     * `signature` is valid for `message` and `signer`, otherwise the whole tx fails.
     * Your program can read it from the Instructions sysvar to trust device data.
     */
    static Instruction ed25519VerifyIx(const Pubkey &signer, const uint8_t signature[64],
                                       const std::vector<uint8_t> &message);

    /** @brief Signs `message` with the device key and returns the Ed25519 program instruction */
    static Instruction ed25519SignIx(const Keypair &device, const std::vector<uint8_t> &message);

    /** @brief Off-chain check of an ed25519 signature */
    static bool verifySignature(const Pubkey &signer, const uint8_t signature[64], const std::vector<uint8_t> &message);

    /**
     * @brief Sends device-signed data in one transaction: Ed25519 check + memo with the data.
     * The memo makes the data visible in explorers; the Ed25519 instruction proves who signed it.
     * @param device Key that signs the data (can be different from the fee payer)
     * @param payer Fee payer
     */
    bool sendSignedData(const Keypair &device, const Keypair &payer, const std::vector<uint8_t> &data,
                        String &outSignature);

    // ========================================================================
    // ANCHOR EVENTS
    // ========================================================================

    /** @brief sha256("event:<Name>")[0..8] */
    static std::vector<uint8_t> eventDiscriminator(const String &eventName);
    /** @brief sha256("account:<Name>")[0..8], the first 8 bytes of an Anchor account */
    static std::vector<uint8_t> accountDiscriminator(const String &accountName);

    /**
     * @brief Extracts emit! events ("Program data:" lines) from transaction logs
     * @param programIdFilter Only events of this program (empty = all)
     */
    static bool parseAnchorEvents(const std::vector<String> &logs, std::vector<AnchorEvent> &outEvents,
                                  const String &programIdFilter = "");

    /** @brief Log messages of a confirmed transaction */
    bool getTransactionLogs(const String &signature, std::vector<String> &outLogs);

    // ========================================================================
    // ADDRESS LOOKUP TABLES (versioned transactions)
    // ========================================================================

    /** @brief Reads a lookup table account so it can be used in tx.lookupTables */
    bool getAddressLookupTable(const String &tableBase58, AddressLookupTable &outTable);

    /**
     * @brief CreateLookupTable instruction
     * @param recentSlot A recent finalized slot (getSlot)
     * @param outTable Derived table address
     */
    bool createLookupTableIx(const String &authorityBase58, const String &payerBase58, uint64_t recentSlot,
                             Instruction &outIx, String &outTable);

    /** @brief ExtendLookupTable instruction (max ~30 addresses per transaction) */
    static Instruction extendLookupTableIx(const Pubkey &table, const Pubkey &authority, const Pubkey &payer,
                                          const std::vector<Pubkey> &newAddresses);

    // ========================================================================
    // DURABLE NONCE (sign now, send later)
    // ========================================================================

    /**
     * @brief Creates and initializes a nonce account
     * @param nonceAccount New keypair for the nonce account (e.g. Keypair::generate(), keep its secret)
     * @param authorityBase58 Who can advance the nonce (usually the device wallet)
     */
    bool createNonceAccount(const String &payerPrivateKeyBase58, const Keypair &nonceAccount,
                            const String &authorityBase58, String &outSignature);

    /** @brief Reads the current nonce value and authority */
    bool getNonce(const String &nonceAccountBase58, NonceInfo &outInfo);

    /** @brief AdvanceNonceAccount instruction (must be the first instruction) */
    static Instruction nonceAdvanceIx(const Pubkey &nonceAccount, const Pubkey &authority);

    /**
     * @brief Turns tx into a durable transaction: sets the nonce as blockhash and
     * inserts the advance instruction first. Sign it now, send it any time later.
     * @param nonce Optional nonce value; empty = read it from the chain
     */
    bool useDurableNonce(Transaction &tx, const String &nonceAccountBase58, const String &authorityBase58,
                         const String &nonce = "");

    // ========================================================================
    // SPL TOKEN (Token Program and Token-2022)
    // ========================================================================

    /**
     * @brief Derives the Associated Token Account address (no RPC call)
     * @param tokenProgramId INFRATIC_TOKEN_PROGRAM_ID or INFRATIC_TOKEN_2022_PROGRAM_ID
     */
    bool getAssociatedTokenAddress(const String &ownerBase58, const String &mintBase58, String &outAta,
                                   const String &tokenProgramId = INFRATIC_TOKEN_PROGRAM_ID);

    /** @brief Instruction that creates an ATA, does nothing if it already exists */
    static Instruction createAssociatedTokenAccountIdempotentIx(const Pubkey &payer, const Pubkey &ata,
                                                                const Pubkey &owner, const Pubkey &mint,
                                                                const Pubkey &tokenProgram);

    /** @brief SPL TransferChecked instruction (amount in base units) */
    static Instruction transferCheckedIx(const Pubkey &source, const Pubkey &mint, const Pubkey &destination,
                                        const Pubkey &owner, uint64_t amount, uint8_t decimals,
                                        const Pubkey &tokenProgram);

    /**
     * @brief Sends SPL tokens from the signer's ATA to the recipient's ATA
     * @param amount Amount in base units (e.g. 1 USDC = 1000000)
     * @param decimals Mint decimals, -1 = read from chain
     * @param createDestinationAta Create the recipient ATA if it does not exist
     */
    bool sendSplToken(const String &privateKeyBase58, const String &fromOwnerBase58,
                      const String &toOwnerBase58, const String &mintBase58, uint64_t amount,
                      String &outSignature, int decimals = -1, bool createDestinationAta = true,
                      const String &tokenProgramId = INFRATIC_TOKEN_PROGRAM_ID);

    // ========================================================================
    // INSTRUCTION BUILDERS: wrapped SOL convenience (builders: SystemProgram, SplToken, MemoProgram)
    // ========================================================================

    /**
     * @brief Wraps SOL: creates the owner's wSOL ATA if missing, moves `lamports` into it and syncs
     * @param tokenProgramId Token program of the native mint (classic Token program by default)
     */
    bool wrapSol(const Keypair &owner, uint64_t lamports, String &outSignature,
                 const String &tokenProgramId = INFRATIC_TOKEN_PROGRAM_ID);

    /** @brief Unwraps all SOL: closes the owner's wSOL ATA and returns its lamports to the owner */
    bool unwrapSol(const Keypair &owner, String &outSignature,
                   const String &tokenProgramId = INFRATIC_TOKEN_PROGRAM_ID);

    // ========================================================================
    // GENERIC RPC
    // ========================================================================

    /**
     * @brief Sends any JSON-RPC request
     * @param method RPC method name (e.g. "getSlot")
     * @param paramsJson JSON array of params (e.g. "[\"<pubkey>\"]")
     * @param outResponse Raw JSON response
     * @return true on HTTP 200 and no RPC "error" field
     */
    bool rpcCall(const String &method, const String &paramsJson, String &outResponse);

    /**
     * @brief Root CA(s) used to verify the RPC / WebSocket server (PEM, several can be concatenated).
     *        By default a bundle for the common Solana RPC providers is used. The string must stay
     *        valid while the client is used (a literal or a global). nullptr restores the default.
     */
    void setRootCA(const char *pem);

    /**
     * @brief Skips certificate verification. Only for local tests, anyone on the network can
     *        then read and change RPC traffic.
     */
    void setTlsInsecure(bool insecure = true);

    /**
     * @brief Adds a backup RPC endpoint. When the active endpoint fails (connection or TLS error,
     *        HTTP 429 or 5xx) the request is retried on the next one, which then stays active.
     *        After 5 minutes on a backup the primary is tried again. WebSocket follows the active
     *        endpoint unless setWsUrl() was used.
     */
    void addRpcEndpoint(const String &url);
    void clearRpcEndpoints(); // keeps only the primary
    String activeRpcUrl() const { return _rpcUrl; }
    void setPrimaryRetryInterval(uint32_t ms) { _primaryRetryMs = ms; }

    /**
     * @brief HTTP connect / read timeout for RPC calls (default 10000 ms).
     *        Lower it on battery devices so a dead network costs less awake time.
     */
    void setTimeout(uint32_t ms);

    /**
     * @brief Reads raw account data (base64 decoded)
     * @param accountBase58 Account address
     * @param outData Account data bytes
     * @param commitment "processed", "confirmed" or "finalized"
     * @param outOwner Optional, receives the owner program
     * @return false if the account does not exist
     */
    bool getAccountData(const String &accountBase58, std::vector<uint8_t> &outData,
                        const String &commitment = "confirmed", String *outOwner = nullptr);

    /**
     * @brief Lists accounts owned by a program, with optional filters
     * Use filters (dataSize / memcmp) to keep the response small on ESP32.
     */
    bool getProgramAccounts(const String &programIdBase58, const std::vector<AccountFilter> &filters,
                            std::vector<ProgramAccount> &outAccounts, const String &commitment = "confirmed");

    /**
     * @brief Latest signatures for an address (newest first)
     * @param until Optional, stop at this signature (exclusive)
     */
    bool getSignaturesForAddress(const String &addressBase58, std::vector<SignatureInfo> &outSignatures,
                                 uint8_t limit = 10, const String &until = "");

    /** @brief Rent-exempt minimum for an account of given size */
    bool getMinimumBalanceForRentExemption(size_t dataLength, uint64_t &outLamports);

    /** @brief Current cluster unix time (getSlot + getBlockTime) */
    bool getClusterTime(int64_t &outUnixTime);

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
    bool signMessageFromBase58(const std::vector<uint8_t> &message, const String &privateKeyBase58,
                               uint8_t outSignature[64]);

    /**
     * @brief Signs message with raw binary private key
     * @param message Message bytes to sign
     * @param privateKey 64-byte private key vector
     * @param outSignature Output buffer for 64-byte signature
     * @return true if successful
     */
    bool signMessageRaw(const std::vector<uint8_t> &message, const std::vector<uint8_t> &privateKey,
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
    bool derivePDA(const std::vector<std::vector<uint8_t>> &seeds, const String &programIdBase58,
                   String &outPDABase58, uint8_t &outBump);

    /**
     * @brief Low-level PDA derivation
     * @param seeds Vector of seed byte arrays
     * @param programId 32-byte program ID
     * @param outPDA Output parameter for 32-byte PDA
     * @param outBump Output parameter for bump seed
     * @return true if successful
     */
    bool findProgramAddress(const std::vector<std::vector<uint8_t>> &seeds,
                            const std::vector<uint8_t> &programId,
                            std::vector<uint8_t> &outPDA, uint8_t &outBump);

    /**
     * @brief Checks if 32 bytes are a valid ed25519 point (same as PublicKey.isOnCurve)
     * @param key 32-byte key
     * @return true if the key is on the curve (PDAs are always off-curve)
     */
    static bool isOnCurve(const uint8_t key[32]);

    // ========================================================================
    // ANCHOR FRAMEWORK SUPPORT
    // ========================================================================

    /**
     * @brief Calculates Anchor instruction discriminator
     * @param functionName Name of the Anchor function
     * @return 8-byte discriminator vector
     */
    std::vector<uint8_t> calculateDiscriminator(const std::string &functionName);

    // ========================================================================
    // UTILITY FUNCTIONS
    // ========================================================================

    /**
     * @brief Encodes data to Base64
     * @param data Pointer to data buffer
     * @param len Length of data
     * @return Base64 encoded string
     */
    String base64Encode(const uint8_t *data, size_t len);

    // ========================================================================
    // ZERO-KNOWLEDGE PROOF OPERATIONS
    // ========================================================================

    // ---- Section A: Hash-Based Commitments ----

    /**
     * @brief Creates a cryptographic commitment to hide data
     * @param data Original data to commit
     * @param secret Secret key for additional security
     * @param outCommitment Output commitment hash
     * @param outNonce Output nonce used in commitment
     * @param outTimestamp
     * @return true if successful
     */
    bool createDataCommitment(const String &data, const String &secret,
                              String &outCommitment, String &outNonce, uint64_t &outTimestamp);

    /**
     * @brief Verifies data against a previously created commitment
     * @param data Revealed data to verify
     * @param secret Secret key used in original commitment
     * @param nonce Nonce from original commitment
     * @param timestamp Timestamp from original commitment
     * @param originalCommitment Original commitment to verify against
     * @return true if data matches commitment
     */
    bool verifyDataCommitment(const String &data, const String &secret,
                              const String &nonce, uint64_t timestamp,
                              const String &originalCommitment);

    /**
     * @brief Stores a ZK commitment on Solana blockchain
     * @param privateKeyBase58 Transaction signer's private key
     * @param fromPubkeyBase58 Sender's public key
     * @param commitment Commitment hash to store
     * @param metadata Additional metadata
     * @param outTxSignature Transaction signature
     * @return true if stored successfully
     */
    bool storeCommitmentOnChain(const String &privateKeyBase58,
                                const String &fromPubkeyBase58,
                                const String &commitment, const String &metadata,
                                String &outTxSignature);

    // ---- Section B: Merkle Tree Proofs ----

    /**
     * @brief Builds a Merkle tree from data list
     * @param dataList Vector of data strings
     * @param outRoot Output Merkle root hash
     * @return true if successful
     */
    bool buildMerkleTree(const std::vector<String> &dataList, String &outRoot);

    /**
     * @brief Generates a Merkle proof for specific data item
     * @param dataList Complete data list
     * @param dataIndex Index of data to prove
     * @param outProof Output MerkleProof structure
     * @return true if successful
     */
    bool createMerkleProof(const std::vector<String> &dataList, size_t dataIndex,
                           MerkleProof &outProof);

    /**
     * @brief Verifies a Merkle proof
     * @param data Data to verify
     * @param proof Merkle proof structure
     * @return true if proof is valid
     */
    bool verifyMerkleProof(const String &data, const MerkleProof &proof);

    // ---- Section C: Range Proofs ----

    /**
     * @brief Creates a range proof showing value is between min and max
     * @param value Secret value to prove
     * @param minValue Minimum allowed value
     * @param maxValue Maximum allowed value
     * @param secret Secret key for commitment
     * @param outProof Output RangeProof structure
     * @return true if successful
     */
    bool createRangeProof(int64_t value, int64_t minValue, int64_t maxValue,
                          const String &secret, RangeProof &outProof);

    /**
     * @brief Verifies a range proof
     * @param value Revealed value to verify
     * @param secret Secret used in original commitment
     * @param proof Range proof to verify
     * @return true if value is in range
     */
    bool verifyRangeProof(int64_t value, const String &secret, const RangeProof &proof);

    // ---- Section D: zkSNARK (Simplified) ----

    /**
     * @brief Creates a zkSNARK proof (simplified for ESP32)
     * @param privateData Private data to prove knowledge of
     * @param publicInputs Public inputs visible to verifier
     * @param circuit Circuit description
     * @param outProof Output zkSNARK proof
     * @return true if successful
     */
    bool createzkSNARKProof(const std::vector<uint8_t> &privateData,
                            const std::vector<uint8_t> &publicInputs,
                            const String &circuit, zkSNARKProof &outProof);

    /**
     * @brief Verifies a zkSNARK proof
     * @param proof zkSNARK proof to verify
     * @param expectedPublicInputs Expected public inputs
     * @return true if proof is valid
     */
    bool verifyzkSNARKProof(const zkSNARKProof &proof,
                            const std::vector<uint8_t> &expectedPublicInputs);

    // ---- Section E: Timestamped Proofs ----

    /**
     * @brief Creates a timestamped proof of data existence
     * @param data Data to timestamp
     * @param outProof Output proof string
     * @param outTimestamp Output timestamp
     * @return true if successful
     */
    bool createTimestampedProof(const String &data, String &outProof,
                                uint64_t &outTimestamp, String &outBlockhash);
    /**
     * @brief Verifies a timestamped proof
     * @param data Original data
     * @param proof Proof hash
     * @param timestamp Claimed timestamp
     * @param blockhash Blockchain anchor
     * @return true if proof matches
     */
    bool verifyTimestampedProof(const String &data, const String &proof,
                                uint64_t timestamp, const String &blockhash);

    // ---- Section F: Batch Operations ----

    /**
     * @brief Creates multiple commitments in batch
     * @param dataList Vector of data strings
     * @param secret Shared secret for all commitments
     * @param outCommitments Output vector of commitments
     * @return true if successful
     */
    bool createBatchCommitments(const std::vector<String> &dataList,
                                const String &secret,
                                std::vector<ZKCommitment> &outCommitments);

    /**
     * @brief Stores batch commitments on-chain efficiently
     * @param privateKeyBase58 Signer's private key
     * @param fromPubkeyBase58 Sender's public key
     * @param commitments Vector of commitments
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool storeBatchCommitmentsOnChain(const String &privateKeyBase58,
                                      const String &fromPubkeyBase58,
                                      const std::vector<ZKCommitment> &commitments,
                                      String &outTxSignature);

    // ========================================================================
    // ANCHOR PROGRAM STORAGE OPERATIONS
    // ========================================================================

    /**
     * @brief Initialize ZK storage account on Anchor program
     * @param privateKeyBase58 Authority's private key
     * @param authorityPubkey Authority's public key
     * @param programId Anchor program ID
     * @param seedName Seed name for PDA derivation
     * @param outPDA Derived PDA address
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool initializeZKStorage(
        const String &privateKeyBase58,
        const String &authorityPubkey,
        const String &programId,
        const String &seedName,
        String &outPDA,
        String &outTxSignature);

    /**
     * @brief Store commitment in Anchor program (permanent storage)
     * @param privateKeyBase58 Authority's private key
     * @param authorityPubkey Authority's public key
     * @param programId Anchor program ID
     * @param seedName Seed name for PDA
     * @param commitment Commitment hash (32 bytes hex)
     * @param metadata Metadata string
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool storeCommitmentInAnchor(
        const String &privateKeyBase58,
        const String &authorityPubkey,
        const String &programId,
        const String &seedName,
        const String &commitment,
        const String &metadata,
        String &outTxSignature);

    /**
     * @brief Update existing commitment in Anchor program
     * @param privateKeyBase58 Authority's private key
     * @param authorityPubkey Authority's public key
     * @param programId Anchor program ID
     * @param seedName Seed name for PDA
     * @param newCommitment New commitment hash
     * @param metadata New metadata
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool updateCommitmentInAnchor(
        const String &privateKeyBase58,
        const String &authorityPubkey,
        const String &programId,
        const String &seedName,
        const String &newCommitment,
        const String &metadata,
        String &outTxSignature);

    /**
     * @brief Store Merkle root in Anchor program
     * @param privateKeyBase58 Authority's private key
     * @param authorityPubkey Authority's public key
     * @param programId Anchor program ID
     * @param seedName Seed name for PDA
     * @param merkleRoot Merkle root hash
     * @param leafCount Number of leaves in tree
     * @param metadata Additional metadata
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool storeMerkleRootInAnchor(
        const String &privateKeyBase58,
        const String &authorityPubkey,
        const String &programId,
        const String &seedName,
        const String &merkleRoot,
        uint32_t leafCount,
        const String &metadata,
        String &outTxSignature);

    /**
     * @brief Store batch commitments in Anchor program
     * @param privateKeyBase58 Authority's private key
     * @param authorityPubkey Authority's public key
     * @param programId Anchor program ID
     * @param batchId Unique batch identifier
     * @param batchRoot Merkle root of all commitments
     * @param batchSize Number of commitments
     * @param metadata Batch metadata
     * @param outTxSignature Transaction signature
     * @return true if successful
     */
    bool storeBatchInAnchor(
        const String &privateKeyBase58,
        const String &authorityPubkey,
        const String &programId,
        const String &batchId,
        const String &batchRoot,
        uint32_t batchSize,
        const String &metadata,
        String &outTxSignature);

    /**
     * @brief Sets the program ID used by the escrow functions.
     * Must be called BEFORE any escrow_... function.
     * @param programId Base58 address of the escrow program.
     */
    void setEscrowProgramId(const String &programId);

    // ============================================================================
    // X402 ESCROW PROTOCOL FUNCTIONS
    // ============================================================================

    /**
     * @brief Derives the escrow PDA (seeds: "escrow", order_id, buyer)
     * @param orderId Order ID (max 32 bytes because it is a PDA seed)
     * @param buyerPubkeyBase58 Buyer address
     */
    bool deriveEscrowPDA(const String &orderId, const String &buyerPubkeyBase58,
                         String &outPDA, uint8_t &outBump);

    /**
     * @brief Reads the current state of an escrow account.
     * @param escrowPdaBase58 Address of the escrow account.
     * @param commitment "finalized" (default) or "confirmed" (faster).
     * @return EscrowAccountResult - success flag and the account data.
     */
    EscrowAccountResult getEscrowAccount(const String &escrowPdaBase58, const String &commitment = "finalized");

    /**
     * @brief Creates a new escrow.
     * @return EscrowCreateResult - success flag, PDA, signature and bump.
     */
    EscrowCreateResult escrow_create(
        const String &buyerPrivateKeyBase58,
        const String &buyerPubkeyBase58,
        const String &sellerPubkeyBase58,
        uint64_t amount,
        const String &order_id,
        int64_t expiration_duration);

    /**
     * @brief Seller confirms the delivery.
     * @return EscrowTxResult - success flag and transaction signature.
     */
    EscrowTxResult escrow_confirmDelivery(
        const String &sellerPrivateKeyBase58,
        const String &sellerPubkeyBase58,
        const String &escrowPdaBase58,
        const String &proof_hash);

    /**
     * @brief Buyer releases the escrow to the seller.
     * @return EscrowTxResult - success flag and transaction signature.
     */
    EscrowTxResult escrow_release(
        const String &buyerPrivateKeyBase58,
        const String &buyerPubkeyBase58,
        const String &sellerPubkeyBase58,
        const String &escrowPdaBase58);

    /**
     * @brief Buyer cancels an expired escrow.
     * @return EscrowTxResult - success flag and transaction signature.
     */
    EscrowTxResult escrow_cancel(
        const String &buyerPrivateKeyBase58,
        const String &buyerPubkeyBase58,
        const String &escrowPdaBase58);

    /**
     * @brief Seller initiates a dispute.
     * @return EscrowTxResult - success flag and transaction signature.
     */
    EscrowTxResult escrow_initiateDispute(
        const String &sellerPrivateKeyBase58,
        const String &sellerPubkeyBase58,
        const String &escrowPdaBase58,
        const String &reason,
        const String &evidence);

    /**
     * @brief (Emergency) Authority force closes the escrow.
     * @return EscrowTxResult - success flag and transaction signature.
     */
    EscrowTxResult escrow_forceClose(
        const String &authorityPrivateKeyBase58,
        const String &authorityPubkeyBase58,
        const String &buyerPubkeyBase58,
        const String &escrowPdaBase58);

    // ========================================================================
    // Token metadata (names, symbols, logos)
    // ========================================================================

    /**
     * @brief Metaplex metadata PDA of a mint (no RPC call)
     */
    bool getMetadataPda(const String &mintBase58, String &outPda);

    /**
     * @brief Metaplex master edition PDA of a mint (no RPC call)
     */
    bool getMasterEditionPda(const String &mintBase58, String &outPda);

    /**
     * @brief Reads name, symbol and uri of a token. Uses the Token-2022 metadata extension when the
     *        mint has one, otherwise the Metaplex metadata account.
     * @param out out.found is false if the mint has no metadata (the call still returns true)
     * @return false if the mint account could not be read
     */
    bool getTokenMetadata(const String &mintBase58, TokenMetadata &out, const String &commitment = "confirmed");

private:
    String _rpcUrl;
    const char *_rootCA = nullptr;
    bool _tlsInsecure = false;
    uint32_t _timeoutMs = 10000;
    std::vector<String> _rpcUrls; // [0] = primary
    size_t _activeRpc = 0;
    unsigned long _switchedAt = 0;
    uint32_t _primaryRetryMs = 300000;
    void useRpc(size_t index);
    bool wsConnectOnce();
    bool httpPostOnce(const String &body, String &outResponse, int &outCode);
    void configureTls(WiFiClientSecure &client);
    // POST to the RPC endpoint, true on HTTP 200
    bool httpPost(const String &body, String &outResponse, int &outCode);
    uint64_t _priorityFeeMicroLamports = 0;
    std::shared_ptr<InfraticWsState> _ws;
    InfraticWsState &ws();
    int wsSubscribe(const String &method, const String &params, int kind, const String &extra);
    bool wsSendText(const String &text);
    bool wsProcessIncoming(uint32_t waitMs, int waitForId, int64_t *outResult);
    void wsHandleMessage(const String &msg, int waitForId, int64_t *outResult, bool *gotResult);
    TxError _lastTxError;

    // 1 = confirmed, -1 = failed (lastTxError set), 0 = pending / unknown
    int checkSignatureStatus(const String &signature);
    uint32_t _computeUnitLimit = 0;

    // Internal transaction building functions
    bool buildAndSignTransaction(const uint8_t *privateKey, size_t privLen,
                                 const uint8_t *fromPub, const uint8_t *toPub,
                                 uint64_t lamports, const String &recentBlockhash,
                                 String &outTxBase64);

    bool buildAndSignMemoTransaction(const uint8_t *privateKey, size_t privLen,
                                     const uint8_t *fromPub, const String &programIdBase58,
                                     const String &memoString, const String &recentBlockhash,
                                     String &outTxBase64);

    String _escrowProgramId; // escrow program ID set at runtime

    // Escrow account (Anchor/Borsh) decoding
    bool deserializeEscrowAccount(const std::vector<uint8_t> &data, EscrowAccount &outAccount);
};

#endif // INFRATIC_LIB_H