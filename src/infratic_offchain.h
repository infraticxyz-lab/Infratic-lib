// Off-chain message signing, Sign-In With Solana and Solana Pay helpers.
// Included from Infratic-lib.h (needs Pubkey and Keypair). The RPC based Solana Pay
// functions (findReference, validateTransfer, createPayTransfer) are Infratic members.
#ifndef INFRATIC_OFFCHAIN_H
#define INFRATIC_OFFCHAIN_H

// ============================================================================
// OFF-CHAIN MESSAGE SIGNING (Solana off-chain message spec, version 0)
// ============================================================================

/** Message format byte of an off-chain message */
enum class OffchainFormat : uint8_t
{
    RestrictedAscii = 0, // printable ASCII 0x20-0x7e, fits one 1232 byte hardware wallet frame
    Utf8Limited = 1,     // UTF-8, fits one 1232 byte hardware wallet frame
    Utf8Extended = 2     // UTF-8, up to 65535 bytes
};

/** Parsed / to-be-built off-chain message (version 0) */
struct OffchainMessage
{
    uint8_t version;                       // only 0 is supported
    std::vector<uint8_t> applicationDomain; // 32 bytes (a base58 address in Solana tooling)
    OffchainFormat format;
    std::vector<Pubkey> signers;           // required signers (1..255)
    std::vector<uint8_t> body;             // message text bytes

    OffchainMessage() : version(0), applicationDomain(32, 0), format(OffchainFormat::RestrictedAscii) {}
};

/**
 * Static helpers. "content" is the byte string that is signed:
 * "\xffsolana offchain" | version | application domain (32) | format | signer count |
 * signer pubkeys | message length (u16 LE) | message.
 * An "envelope" is: signature count (u8) | 64 byte signatures (one per signer, in signer
 * order, all zero = not signed yet) | content. Reference: @solana/offchain-messages.
 */
class Offchain
{
public:
    /** @brief Max body bytes for a format and signer count (0 = does not fit at all) */
    static size_t maxBodyLength(OffchainFormat format, size_t signerCount);

    /** @brief Checks version, domain, signers, format rules (ASCII range, UTF-8, length limits) */
    static bool validate(const OffchainMessage &msg, String *outError = nullptr);

    /** @brief Convenience: message with a base58 application domain and one signer */
    static bool make(const String &applicationDomainBase58, OffchainFormat format, const Pubkey &signer,
                     const String &text, OffchainMessage &outMsg);

    /** @brief Serializes the content to sign. false (and outError) if the message is invalid */
    static bool build(const OffchainMessage &msg, std::vector<uint8_t> &outContent, String *outError = nullptr);

    /** @brief Parses and validates content bytes (also checks the length field and trailing bytes) */
    static bool parse(const std::vector<uint8_t> &content, OffchainMessage &outMsg, String *outError = nullptr);

    /** @brief Signs content with keypair; the keypair must be one of the required signers */
    static bool sign(const std::vector<uint8_t> &content, const Keypair &keypair, uint8_t outSignature[64],
                     String *outError = nullptr);

    /** @brief Checks one signature; signer must be a required signer of the content */
    static bool verify(const std::vector<uint8_t> &content, const Pubkey &signer, const uint8_t signature[64]);

    /** @brief Signs with every given keypair (missing signers stay zero) and builds the envelope */
    static bool buildEnvelope(const std::vector<uint8_t> &content, const std::vector<Keypair> &signers,
                              std::vector<uint8_t> &outEnvelope, String *outError = nullptr);

    /** @brief Splits an envelope into content and signatures (checks counts against the content) */
    static bool parseEnvelope(const std::vector<uint8_t> &envelope, std::vector<uint8_t> &outContent,
                              std::vector<std::vector<uint8_t>> &outSignatures, String *outError = nullptr);

    /** @brief true if every required signer has a valid signature */
    static bool verifyEnvelope(const std::vector<uint8_t> &envelope, String *outError = nullptr);
};

// ============================================================================
// SIGN-IN WITH SOLANA (SIWS, as used by Phantom and @solana/wallet-standard-util)
// ============================================================================

/** Fields of a SIWS message. An empty String / empty vector means "not present". */
struct SignInMessage
{
    String domain;  // requesting site, e.g. "example.com"
    String address; // base58 account that signs in
    String statement;
    String uri;
    String version; // e.g. "1"
    String chainId; // e.g. "mainnet"
    String nonce;
    String issuedAt;       // ISO 8601, e.g. "2026-01-01T00:00:00.000Z"
    String expirationTime; // ISO 8601
    String notBefore;      // ISO 8601
    String requestId;
    std::vector<String> resources;
};

class Siws
{
public:
    /**
     * @brief Message text in the exact layout of createSignInMessageText().
     * Fails (empty result) if domain or address is empty or a single line field contains a newline.
     */
    static bool buildText(const SignInMessage &msg, String &outText, String *outError = nullptr);

    /** @brief Parses text like parseSignInMessageText(); false if it does not match the layout */
    static bool parse(const String &text, SignInMessage &outMsg);

    /**
     * @brief Builds the text and signs its UTF-8 bytes with ed25519 (what a wallet's signIn does).
     * If msg.address is empty it is filled from the keypair, otherwise it must match.
     */
    static bool sign(const SignInMessage &msg, const Keypair &keypair, String &outText, uint8_t outSignature[64],
                     String *outError = nullptr);

    /**
     * @brief Like verifySignIn() of @solana/wallet-standard-util: the signed text must parse, be
     * in canonical form, match `expected` (empty domain / address in expected = any, every other
     * field must be equal), the address must be the public key, and the signature must be valid.
     * @param nowUnix If non-zero also rejects an expired expirationTime or a future notBefore
     *                (an addition to the reference implementation, which does not check time).
     */
    static bool verify(const SignInMessage &expected, const std::vector<uint8_t> &signedMessage,
                       const uint8_t signature[64], const Pubkey &publicKey, int64_t nowUnix = 0,
                       String *outError = nullptr);

    /** @brief ISO 8601 "YYYY-MM-DDTHH:MM:SS[.fff](Z|+HH:MM)" to unix seconds */
    static bool parseTime(const String &iso8601, int64_t &outUnix);
};

// ============================================================================
// SOLANA PAY (transfer requests and transaction requests)
// ============================================================================

/** Transfer request fields (spec: solana:<recipient>?amount=...) */
struct PayTransfer
{
    String recipient;  // base58 wallet
    String amount;     // decimal string in SOL or token units ("1.5"), empty = not set
    String splToken;   // base58 mint, empty = native SOL
    std::vector<String> references; // base58 read-only reference keys
    String label;
    String message;
    String memo;
};

/** Transaction request: solana:<https link>?label=...&message=... */
struct PayTransactionRequest
{
    String link;
    String label;
    String message;
};

enum class PayUrlKind : uint8_t
{
    Invalid = 0,
    Transfer = 1,
    Transaction = 2
};

class SolanaPay
{
public:
    /** @brief Encodes a transfer request URL (like encodeURL of @solana/pay). Empty String if invalid */
    static String encodeTransfer(const PayTransfer &req, String *outError = nullptr);

    /** @brief Encodes a transaction request URL; link must be a normalized https URL */
    static String encodeTransactionRequest(const PayTransactionRequest &req, String *outError = nullptr);

    /** @brief Parses either kind of URL (like parseURL of @solana/pay) */
    static PayUrlKind parse(const String &url, PayTransfer &outTransfer, PayTransactionRequest &outTransaction,
                            String *outError = nullptr);

    static bool parseTransfer(const String &url, PayTransfer &outTransfer, String *outError = nullptr);
    static bool parseTransactionRequest(const String &url, PayTransactionRequest &outTx, String *outError = nullptr);

    /**
     * @brief Decimal amount string ("1.5") to base units. false if it is not a plain decimal or
     * overflows u64. More fraction digits than `decimals`: false, or rounded up when roundUp.
     */
    static bool amountToBaseUnits(const String &amount, uint8_t decimals, uint64_t &outUnits, bool roundUp = false);
};

#endif // INFRATIC_OFFCHAIN_H
