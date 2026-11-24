// Parsing, safe signing and human-readable decoding of transactions built elsewhere
// (dApp / phone). Included from Infratic-lib.h, do not include directly.
#ifndef INFRATIC_TXDECODE_H
#define INFRATIC_TXDECODE_H

#include <stdint.h>
#include <vector>
#include <Arduino.h>

#define INFRATIC_MAX_TX_SIZE 1232 // Solana packet limit for a serialized transaction

#define INFRATIC_MEMO_PROGRAM_ID "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
#define INFRATIC_MEMO_V1_PROGRAM_ID "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"

struct ParsedInstruction
{
    uint8_t programIdIndex;
    std::vector<uint8_t> accountIndexes;
    std::vector<uint8_t> data;
    ParsedInstruction() : programIdIndex(0) {}
};

/** One address table reference of a v0 message */
struct LookupTableRef
{
    String table; // Base58 address of the lookup table
    std::vector<uint8_t> writableIndexes;
    std::vector<uint8_t> readonlyIndexes;
    // Optional: the table contents (Base58), set with ParsedTransaction::setLookupTable().
    // Empty = unresolved, the loaded accounts are unknown offline.
    std::vector<String> addresses;
};

/** Human-readable view of one instruction for a confirmation screen */
struct DecodedInstruction
{
    String program;     // "system", "spl-token", "token-2022", "compute-budget", "memo", "associated-token", "unknown"
    String type;        // "transfer", "transferChecked", "setComputeUnitPrice", ..., "unknown"
    String summary;     // e.g. "Transfer 0.25 SOL to 9WzD...AWWM"
    String programId;   // Base58 (or "lookup:<table>[i]" if unresolved, never for valid messages)
    bool known;         // false: unrecognised program or instruction, a wallet should warn
    bool resolved;      // false: some accounts come from an unresolved lookup table
    String source, destination, authority, mint, owner; // Base58, empty if not applicable or unresolved
    uint64_t amount;    // lamports / raw token units / microLamports / compute units
    int decimals;       // -1 if not part of the instruction
    String text;        // memo text
    DecodedInstruction() : known(false), resolved(true), amount(0), decimals(-1) {}
};

/** Fee and SOL outflow estimate for one signer, see ParsedTransaction::estimateCost() */
struct TxCostEstimate
{
    uint64_t baseFee = 0;            // 5000 lamports * required signatures
    uint64_t priorityFee = 0;        // from the compute budget instructions
    uint64_t lamportsTransferred = 0; // System transfers out of the signer
    uint64_t lamportsFunded = 0;      // System createAccount funded by the signer (rent + deposit)
    uint64_t totalLamports = 0;       // sum of the above (saturating)
    uint32_t computeUnitLimit = 0;    // used for the priority fee (requested, or default estimate)
    uint64_t microLamportsPerCU = 0;
    bool limitRequested = false;      // false: the limit is a default estimate (200k per instruction)
    // false if some instruction is not understood (it may move more SOL) or the signer
    // funds an associated token account (its rent is not counted)
    bool complete = true;
};

class ParsedTransaction
{
public:
    bool isVersioned = false; // true: v0 message
    uint8_t numRequiredSignatures = 0, numReadonlySigned = 0, numReadonlyUnsigned = 0;
    std::vector<String> staticKeys;
    String recentBlockhash;
    std::vector<ParsedInstruction> instructions;
    std::vector<LookupTableRef> lookups;
    std::vector<std::vector<uint8_t>> signatures; // 64 bytes each, all zero = missing
    std::vector<uint8_t> message;                 // the exact bytes that are signed

    /** @brief Parses a Base64 wire-format transaction. Rejects anything malformed (see fromBytes). */
    bool fromBase64(const String &b64);
    /**
     * @brief Parses a wire-format transaction (signatures + message), legacy or v0.
     * Strict: bounds checks everywhere, canonical compact-u16, no trailing bytes, at most
     * 1232 bytes. Leaves the object empty and returns false on any error.
     */
    bool fromBytes(const std::vector<uint8_t> &raw);
    /** @brief Short reason of the last failed parse, empty after success */
    const String &error() const { return _error; }

    /** @brief Wire format, byte for byte what was parsed (plus any signatures added since) */
    std::vector<uint8_t> serialize() const;
    String toBase64() const;

    /** @brief Index of the key among the required signers, -1 if it is not one */
    int signerIndex(const Pubkey &key) const;
    int signerIndex(const String &base58) const;
    /** @brief Signs the message and stores the signature in the key's slot. False if not a required signer. */
    bool sign(const Keypair &keypair);
    /**
     * @brief True if every signature that is present is valid.
     * @param outMissing optional, receives the signer slots without a signature
     */
    bool verifySignatures(std::vector<uint8_t> *outMissing = nullptr) const;
    /** @brief All required signatures present and valid */
    bool isFullySigned() const;

    /** @brief Provides the contents of a lookup table so loaded accounts can be resolved. False if the table is not referenced. */
    bool setLookupTable(const String &tableBase58, const std::vector<String> &addresses);
    /** @brief Number of accounts of the message (static + loaded from tables) */
    size_t accountCount() const;
    /** @brief Base58 address of account `index`, empty if it comes from an unresolved table or is out of range */
    String accountKey(size_t index) const;
    bool isSignerIndex(size_t index) const { return index < numRequiredSignatures; }
    bool isWritableIndex(size_t index) const;

    /** @brief Decodes one instruction into a summary. Unrecognised ones get program/type "unknown". */
    DecodedInstruction decodeInstruction(size_t index) const;
    std::vector<DecodedInstruction> decodeAll() const;

    /** @brief Fee and SOL leaving `signer` (Base58). */
    TxCostEstimate estimateCost(const String &signer) const;

    /** @brief Formats lamports as SOL, e.g. 250000000 -> "0.25 SOL" */
    static String formatSol(uint64_t lamports);
    /** @brief Formats a raw token amount with its decimals, e.g. (1500000, 6) -> "1.5" */
    static String formatUnits(uint64_t amount, int decimals);
    /** @brief "9WzD...AWWM" */
    static String shortKey(const String &base58);

private:
    String _error;
    void clear();
    bool fail(const char *why);
    bool parseMessage(size_t sigCount);
};

#endif
