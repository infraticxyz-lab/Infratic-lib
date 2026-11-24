// Static instruction builders for the System, SPL Token / Token-2022, Associated Token and Memo programs.
// Pure functions: no RPC, no heap beyond the returned Instruction. Included from Infratic-lib.h.
#ifndef INFRATIC_INSTRUCTIONS_H
#define INFRATIC_INSTRUCTIONS_H

#include <stdint.h>
#include <vector>

/** Authority kinds for SplToken::setAuthorityIx (values match the on-chain enum) */
enum class AuthorityType : uint8_t
{
    MintTokens = 0,
    FreezeAccount = 1,
    AccountOwner = 2,
    CloseAccount = 3,
    TransferFeeConfig = 4, // Token-2022 only from here on
    WithheldWithdraw = 5,
    CloseMint = 6,
    InterestRate = 7,
    PermanentDelegate = 8,
    ConfidentialTransferMint = 9,
    TransferHookProgramId = 10,
    ConfidentialTransferFeeConfig = 11,
    MetadataPointer = 12,
    GroupPointer = 13,
    GroupMemberPointer = 14
};

/** System program instructions (SOL transfers, account creation) */
struct SystemProgram
{
    static Instruction transferIx(const Pubkey &from, const Pubkey &to, uint64_t lamports);
    /** @brief Creates an account owned by `owner` (both from and newAccount sign) */
    static Instruction createAccountIx(const Pubkey &from, const Pubkey &newAccount, uint64_t lamports,
                                       uint64_t space, const Pubkey &owner);
    static Instruction assignIx(const Pubkey &account, const Pubkey &owner);
    static Instruction allocateIx(const Pubkey &account, uint64_t space);
    /** @brief newAccount = createWithSeed(base, seed, owner). `base` signs (it is not added twice if it equals `from`). */
    static Instruction createAccountWithSeedIx(const Pubkey &from, const Pubkey &newAccount, const Pubkey &base,
                                               const String &seed, uint64_t lamports, uint64_t space,
                                               const Pubkey &owner);
    /** @brief Moves SOL out of an account derived with createWithSeed(base, seed, seedOwner) */
    static Instruction transferWithSeedIx(const Pubkey &from, const Pubkey &base, const String &seed,
                                          const Pubkey &seedOwner, const Pubkey &to, uint64_t lamports);
    /**
     * @brief Address of an account made with createAccountWithSeedIx: sha256(base || seed || programId)
     * @return false if the seed is longer than 32 bytes, an address is not 32 bytes, or programId is a PDA marker
     */
    static bool createWithSeed(const Pubkey &base, const String &seed, const Pubkey &programId, String &outBase58);
};

/** SPL Token / Token-2022 instructions. Pass the token program id (INFRATIC_TOKEN_PROGRAM_ID or ..._2022_...). */
struct SplToken
{
    /** @brief InitializeMint2 (no rent sysvar). Pass freezeAuthority = nullptr for none. */
    static Instruction initializeMint2Ix(const Pubkey &mint, uint8_t decimals, const Pubkey &mintAuthority,
                                         const Pubkey *freezeAuthority, const Pubkey &tokenProgram);
    /** @brief InitializeAccount3 (owner passed in data, no rent sysvar) */
    static Instruction initializeAccount3Ix(const Pubkey &account, const Pubkey &mint, const Pubkey &owner,
                                            const Pubkey &tokenProgram);
    /** @brief Unchecked Transfer. Prefer Infratic::transferCheckedIx for Token-2022 mints. */
    static Instruction transferIx(const Pubkey &source, const Pubkey &destination, const Pubkey &owner,
                                  uint64_t amount, const Pubkey &tokenProgram);
    static Instruction mintToIx(const Pubkey &mint, const Pubkey &destination, const Pubkey &authority,
                                uint64_t amount, const Pubkey &tokenProgram);
    static Instruction mintToCheckedIx(const Pubkey &mint, const Pubkey &destination, const Pubkey &authority,
                                       uint64_t amount, uint8_t decimals, const Pubkey &tokenProgram);
    static Instruction burnIx(const Pubkey &account, const Pubkey &mint, const Pubkey &owner, uint64_t amount,
                              const Pubkey &tokenProgram);
    static Instruction burnCheckedIx(const Pubkey &account, const Pubkey &mint, const Pubkey &owner,
                                     uint64_t amount, uint8_t decimals, const Pubkey &tokenProgram);
    static Instruction approveIx(const Pubkey &account, const Pubkey &delegate, const Pubkey &owner,
                                 uint64_t amount, const Pubkey &tokenProgram);
    static Instruction approveCheckedIx(const Pubkey &account, const Pubkey &mint, const Pubkey &delegate,
                                        const Pubkey &owner, uint64_t amount, uint8_t decimals,
                                        const Pubkey &tokenProgram);
    static Instruction revokeIx(const Pubkey &account, const Pubkey &owner, const Pubkey &tokenProgram);
    /** @brief Closes a token account, its lamports (and the wSOL balance) go to destination */
    static Instruction closeAccountIx(const Pubkey &account, const Pubkey &destination, const Pubkey &owner,
                                      const Pubkey &tokenProgram);
    /** @brief Pass newAuthority = nullptr to remove the authority */
    static Instruction setAuthorityIx(const Pubkey &account, AuthorityType type, const Pubkey &currentAuthority,
                                      const Pubkey *newAuthority, const Pubkey &tokenProgram);
    /** @brief Updates the token balance of a wrapped SOL account after lamports were sent to it */
    static Instruction syncNativeIx(const Pubkey &account, const Pubkey &tokenProgram);
    static Instruction freezeAccountIx(const Pubkey &account, const Pubkey &mint, const Pubkey &freezeAuthority,
                                       const Pubkey &tokenProgram);
    static Instruction thawAccountIx(const Pubkey &account, const Pubkey &mint, const Pubkey &freezeAuthority,
                                     const Pubkey &tokenProgram);
    /** @brief Associated Token Account Create (fails if it exists; see Infratic::createAssociatedTokenAccountIdempotentIx) */
    static Instruction createAssociatedTokenAccountIx(const Pubkey &payer, const Pubkey &ata, const Pubkey &owner,
                                                      const Pubkey &mint, const Pubkey &tokenProgram);
};

/** Memo program v2 */
struct MemoProgram
{
    /** @brief Memo with UTF-8 text; every listed signer must sign and is checked by the program */
    static Instruction memoIx(const String &text, const std::vector<Pubkey> &signers = std::vector<Pubkey>());
};

#endif
