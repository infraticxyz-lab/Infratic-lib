// Static instruction builders: System program, SPL Token / Token-2022, ATA create, Memo, plus wrapSol / unwrapSol.
#include "infratic_internal.h"
#include <mbedtls/version.h>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
#define mbedtls_sha256_starts_ret mbedtls_sha256_starts
#define mbedtls_sha256_update_ret mbedtls_sha256_update
#define mbedtls_sha256_finish_ret mbedtls_sha256_finish
#endif

#define INFRATIC_NATIVE_MINT "So11111111111111111111111111111111111111112"
#define INFRATIC_NATIVE_MINT_2022 "9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP"

// Token-2022 has its own native (wrapped SOL) mint
static const char *nativeMintFor(const String &tokenProgramId)
{
    return tokenProgramId == INFRATIC_TOKEN_2022_PROGRAM_ID ? INFRATIC_NATIVE_MINT_2022 : INFRATIC_NATIVE_MINT;
}

namespace
{
    Pubkey sysProgram() { return Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID); }

    void putU32(std::vector<uint8_t> &d, uint32_t v)
    {
        for (int i = 0; i < 4; i++) d.push_back((uint8_t)(v >> (8 * i)));
    }
    void putU64(std::vector<uint8_t> &d, uint64_t v)
    {
        for (int i = 0; i < 8; i++) d.push_back((uint8_t)(v >> (8 * i)));
    }
    void putKey(std::vector<uint8_t> &d, const Pubkey &k)
    {
        // short keys are zero padded so the layout never shifts
        for (size_t i = 0; i < 32; i++) d.push_back(i < k.data.size() ? k.data[i] : 0);
    }
    // System program Rust-style string: u64 length + bytes
    void putStr(std::vector<uint8_t> &d, const String &s)
    {
        putU64(d, (uint64_t)s.length());
        for (size_t i = 0; i < (size_t)s.length(); i++) d.push_back((uint8_t)s[i]);
    }
    AccountMeta ro(const Pubkey &k) { return AccountMeta{k, false, false}; }
    AccountMeta wr(const Pubkey &k) { return AccountMeta::writable(k, false); }
    AccountMeta sig(const Pubkey &k) { return AccountMeta::signer(k); }
    AccountMeta wrSig(const Pubkey &k) { return AccountMeta::writable(k, true); }

    bool samePubkey(const Pubkey &a, const Pubkey &b) { return a.data == b.data; }

    // tag + u64 amount (+ decimals)
    std::vector<uint8_t> amountData(uint8_t tag, uint64_t amount, bool withDecimals, uint8_t decimals)
    {
        std::vector<uint8_t> d(1, tag);
        putU64(d, amount);
        if (withDecimals) d.push_back(decimals);
        return d;
    }
}

// ============================================================================
// SYSTEM PROGRAM
// ============================================================================

Instruction SystemProgram::transferIx(const Pubkey &from, const Pubkey &to, uint64_t lamports)
{
    std::vector<uint8_t> d;
    putU32(d, 2);
    putU64(d, lamports);
    return Instruction(sysProgram(), {wrSig(from), wr(to)}, d);
}

Instruction SystemProgram::createAccountIx(const Pubkey &from, const Pubkey &newAccount, uint64_t lamports,
                                           uint64_t space, const Pubkey &owner)
{
    std::vector<uint8_t> d;
    putU32(d, 0);
    putU64(d, lamports);
    putU64(d, space);
    putKey(d, owner);
    return Instruction(sysProgram(), {wrSig(from), wrSig(newAccount)}, d);
}

Instruction SystemProgram::assignIx(const Pubkey &account, const Pubkey &owner)
{
    std::vector<uint8_t> d;
    putU32(d, 1);
    putKey(d, owner);
    return Instruction(sysProgram(), {wrSig(account)}, d);
}

Instruction SystemProgram::allocateIx(const Pubkey &account, uint64_t space)
{
    std::vector<uint8_t> d;
    putU32(d, 8);
    putU64(d, space);
    return Instruction(sysProgram(), {wrSig(account)}, d);
}

Instruction SystemProgram::createAccountWithSeedIx(const Pubkey &from, const Pubkey &newAccount, const Pubkey &base,
                                                   const String &seed, uint64_t lamports, uint64_t space,
                                                   const Pubkey &owner)
{
    std::vector<uint8_t> d;
    putU32(d, 3);
    putKey(d, base);
    putStr(d, seed);
    putU64(d, lamports);
    putU64(d, space);
    putKey(d, owner);
    std::vector<AccountMeta> keys = {wrSig(from), wr(newAccount)};
    if (!samePubkey(base, from)) keys.push_back(sig(base));
    return Instruction(sysProgram(), keys, d);
}

Instruction SystemProgram::transferWithSeedIx(const Pubkey &from, const Pubkey &base, const String &seed,
                                              const Pubkey &seedOwner, const Pubkey &to, uint64_t lamports)
{
    std::vector<uint8_t> d;
    putU32(d, 11);
    putU64(d, lamports);
    putStr(d, seed);
    putKey(d, seedOwner);
    return Instruction(sysProgram(), {wr(from), sig(base), wr(to)}, d);
}

bool SystemProgram::createWithSeed(const Pubkey &base, const String &seed, const Pubkey &programId, String &outBase58)
{
    static const char marker[] = "ProgramDerivedAddress";
    const size_t markerLen = sizeof(marker) - 1;
    if (seed.length() > 32 || base.data.size() != 32 || programId.data.size() != 32)
    {
        _logErr.println("❌ createWithSeed: seed > 32 bytes or invalid address");
        return false;
    }
    // runtime rejects owners that end in the PDA marker
    if (memcmp(programId.data.data() + 32 - markerLen, marker, markerLen) == 0)
    {
        _logErr.println("❌ createWithSeed: program id must not end with ProgramDerivedAddress");
        return false;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, base.data.data(), 32);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t *)seed.c_str(), seed.length());
    mbedtls_sha256_update_ret(&ctx, programId.data.data(), 32);
    uint8_t hash[32];
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    outBase58 = base58Encode(hash, 32);
    return !outBase58.isEmpty();
}

// ============================================================================
// SPL TOKEN / TOKEN-2022
// ============================================================================

Instruction SplToken::initializeMint2Ix(const Pubkey &mint, uint8_t decimals, const Pubkey &mintAuthority,
                                        const Pubkey *freezeAuthority, const Pubkey &tokenProgram)
{
    // tag 20, decimals, mint authority, COption<Pubkey> as flag + 32 bytes (zeros when None)
    std::vector<uint8_t> d = {20, decimals};
    putKey(d, mintAuthority);
    d.push_back(freezeAuthority ? 1 : 0);
    if (freezeAuthority) putKey(d, *freezeAuthority);
    else d.insert(d.end(), 32, 0);
    return Instruction(tokenProgram, {wr(mint)}, d);
}

Instruction SplToken::initializeAccount3Ix(const Pubkey &account, const Pubkey &mint, const Pubkey &owner,
                                           const Pubkey &tokenProgram)
{
    std::vector<uint8_t> d(1, 18);
    putKey(d, owner);
    return Instruction(tokenProgram, {wr(account), ro(mint)}, d);
}

Instruction SplToken::transferIx(const Pubkey &source, const Pubkey &destination, const Pubkey &owner,
                                 uint64_t amount, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(source), wr(destination), sig(owner)}, amountData(3, amount, false, 0));
}

Instruction SplToken::mintToIx(const Pubkey &mint, const Pubkey &destination, const Pubkey &authority,
                               uint64_t amount, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(mint), wr(destination), sig(authority)}, amountData(7, amount, false, 0));
}

Instruction SplToken::mintToCheckedIx(const Pubkey &mint, const Pubkey &destination, const Pubkey &authority,
                                      uint64_t amount, uint8_t decimals, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(mint), wr(destination), sig(authority)},
                       amountData(14, amount, true, decimals));
}

Instruction SplToken::burnIx(const Pubkey &account, const Pubkey &mint, const Pubkey &owner, uint64_t amount,
                             const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), wr(mint), sig(owner)}, amountData(8, amount, false, 0));
}

Instruction SplToken::burnCheckedIx(const Pubkey &account, const Pubkey &mint, const Pubkey &owner,
                                    uint64_t amount, uint8_t decimals, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), wr(mint), sig(owner)}, amountData(15, amount, true, decimals));
}

Instruction SplToken::approveIx(const Pubkey &account, const Pubkey &delegate, const Pubkey &owner,
                                uint64_t amount, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), ro(delegate), sig(owner)}, amountData(4, amount, false, 0));
}

Instruction SplToken::approveCheckedIx(const Pubkey &account, const Pubkey &mint, const Pubkey &delegate,
                                       const Pubkey &owner, uint64_t amount, uint8_t decimals,
                                       const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), ro(mint), ro(delegate), sig(owner)},
                       amountData(13, amount, true, decimals));
}

Instruction SplToken::revokeIx(const Pubkey &account, const Pubkey &owner, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), sig(owner)}, {5});
}

Instruction SplToken::closeAccountIx(const Pubkey &account, const Pubkey &destination, const Pubkey &owner,
                                     const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), wr(destination), sig(owner)}, {9});
}

Instruction SplToken::setAuthorityIx(const Pubkey &account, AuthorityType type, const Pubkey &currentAuthority,
                                     const Pubkey *newAuthority, const Pubkey &tokenProgram)
{
    std::vector<uint8_t> d = {6, (uint8_t)type, (uint8_t)(newAuthority ? 1 : 0)};
    if (newAuthority) putKey(d, *newAuthority);
    else d.insert(d.end(), 32, 0);
    return Instruction(tokenProgram, {wr(account), sig(currentAuthority)}, d);
}

Instruction SplToken::syncNativeIx(const Pubkey &account, const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account)}, {17});
}

Instruction SplToken::freezeAccountIx(const Pubkey &account, const Pubkey &mint, const Pubkey &freezeAuthority,
                                      const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), ro(mint), sig(freezeAuthority)}, {10});
}

Instruction SplToken::thawAccountIx(const Pubkey &account, const Pubkey &mint, const Pubkey &freezeAuthority,
                                    const Pubkey &tokenProgram)
{
    return Instruction(tokenProgram, {wr(account), ro(mint), sig(freezeAuthority)}, {11});
}

Instruction SplToken::createAssociatedTokenAccountIx(const Pubkey &payer, const Pubkey &ata, const Pubkey &owner,
                                                     const Pubkey &mint, const Pubkey &tokenProgram)
{
    // the ATA program treats empty data as Create
    return Instruction(Pubkey::fromBase58(INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID),
                       {wrSig(payer), wr(ata), ro(owner), ro(mint), ro(sysProgram()), ro(tokenProgram)},
                       std::vector<uint8_t>());
}

// ============================================================================
// MEMO
// ============================================================================

Instruction MemoProgram::memoIx(const String &text, const std::vector<Pubkey> &signers)
{
    std::vector<AccountMeta> keys;
    for (size_t i = 0; i < signers.size(); i++) keys.push_back(sig(signers[i]));
    return Instruction(Pubkey::fromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), keys,
                       std::vector<uint8_t>(text.begin(), text.end()));
}

// ============================================================================
// WRAPPED SOL
// ============================================================================

bool Infratic::wrapSol(const Keypair &owner, uint64_t lamports, String &outSignature, const String &tokenProgramId)
{
    if (owner.privkey.size() < 64 || lamports == 0)
    {
        _logErr.println("❌ wrapSol: invalid owner or zero amount");
        return false;
    }
    String ataStr;
    if (!getAssociatedTokenAddress(owner.publicBase58(), nativeMintFor(tokenProgramId), ataStr, tokenProgramId))
    {
        return false;
    }
    Pubkey ata = Pubkey::fromBase58(ataStr);
    Pubkey token = Pubkey::fromBase58(tokenProgramId);

    Transaction tx;
    tx.fee_payer = owner.pubkey();
    tx.add(createAssociatedTokenAccountIdempotentIx(owner.pubkey(), ata, owner.pubkey(),
                                                    Pubkey::fromBase58(nativeMintFor(tokenProgramId)), token));
    tx.add(SystemProgram::transferIx(owner.pubkey(), ata, lamports));
    tx.add(SplToken::syncNativeIx(ata, token));
    return signAndSend(tx, {owner}, outSignature);
}

bool Infratic::unwrapSol(const Keypair &owner, String &outSignature, const String &tokenProgramId)
{
    if (owner.privkey.size() < 64)
    {
        _logErr.println("❌ unwrapSol: invalid owner");
        return false;
    }
    String ataStr;
    if (!getAssociatedTokenAddress(owner.publicBase58(), nativeMintFor(tokenProgramId), ataStr, tokenProgramId))
    {
        return false;
    }
    Transaction tx;
    tx.fee_payer = owner.pubkey();
    tx.add(SplToken::closeAccountIx(Pubkey::fromBase58(ataStr), owner.pubkey(), owner.pubkey(),
                                    Pubkey::fromBase58(tokenProgramId)));
    return signAndSend(tx, {owner}, outSignature);
}
