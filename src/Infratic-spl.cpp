// SPL Token support (Token Program and Token-2022) and the shared send helper.
#include "infratic_internal.h"

Keypair Keypair::fromBase58(const String &secretKeyBase58)
{
    uint8_t buf[128];
    size_t len = sizeof(buf);
    if (!base58Decode(secretKeyBase58, buf, len) || len < 64)
    {
        _logErr.println("❌ Invalid Base58 secret key");
        return Keypair();
    }
    return Keypair::fromPrivateKey(buf);
}

bool Infratic::signAndSend(Transaction &tx, const std::vector<Keypair> &signers, String &outSignature,
                           uint32_t confirmWaitMs)
{
    if (signers.empty() || signers[0].privkey.size() < 64)
    {
        _logErr.println("❌ signAndSend: no valid signer");
        return false;
    }
    if (tx.fee_payer.data.size() != 32)
    {
        tx.fee_payer = signers[0].pubkey();
    }
    if (tx.recent_blockhash.isEmpty())
    {
        tx.recent_blockhash = getLatestBlockhash();
        if (tx.recent_blockhash.isEmpty())
        {
            return false;
        }
    }

    applyPriorityFee(tx);
    if (!tx.sign(signers))
    {
        return false;
    }

    String txBase64 = tx.serializeBase64();
    if (txBase64.isEmpty() || !sendRawTransaction(txBase64, outSignature))
    {
        return false;
    }

    _logInfo.println("📤 Sent: " + outSignature);
    return confirmWaitMs == 0 || confirmTransaction(outSignature, confirmWaitMs);
}

bool Infratic::getAssociatedTokenAddress(const String &ownerBase58, const String &mintBase58, String &outAta,
                                         const String &tokenProgramId)
{
    std::vector<uint8_t> owner = base58ToPubkey(ownerBase58);
    std::vector<uint8_t> mint = base58ToPubkey(mintBase58);
    std::vector<uint8_t> tokenProgram = base58ToPubkey(tokenProgramId);
    if (owner.size() != 32 || mint.size() != 32 || tokenProgram.size() != 32)
    {
        _logErr.println("❌ getAssociatedTokenAddress: invalid address");
        return false;
    }

    uint8_t bump;
    return derivePDA({owner, tokenProgram, mint}, INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID, outAta, bump);
}

Instruction Infratic::createAssociatedTokenAccountIdempotentIx(const Pubkey &payer, const Pubkey &ata,
                                                              const Pubkey &owner, const Pubkey &mint,
                                                              const Pubkey &tokenProgram)
{
    // instruction 1 = CreateIdempotent
    return Instruction(Pubkey::fromBase58(INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID),
                       {AccountMeta::writable(payer, true),
                        AccountMeta::writable(ata, false),
                        AccountMeta{owner, false, false},
                        AccountMeta{mint, false, false},
                        AccountMeta{Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), false, false},
                        AccountMeta{tokenProgram, false, false}},
                       {1});
}

Instruction Infratic::transferCheckedIx(const Pubkey &source, const Pubkey &mint, const Pubkey &destination,
                                       const Pubkey &owner, uint64_t amount, uint8_t decimals,
                                       const Pubkey &tokenProgram)
{
    // instruction 12 = TransferChecked: u8 tag + u64 amount + u8 decimals
    std::vector<uint8_t> data = {12};
    std::vector<uint8_t> amountBytes = encodeU64LE(amount);
    data.insert(data.end(), amountBytes.begin(), amountBytes.end());
    data.push_back(decimals);

    return Instruction(tokenProgram,
                       {AccountMeta::writable(source, false),
                        AccountMeta{mint, false, false},
                        AccountMeta::writable(destination, false),
                        AccountMeta::signer(owner)},
                       data);
}

bool Infratic::sendSplToken(const String &privateKeyBase58, const String &fromOwnerBase58,
                            const String &toOwnerBase58, const String &mintBase58, uint64_t amount,
                            String &outSignature, int decimals, bool createDestinationAta,
                            const String &tokenProgramId)
{
    _logInfo.println("\n=== Send SPL Token ===");

    Keypair signer = Keypair::fromBase58(privateKeyBase58);
    if (signer.privkey.empty())
    {
        return false;
    }

    if (decimals < 0)
    {
        uint8_t d = 0;
        if (!getTokenDecimals(mintBase58, d))
        {
            _logErr.println("❌ Could not read mint decimals");
            return false;
        }
        decimals = d;
    }

    String sourceAta, destinationAta;
    if (!getAssociatedTokenAddress(fromOwnerBase58, mintBase58, sourceAta, tokenProgramId) ||
        !getAssociatedTokenAddress(toOwnerBase58, mintBase58, destinationAta, tokenProgramId))
    {
        return false;
    }

    Pubkey from = Pubkey::fromBase58(fromOwnerBase58);
    Pubkey to = Pubkey::fromBase58(toOwnerBase58);
    Pubkey mint = Pubkey::fromBase58(mintBase58);
    Pubkey tokenProgram = Pubkey::fromBase58(tokenProgramId);
    Pubkey destination = Pubkey::fromBase58(destinationAta);

    Transaction tx;
    tx.fee_payer = from;
    if (createDestinationAta)
    {
        tx.add(createAssociatedTokenAccountIdempotentIx(from, destination, to, mint, tokenProgram));
    }
    tx.add(transferCheckedIx(Pubkey::fromBase58(sourceAta), mint, destination, from, amount,
                             (uint8_t)decimals, tokenProgram));

    _logInfo.printf("   Amount: %llu (decimals %d)\n", (unsigned long long)amount, decimals);
    _logInfo.println("   From ATA: " + sourceAta);
    _logInfo.println("   To ATA:   " + destinationAta);

    return signAndSend(tx, {signer}, outSignature);
}
