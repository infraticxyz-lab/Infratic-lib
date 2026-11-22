// Durable nonce support and keypair helpers.
#include "infratic_internal.h"

Keypair Keypair::fromSeed(const uint8_t seed[32])
{
    uint8_t key[64];
    memcpy(key, seed, 32);
    Ed25519::derivePublicKey(key + 32, key);
    return Keypair::fromPrivateKey(key);
}

Keypair Keypair::generate()
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i += 4)
    {
        uint32_t r = esp_random();
        memcpy(seed + i, &r, 4);
    }
    Keypair kp = fromSeed(seed);
    memset(seed, 0, sizeof(seed));
    return kp;
}

String Keypair::secretBase58() const
{
    return privkey.size() < 64 ? String("") : base58Encode(privkey.data(), 64);
}

String Keypair::publicBase58() const
{
    return pubkey_.data.size() != 32 ? String("") : base58Encode(pubkey_.data.data(), 32);
}

Instruction Infratic::nonceAdvanceIx(const Pubkey &nonceAccount, const Pubkey &authority)
{
    // SystemInstruction::AdvanceNonceAccount = 4
    return Instruction(Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID),
                       {AccountMeta::writable(nonceAccount, false),
                        AccountMeta{Pubkey::fromBase58(INFRATIC_SYSVAR_RECENT_BLOCKHASHES_ID), false, false},
                        AccountMeta::signer(authority)},
                       encodeU32LE(4));
}

bool Infratic::createNonceAccount(const String &payerPrivateKeyBase58, const Keypair &nonceAccount,
                                  const String &authorityBase58, String &outSignature)
{
    _logInfo.println("\n=== Create Nonce Account ===");

    Keypair payer = Keypair::fromBase58(payerPrivateKeyBase58);
    Pubkey authority = Pubkey::fromBase58(authorityBase58);
    if (payer.privkey.empty() || nonceAccount.privkey.size() < 64 || authority.data.size() != 32)
    {
        _logErr.println("❌ createNonceAccount: invalid keys");
        return false;
    }

    uint64_t rent = 0;
    if (!getMinimumBalanceForRentExemption(NONCE_ACCOUNT_SPACE, rent))
    {
        _logErr.println("❌ Could not get rent for nonce account");
        return false;
    }

    Pubkey system = Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID);

    // SystemInstruction::CreateAccount = 0: lamports, space, owner
    std::vector<uint8_t> create = encodeU32LE(0);
    std::vector<uint8_t> lamports = encodeU64LE(rent);
    std::vector<uint8_t> space = encodeU64LE(NONCE_ACCOUNT_SPACE);
    create.insert(create.end(), lamports.begin(), lamports.end());
    create.insert(create.end(), space.begin(), space.end());
    create.insert(create.end(), system.data.begin(), system.data.end());

    // SystemInstruction::InitializeNonceAccount = 6: authority
    std::vector<uint8_t> init = encodeU32LE(6);
    init.insert(init.end(), authority.data.begin(), authority.data.end());

    Transaction tx;
    tx.fee_payer = payer.pubkey();
    tx.add(Instruction(system, {AccountMeta::writable(payer.pubkey(), true),
                                AccountMeta::writable(nonceAccount.pubkey(), true)}, create));
    tx.add(Instruction(system, {AccountMeta::writable(nonceAccount.pubkey(), false),
                                AccountMeta{Pubkey::fromBase58(INFRATIC_SYSVAR_RECENT_BLOCKHASHES_ID), false, false},
                                AccountMeta{Pubkey::fromBase58(INFRATIC_SYSVAR_RENT_ID), false, false}}, init));

    _logInfo.println("   Nonce account: " + nonceAccount.publicBase58());
    return signAndSend(tx, {payer, nonceAccount}, outSignature);
}

bool Infratic::getNonce(const String &nonceAccountBase58, NonceInfo &outInfo)
{
    std::vector<uint8_t> data;
    String owner;
    if (!getAccountData(nonceAccountBase58, data, "confirmed", &owner))
    {
        return false;
    }
    if (owner != INFRATIC_SYSTEM_PROGRAM_ID || data.size() < NONCE_ACCOUNT_SPACE)
    {
        _logErr.println("❌ Not a nonce account: " + nonceAccountBase58);
        return false;
    }

    uint32_t state = data[4] | (data[5] << 8) | (data[6] << 16) | ((uint32_t)data[7] << 24);
    if (state != 1)
    {
        _logErr.println("❌ Nonce account is not initialized");
        return false;
    }

    outInfo.authority = base58Encode(data.data() + 8, 32);
    outInfo.nonce = base58Encode(data.data() + 40, 32);
    outInfo.lamportsPerSignature = 0;
    for (int i = 0; i < 8; i++)
    {
        outInfo.lamportsPerSignature |= (uint64_t)data[72 + i] << (8 * i);
    }
    return true;
}

bool Infratic::useDurableNonce(Transaction &tx, const String &nonceAccountBase58, const String &authorityBase58,
                               const String &nonce)
{
    String value = nonce;
    if (value.isEmpty())
    {
        NonceInfo info;
        if (!getNonce(nonceAccountBase58, info))
        {
            return false;
        }
        if (info.authority != authorityBase58)
        {
            _logErr.println("❌ Nonce authority mismatch: " + info.authority);
            return false;
        }
        value = info.nonce;
    }

    tx.recent_blockhash = value;
    tx.instructions.insert(tx.instructions.begin(),
                           nonceAdvanceIx(Pubkey::fromBase58(nonceAccountBase58), Pubkey::fromBase58(authorityBase58)));
    _logInfo.println("🔒 Durable nonce: " + value);
    return true;
}
