// Versioned (v0) transactions and Address Lookup Tables.
#include "infratic_internal.h"

using infratic_detail::CompiledKey;

std::vector<uint8_t> Transaction::serializeMessageV0() const
{
    if (fee_payer.data.size() != 32)
    {
        _logErr.println("❌ Transaction: fee payer not set");
        return {};
    }

    uint8_t legacyHeader[3];
    std::vector<CompiledKey> keys = infratic_detail::compileKeys(*this, legacyHeader);

    uint8_t blockhash[32];
    size_t bhLen = sizeof(blockhash);
    if (!base58Decode(recent_blockhash, blockhash, bhLen) || bhLen != 32)
    {
        _logErr.println("❌ Transaction: invalid recent blockhash");
        return {};
    }

    auto isProgram = [&](const Pubkey &k)
    {
        for (const auto &ix : instructions)
            if (ix.programId.data == k.data) return true;
        return false;
    };

    // which non-signer, non-program accounts can be loaded from a table
    struct Lookup
    {
        const AddressLookupTable *table;
        std::vector<uint8_t> writableIdx, readonlyIdx;
        std::vector<Pubkey> writableKeys, readonlyKeys;
    };
    std::vector<Lookup> lookups;
    std::vector<bool> fromTable(keys.size(), false);

    for (const auto &table : lookupTables)
    {
        Lookup l{&table, {}, {}, {}, {}};
        for (int pass = 0; pass < 2; pass++) // writable first, then readonly
        {
            bool wantWritable = pass == 0;
            for (size_t i = 0; i < keys.size(); i++)
            {
                const CompiledKey &k = keys[i];
                if (fromTable[i] || k.signer || k.writable != wantWritable || isProgram(k.key))
                    continue;
                for (size_t t = 0; t < table.addresses.size() && t < 256; t++)
                {
                    if (table.addresses[t].data == k.key.data)
                    {
                        fromTable[i] = true;
                        (wantWritable ? l.writableIdx : l.readonlyIdx).push_back((uint8_t)t);
                        (wantWritable ? l.writableKeys : l.readonlyKeys).push_back(k.key);
                        break;
                    }
                }
            }
        }
        if (!l.writableIdx.empty() || !l.readonlyIdx.empty())
        {
            lookups.push_back(l);
        }
    }

    // static keys keep the legacy ordering
    std::vector<Pubkey> account;
    uint8_t header[3] = {0, 0, 0};
    for (size_t i = 0; i < keys.size(); i++)
    {
        if (fromTable[i]) continue;
        const CompiledKey &k = keys[i];
        if (k.key.data.size() != 32)
        {
            _logErr.println("❌ Transaction: invalid public key in accounts");
            return {};
        }
        account.push_back(k.key);
        if (k.signer)
        {
            header[0]++;
            if (!k.writable) header[1]++;
        }
        else if (!k.writable)
        {
            header[2]++;
        }
    }
    size_t staticCount = account.size();
    for (const auto &l : lookups) account.insert(account.end(), l.writableKeys.begin(), l.writableKeys.end());
    for (const auto &l : lookups) account.insert(account.end(), l.readonlyKeys.begin(), l.readonlyKeys.end());
    if (account.size() > 256)
    {
        _logErr.println("❌ Transaction: too many accounts");
        return {};
    }

    auto indexOf = [&](const Pubkey &k) -> int
    {
        for (size_t i = 0; i < account.size(); i++)
            if (account[i].data == k.data) return (int)i;
        return -1;
    };

    std::vector<uint8_t> msg;
    msg.push_back(0x80); // version prefix: v0
    msg.insert(msg.end(), header, header + 3);
    appendCompactU16(msg, staticCount);
    for (size_t i = 0; i < staticCount; i++)
    {
        msg.insert(msg.end(), account[i].data.begin(), account[i].data.end());
    }
    msg.insert(msg.end(), blockhash, blockhash + 32);

    appendCompactU16(msg, instructions.size());
    for (const auto &ix : instructions)
    {
        msg.push_back((uint8_t)indexOf(ix.programId));
        appendCompactU16(msg, ix.accounts.size());
        for (const auto &acct : ix.accounts)
        {
            msg.push_back((uint8_t)indexOf(acct.pubkey));
        }
        appendCompactU16(msg, ix.data.size());
        msg.insert(msg.end(), ix.data.begin(), ix.data.end());
    }

    appendCompactU16(msg, lookups.size());
    for (const auto &l : lookups)
    {
        msg.insert(msg.end(), l.table->key.data.begin(), l.table->key.data.end());
        appendCompactU16(msg, l.writableIdx.size());
        msg.insert(msg.end(), l.writableIdx.begin(), l.writableIdx.end());
        appendCompactU16(msg, l.readonlyIdx.size());
        msg.insert(msg.end(), l.readonlyIdx.begin(), l.readonlyIdx.end());
    }
    return msg;
}

bool Infratic::getAddressLookupTable(const String &tableBase58, AddressLookupTable &outTable)
{
    const size_t META_SIZE = 56;
    std::vector<uint8_t> data;
    String owner;
    if (!getAccountData(tableBase58, data, "confirmed", &owner))
    {
        return false;
    }
    if (owner != INFRATIC_ADDRESS_LOOKUP_TABLE_PROGRAM_ID || data.size() < META_SIZE ||
        (data.size() - META_SIZE) % 32 != 0)
    {
        _logErr.println("❌ Not an address lookup table: " + tableBase58);
        return false;
    }

    outTable.key = Pubkey::fromBase58(tableBase58);
    outTable.addresses.clear();
    for (size_t off = META_SIZE; off + 32 <= data.size(); off += 32)
    {
        outTable.addresses.push_back(Pubkey{std::vector<uint8_t>(data.begin() + off, data.begin() + off + 32)});
    }
    _logInfo.printf("📇 Lookup table with %u addresses\n", (unsigned)outTable.addresses.size());
    return true;
}

bool Infratic::createLookupTableIx(const String &authorityBase58, const String &payerBase58, uint64_t recentSlot,
                                   Instruction &outIx, String &outTable)
{
    Pubkey authority = Pubkey::fromBase58(authorityBase58);
    Pubkey payer = Pubkey::fromBase58(payerBase58);
    if (authority.data.size() != 32 || payer.data.size() != 32)
    {
        return false;
    }

    uint8_t bump;
    if (!derivePDA({authority.data, encodeU64LE(recentSlot)}, INFRATIC_ADDRESS_LOOKUP_TABLE_PROGRAM_ID, outTable, bump))
    {
        return false;
    }

    // ProgramInstruction::CreateLookupTable = 0: recent_slot u64, bump u8
    std::vector<uint8_t> data = encodeU32LE(0);
    std::vector<uint8_t> slot = encodeU64LE(recentSlot);
    data.insert(data.end(), slot.begin(), slot.end());
    data.push_back(bump);

    outIx = Instruction(Pubkey::fromBase58(INFRATIC_ADDRESS_LOOKUP_TABLE_PROGRAM_ID),
                        {AccountMeta::writable(Pubkey::fromBase58(outTable), false),
                         AccountMeta::signer(authority),
                         AccountMeta::writable(payer, true),
                         AccountMeta{Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), false, false}},
                        data);
    return true;
}

Instruction Infratic::extendLookupTableIx(const Pubkey &table, const Pubkey &authority, const Pubkey &payer,
                                         const std::vector<Pubkey> &newAddresses)
{
    // ProgramInstruction::ExtendLookupTable = 2: Vec<Pubkey> (u64 length)
    std::vector<uint8_t> data = encodeU32LE(2);
    std::vector<uint8_t> count = encodeU64LE(newAddresses.size());
    data.insert(data.end(), count.begin(), count.end());
    for (const auto &a : newAddresses)
    {
        data.insert(data.end(), a.data.begin(), a.data.end());
    }

    return Instruction(Pubkey::fromBase58(INFRATIC_ADDRESS_LOOKUP_TABLE_PROGRAM_ID),
                       {AccountMeta::writable(table, false),
                        AccountMeta::signer(authority),
                        AccountMeta::writable(payer, true),
                        AccountMeta{Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID), false, false}},
                       data);
}
