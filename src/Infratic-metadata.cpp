// Token metadata: Metaplex Token Metadata accounts and the Token-2022 metadata extension.
#include "infratic_internal.h"

namespace
{
    const size_t MAX_STR = 1024;           // real limits are 32 / 10 / 200 bytes, stay defensive
    const size_t MINT_BASE_SIZE = 82;      // SPL Mint layout
    const size_t ACCOUNT_TYPE_OFFSET = 165; // multisig/account size, the account type byte follows
    const size_t DECIMALS_OFFSET = 44;
    const uint8_t ACCOUNT_TYPE_MINT = 1;
    const uint16_t EXT_METADATA_POINTER = 18;
    const uint16_t EXT_TOKEN_METADATA = 19;
    const uint8_t METAPLEX_KEY_METADATA_V1 = 4;

    bool allZero(const std::vector<uint8_t> &v, size_t off, size_t n)
    {
        for (size_t i = 0; i < n; i++)
            if (v[off + i] != 0) return false;
        return true;
    }

    // 32 byte key where all zeros means "none" (OptionalNonZeroPubkey)
    String optionalKey(BorshReader &r)
    {
        if (!r.ok || r.remaining() < 32) { r.ok = false; return ""; }
        bool zero = allZero(r.buf, r.pos, 32);
        String s = r.pubkey();
        return zero ? String("") : s;
    }
}

String TokenMetadataParser::stripNul(const String &s)
{
    size_t n = s.length();
    while (n > 0 && s[n - 1] == '\0') n--;
    return n == s.length() ? s : s.substring(0, n);
}

bool TokenMetadataParser::parseMetaplex(const std::vector<uint8_t> &data, MetaplexMetadata &out)
{
    out = MetaplexMetadata();
    BorshReader r(data);
    uint8_t key = r.u8();
    if (!r.ok || key != METAPLEX_KEY_METADATA_V1) return false;

    MetaplexMetadata m;
    m.key = key;
    m.updateAuthority = r.pubkey();
    m.mint = r.pubkey();
    m.name = stripNul(r.str(MAX_STR));
    m.symbol = stripNul(r.str(MAX_STR));
    m.uri = stripNul(r.str(MAX_STR));
    m.sellerFeeBasisPoints = r.u16();
    if (!r.ok) return false; // everything up to here is mandatory

    // The rest is optional: stop quietly at the first field that does not fit (old accounts)
    if (r.remaining() >= 1)
    {
        if (r.u8() != 0)
        {
            uint32_t n = r.u32();
            if (!r.ok || n > r.remaining() / 34) goto done;
            std::vector<MetaplexCreator> list;
            for (uint32_t i = 0; i < n; i++)
            {
                MetaplexCreator c;
                c.address = r.pubkey();
                c.verified = r.boolean();
                c.share = r.u8();
                list.push_back(c);
            }
            if (!r.ok) goto done;
            m.hasCreators = true;
            m.creators.swap(list);
        }
    }
    else goto done;

    {
        size_t save = r.pos;
        bool primary = r.boolean();
        bool mutableFlag = r.boolean();
        if (!r.ok) { r.pos = save; goto done; }
        m.primarySaleHappened = primary;
        m.isMutable = mutableFlag;
    }

    if (r.remaining() >= 1 && r.u8() != 0) // edition nonce
    {
        uint8_t v = r.u8();
        if (!r.ok) goto done;
        m.hasEditionNonce = true;
        m.editionNonce = v;
    }
    if (r.remaining() >= 1 && r.u8() != 0) // token standard
    {
        uint8_t v = r.u8();
        if (!r.ok) goto done;
        m.hasTokenStandard = true;
        m.tokenStandard = v;
    }
    if (r.remaining() >= 1 && r.u8() != 0) // collection
    {
        bool verified = r.boolean();
        String k = r.pubkey();
        if (!r.ok) goto done;
        m.hasCollection = true;
        m.collectionVerified = verified;
        m.collectionKey = k;
    }
    if (r.remaining() >= 1 && r.u8() != 0) // uses
    {
        uint8_t method = r.u8();
        uint64_t remaining = r.u64();
        uint64_t total = r.u64();
        if (!r.ok) goto done;
        m.hasUses = true;
        m.useMethod = method;
        m.usesRemaining = remaining;
        m.usesTotal = total;
    }

done:
    out = m;
    return true;
}

bool TokenMetadataParser::parseToken2022(const std::vector<uint8_t> &d, Token2022Metadata &out)
{
    out = Token2022Metadata();
    if (d.size() < MINT_BASE_SIZE) return false;
    out.decimals = d[DECIMALS_OFFSET];
    // extensions: padding up to 165, account type byte, then TLV entries
    if (d.size() <= ACCOUNT_TYPE_OFFSET + 1 || d[ACCOUNT_TYPE_OFFSET] != ACCOUNT_TYPE_MINT) return false;

    size_t pos = ACCOUNT_TYPE_OFFSET + 1;
    while (pos + 4 <= d.size())
    {
        uint16_t type = d[pos] | (d[pos + 1] << 8);
        size_t len = d[pos + 2] | (d[pos + 3] << 8);
        pos += 4;
        if (type == 0 && len == 0) break;          // uninitialized padding
        if (len > d.size() - pos) break;           // truncated entry
        if (type == EXT_METADATA_POINTER && len >= 64)
        {
            std::vector<uint8_t> v(d.begin() + pos, d.begin() + pos + len);
            BorshReader r(v);
            out.pointerAuthority = optionalKey(r);
            out.pointerAddress = optionalKey(r);
            out.hasMetadataPointer = r.ok;
        }
        else if (type == EXT_TOKEN_METADATA)
        {
            std::vector<uint8_t> v(d.begin() + pos, d.begin() + pos + len);
            BorshReader r(v);
            Token2022Metadata t;
            t.updateAuthority = optionalKey(r);
            t.mint = r.pubkey();
            t.name = r.str(MAX_STR);
            t.symbol = r.str(MAX_STR);
            t.uri = r.str(MAX_STR);
            if (r.ok)
            {
                out.hasTokenMetadata = true;
                out.updateAuthority = t.updateAuthority;
                out.mint = t.mint;
                out.name = t.name;
                out.symbol = t.symbol;
                out.uri = t.uri;
                // additional_metadata is a vec of (key, value); keep the pairs that parse
                uint32_t n = r.u32();
                for (uint32_t i = 0; r.ok && i < n && r.remaining() >= 8; i++)
                {
                    MetadataField f;
                    f.key = r.str(MAX_STR);
                    f.value = r.str(MAX_STR);
                    if (!r.ok) break;
                    out.additional.push_back(f);
                }
            }
        }
        pos += len;
    }
    return true;
}

// ----------------------------------------------------------------------------
// Infratic
// ----------------------------------------------------------------------------

static bool metaplexPda(Infratic &sol, const String &mintBase58, bool edition, String &out)
{
    std::vector<uint8_t> program = base58ToPubkey(INFRATIC_METAPLEX_METADATA_PROGRAM_ID);
    std::vector<uint8_t> mint = base58ToPubkey(mintBase58);
    if (mint.size() != 32)
    {
        _logErr.println("❌ Metadata PDA: invalid mint address");
        return false;
    }
    std::vector<std::vector<uint8_t>> seeds;
    seeds.push_back(std::vector<uint8_t>({'m', 'e', 't', 'a', 'd', 'a', 't', 'a'}));
    seeds.push_back(program);
    seeds.push_back(mint);
    if (edition) seeds.push_back(std::vector<uint8_t>({'e', 'd', 'i', 't', 'i', 'o', 'n'}));
    uint8_t bump;
    return sol.derivePDA(seeds, INFRATIC_METAPLEX_METADATA_PROGRAM_ID, out, bump);
}

bool Infratic::getMetadataPda(const String &mintBase58, String &outPda)
{
    return metaplexPda(*this, mintBase58, false, outPda);
}

bool Infratic::getMasterEditionPda(const String &mintBase58, String &outPda)
{
    return metaplexPda(*this, mintBase58, true, outPda);
}

bool Infratic::getTokenMetadata(const String &mintBase58, TokenMetadata &out, const String &commitment)
{
    out = TokenMetadata();

    std::vector<uint8_t> mintData;
    String owner;
    if (!getAccountData(mintBase58, mintData, commitment, &owner)) return false;

    bool is2022 = owner == INFRATIC_TOKEN_2022_PROGRAM_ID;
    if ((!is2022 && owner != INFRATIC_TOKEN_PROGRAM_ID) || mintData.size() < MINT_BASE_SIZE)
    {
        _logErr.println("❌ getTokenMetadata: not a token mint " + mintBase58);
        return false;
    }
    uint8_t decimals = mintData[DECIMALS_OFFSET];

    if (is2022)
    {
        Token2022Metadata t;
        if (TokenMetadataParser::parseToken2022(mintData, t) && t.hasTokenMetadata)
        {
            out.found = true;
            out.source = "token-2022";
            out.name = t.name;
            out.symbol = t.symbol;
            out.uri = t.uri;
            out.decimals = decimals;
            out.updateAuthority = t.updateAuthority;
            out.isMutable = !t.updateAuthority.isEmpty();
            return true;
        }
    }

    String pda;
    if (!getMetadataPda(mintBase58, pda)) return false;
    std::vector<uint8_t> metaData;
    String metaOwner;
    if (!getAccountData(pda, metaData, commitment, &metaOwner)) return true; // no metadata account
    MetaplexMetadata m;
    if (metaOwner != INFRATIC_METAPLEX_METADATA_PROGRAM_ID || !TokenMetadataParser::parseMetaplex(metaData, m) ||
        m.mint != mintBase58)
    {
        _logInfo.println("ℹ️ getTokenMetadata: no valid metadata account for " + mintBase58);
        return true;
    }
    out.found = true;
    out.source = "metaplex";
    out.name = m.name;
    out.symbol = m.symbol;
    out.uri = m.uri;
    out.decimals = decimals;
    out.updateAuthority = m.updateAuthority;
    out.isMutable = m.isMutable;
    return true;
}
