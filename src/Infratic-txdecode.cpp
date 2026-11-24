// Parsing, signing and decoding of transactions built elsewhere (dApp / phone).
// The input is untrusted: every length and index is checked before it is used.
#include "infratic_internal.h"

namespace
{
    const size_t MAX_ACCOUNTS = 256; // instruction account indexes are one byte

    // Strict compact-u16 (short_vec length): 1-3 bytes, canonical, value fits in 16 bits
    bool readCompact(const std::vector<uint8_t> &b, size_t &off, size_t &out)
    {
        uint32_t value = 0;
        for (int i = 0; i < 3; i++)
        {
            if (off >= b.size()) return false;
            uint8_t byte = b[off++];
            if (i == 2 && (byte & 0xfc)) return false; // would exceed 16 bits (third byte holds 2 bits)
            value |= (uint32_t)(byte & 0x7f) << (7 * i);
            if (!(byte & 0x80))
            {
                if (i > 0 && byte == 0) return false; // non-canonical alias (e.g. 0x80 0x00)
                out = value;
                return true;
            }
        }
        return false; // continuation bit on the third byte
    }

    bool readBytes(const std::vector<uint8_t> &b, size_t &off, size_t n, std::vector<uint8_t> &out)
    {
        if (n > b.size() - off) return false;
        out.assign(b.begin() + off, b.begin() + off + n);
        off += n;
        return true;
    }

    bool allZero(const std::vector<uint8_t> &v)
    {
        for (uint8_t x : v)
            if (x) return false;
        return true;
    }

    String u64Str(uint64_t v)
    {
        char buf[24];
        int i = sizeof(buf) - 1;
        buf[i] = 0;
        do
        {
            buf[--i] = '0' + (char)(v % 10);
            v /= 10;
        } while (v);
        return String(buf + i);
    }

    uint64_t readU64(const std::vector<uint8_t> &d, size_t off)
    {
        uint64_t v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | d[off + i];
        return v;
    }
    uint32_t readU32(const std::vector<uint8_t> &d, size_t off)
    {
        return (uint32_t)d[off] | ((uint32_t)d[off + 1] << 8) | ((uint32_t)d[off + 2] << 16) | ((uint32_t)d[off + 3] << 24);
    }

    uint64_t satAdd(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }

    // ceil(a * b / 1000000) saturating, without 128-bit integers
    uint64_t mulDivCeilMillion(uint64_t a, uint64_t b)
    {
        const uint64_t M = 1000000;
        uint64_t q = b / M, r = b % M;
        // a*b/M = a*q + a*r/M ; a is at most ~2^32 here, r < 2^20, so a*r fits in 64 bits
        if (q && a > UINT64_MAX / q) return UINT64_MAX;
        uint64_t hi = a * q;
        uint64_t lo = (a * r + M - 1) / M;
        return satAdd(hi, lo);
    }

    // True for well-formed UTF-8 (no overlongs, surrogates or values above U+10FFFF)
    bool validUtf8(const std::vector<uint8_t> &d)
    {
        size_t i = 0, n = d.size();
        while (i < n)
        {
            uint8_t c = d[i];
            size_t extra;
            uint32_t cp;
            if (c < 0x80) { i++; continue; }
            else if (c >= 0xc2 && c <= 0xdf) { extra = 1; cp = c & 0x1f; }
            else if (c >= 0xe0 && c <= 0xef) { extra = 2; cp = c & 0x0f; }
            else if (c >= 0xf0 && c <= 0xf4) { extra = 3; cp = c & 0x07; }
            else return false;
            if (extra > n - i - 1) return false;
            for (size_t k = 1; k <= extra; k++)
            {
                if ((d[i + k] & 0xc0) != 0x80) return false;
                cp = (cp << 6) | (d[i + k] & 0x3f);
            }
            if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
                return false;
            i += extra + 1;
        }
        return true;
    }

    String keyToBase58(const uint8_t *p) { return base58Encode(p, 32); }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

void ParsedTransaction::clear()
{
    isVersioned = false;
    numRequiredSignatures = numReadonlySigned = numReadonlyUnsigned = 0;
    staticKeys.clear();
    recentBlockhash = "";
    instructions.clear();
    lookups.clear();
    signatures.clear();
    message.clear();
}

bool ParsedTransaction::fail(const char *why)
{
    clear();
    _error = why;
    return false;
}

bool ParsedTransaction::fromBase64(const String &b64)
{
    // 1232 bytes encode to at most 1644 characters; refuse bigger input before decoding it
    if (b64.length() == 0 || b64.length() > ((INFRATIC_MAX_TX_SIZE + 2) / 3) * 4 + 4)
        return fail("input too large or empty");
    std::vector<uint8_t> raw;
    if (!infratic_detail::fromBase64(b64.c_str(), raw)) return fail("invalid base64");
    return fromBytes(raw);
}

bool ParsedTransaction::fromBytes(const std::vector<uint8_t> &raw)
{
    clear();
    _error = "";
    if (raw.empty()) return fail("empty transaction");
    if (raw.size() > INFRATIC_MAX_TX_SIZE) return fail("transaction larger than 1232 bytes");

    size_t off = 0, sigCount = 0;
    if (!readCompact(raw, off, sigCount)) return fail("bad signature count");
    if (sigCount == 0) return fail("no signatures");
    if (sigCount > INFRATIC_MAX_TX_SIZE / 64) return fail("too many signatures");
    if (sigCount * 64 > raw.size() - off) return fail("truncated signatures");
    for (size_t i = 0; i < sigCount; i++)
    {
        signatures.push_back(std::vector<uint8_t>(raw.begin() + off, raw.begin() + off + 64));
        off += 64;
    }
    message.assign(raw.begin() + off, raw.end());
    return parseMessage(sigCount);
}

bool ParsedTransaction::parseMessage(size_t sigCount)
{
    const std::vector<uint8_t> &m = message;
    size_t o = 0;
    if (m.empty()) return fail("empty message");

    if (m[0] & 0x80)
    {
        if ((m[0] & 0x7f) != 0) return fail("unsupported message version");
        isVersioned = true;
        o = 1;
    }
    if (m.size() - o < 3) return fail("truncated header");
    numRequiredSignatures = m[o];
    numReadonlySigned = m[o + 1];
    numReadonlyUnsigned = m[o + 2];
    o += 3;
    if (numRequiredSignatures != sigCount) return fail("signature count does not match header");
    if (numRequiredSignatures == 0 || numReadonlySigned >= numRequiredSignatures)
        return fail("invalid header (fee payer must be a writable signer)");

    size_t nKeys = 0;
    if (!readCompact(m, o, nKeys)) return fail("bad account count");
    if (nKeys > MAX_ACCOUNTS) return fail("too many accounts");
    if (nKeys < (size_t)numRequiredSignatures + numReadonlyUnsigned) return fail("header exceeds account count");
    if (nKeys * 32 > m.size() - o) return fail("truncated account keys");
    for (size_t i = 0; i < nKeys; i++)
    {
        staticKeys.push_back(keyToBase58(&m[o]));
        o += 32;
    }
    if (m.size() - o < 32) return fail("truncated blockhash");
    recentBlockhash = keyToBase58(&m[o]);
    o += 32;

    size_t nIx = 0;
    if (!readCompact(m, o, nIx)) return fail("bad instruction count");
    if (nIx > (m.size() - o) / 3) return fail("instruction count exceeds message size"); // 3 bytes minimum each
    for (size_t i = 0; i < nIx; i++)
    {
        ParsedInstruction ix;
        if (o >= m.size()) return fail("truncated instruction");
        ix.programIdIndex = m[o++];
        size_t nAcc = 0, nData = 0;
        if (!readCompact(m, o, nAcc) || !readBytes(m, o, nAcc, ix.accountIndexes)) return fail("bad instruction accounts");
        if (!readCompact(m, o, nData) || !readBytes(m, o, nData, ix.data)) return fail("bad instruction data");
        instructions.push_back(ix);
    }

    size_t loaded = 0;
    if (isVersioned)
    {
        size_t nLookups = 0;
        if (!readCompact(m, o, nLookups)) return fail("bad lookup table count");
        if (nLookups > (m.size() - o) / 34) return fail("lookup count exceeds message size"); // 32 + 2 bytes minimum
        for (size_t i = 0; i < nLookups; i++)
        {
            LookupTableRef ref;
            if (m.size() - o < 32) return fail("truncated lookup table");
            ref.table = keyToBase58(&m[o]);
            o += 32;
            size_t nw = 0, nr = 0;
            if (!readCompact(m, o, nw) || !readBytes(m, o, nw, ref.writableIndexes)) return fail("bad writable lookup indexes");
            if (!readCompact(m, o, nr) || !readBytes(m, o, nr, ref.readonlyIndexes)) return fail("bad readonly lookup indexes");
            loaded += nw + nr;
            if (loaded > MAX_ACCOUNTS) return fail("too many accounts");
            lookups.push_back(ref);
        }
    }
    if (o != m.size()) return fail("trailing bytes");

    size_t total = nKeys + loaded;
    if (total > MAX_ACCOUNTS) return fail("too many accounts");
    for (const ParsedInstruction &ix : instructions)
    {
        // the program must be a static key and cannot be the fee payer
        if (ix.programIdIndex == 0 || ix.programIdIndex >= nKeys) return fail("invalid program index");
        for (uint8_t a : ix.accountIndexes)
            if (a >= total) return fail("account index out of range");
    }
    _error = "";
    return true;
}

// ---------------------------------------------------------------------------
// Serialization and signing
// ---------------------------------------------------------------------------

std::vector<uint8_t> ParsedTransaction::serialize() const
{
    std::vector<uint8_t> out;
    if (message.empty()) return out;
    appendCompactU16(out, (uint16_t)signatures.size());
    for (const auto &s : signatures) out.insert(out.end(), s.begin(), s.end());
    out.insert(out.end(), message.begin(), message.end());
    return out;
}

String ParsedTransaction::toBase64() const
{
    std::vector<uint8_t> raw = serialize();
    if (raw.empty()) return "";
    return infratic_detail::toBase64(raw.data(), raw.size());
}

int ParsedTransaction::signerIndex(const String &base58) const
{
    for (size_t i = 0; i < numRequiredSignatures && i < staticKeys.size(); i++)
        if (staticKeys[i] == base58) return (int)i;
    return -1;
}

int ParsedTransaction::signerIndex(const Pubkey &key) const
{
    if (key.data.size() != 32) return -1;
    return signerIndex(keyToBase58(key.data.data()));
}

bool ParsedTransaction::sign(const Keypair &keypair)
{
    if (message.empty() || keypair.privkey.size() < 64 || keypair.pubkey().data.size() != 32) return false;
    int idx = signerIndex(keypair.pubkey());
    if (idx < 0 || (size_t)idx >= signatures.size()) return false;
    uint8_t sig[64];
    Ed25519::sign(sig, keypair.privkey.data(), keypair.privkey.data() + 32, message.data(), message.size());
    // a keypair whose halves do not match would store a signature that never verifies
    if (!Ed25519::verify(sig, keypair.pubkey().data.data(), message.data(), message.size())) return false;
    signatures[idx].assign(sig, sig + 64);
    return true;
}

bool ParsedTransaction::verifySignatures(std::vector<uint8_t> *outMissing) const
{
    if (outMissing) outMissing->clear();
    if (message.empty() || signatures.size() != numRequiredSignatures || staticKeys.size() < numRequiredSignatures) return false;
    bool ok = true;
    for (size_t i = 0; i < signatures.size(); i++)
    {
        if (signatures[i].size() != 64) { ok = false; continue; }
        if (allZero(signatures[i]))
        {
            if (outMissing) outMissing->push_back((uint8_t)i);
            continue;
        }
        uint8_t pub[32];
        size_t len = sizeof(pub);
        if (!base58Decode(staticKeys[i], pub, len) || len != 32 ||
            !Ed25519::verify(signatures[i].data(), pub, message.data(), message.size()))
            ok = false;
    }
    return ok;
}

bool ParsedTransaction::isFullySigned() const
{
    std::vector<uint8_t> missing;
    return verifySignatures(&missing) && missing.empty();
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

bool ParsedTransaction::setLookupTable(const String &tableBase58, const std::vector<String> &addresses)
{
    bool found = false;
    for (LookupTableRef &l : lookups)
        if (l.table == tableBase58)
        {
            l.addresses = addresses;
            found = true;
        }
    return found;
}

size_t ParsedTransaction::accountCount() const
{
    size_t n = staticKeys.size();
    for (const LookupTableRef &l : lookups) n += l.writableIndexes.size() + l.readonlyIndexes.size();
    return n;
}

String ParsedTransaction::accountKey(size_t index) const
{
    if (index < staticKeys.size()) return staticKeys[index];
    size_t off = staticKeys.size();
    for (int pass = 0; pass < 2; pass++) // loaded accounts: all writable first, then all readonly
        for (const LookupTableRef &l : lookups)
        {
            const std::vector<uint8_t> &idx = pass == 0 ? l.writableIndexes : l.readonlyIndexes;
            if (index < off + idx.size())
            {
                size_t t = idx[index - off];
                return t < l.addresses.size() ? l.addresses[t] : String();
            }
            off += idx.size();
        }
    return String();
}

bool ParsedTransaction::isWritableIndex(size_t index) const
{
    size_t n = staticKeys.size();
    if (index < numRequiredSignatures) return index < (size_t)(numRequiredSignatures - numReadonlySigned);
    if (index < n) return index < n - numReadonlyUnsigned;
    size_t writableLoaded = 0;
    for (const LookupTableRef &l : lookups) writableLoaded += l.writableIndexes.size();
    return index < accountCount() && index - n < writableLoaded;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

String ParsedTransaction::formatUnits(uint64_t amount, int decimals)
{
    String digits = u64Str(amount);
    if (decimals <= 0) return digits;
    while ((int)digits.length() <= decimals) digits = String("0") + digits;
    String intPart = digits.substring(0, digits.length() - decimals);
    String frac = digits.substring(digits.length() - decimals);
    int end = frac.length();
    while (end > 0 && frac[end - 1] == '0') end--;
    if (end == 0) return intPart;
    return intPart + "." + frac.substring(0, end);
}

String ParsedTransaction::formatSol(uint64_t lamports)
{
    return formatUnits(lamports, 9) + " SOL";
}

String ParsedTransaction::shortKey(const String &k)
{
    if (k.length() < 12) return k;
    return k.substring(0, 4) + "..." + k.substring(k.length() - 4);
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

namespace
{
    const char *MEMO_V1 = INFRATIC_MEMO_V1_PROGRAM_ID;

    struct Fields
    {
        const ParsedTransaction &tx;
        const ParsedInstruction &ix;
        bool resolved;
        Fields(const ParsedTransaction &t, const ParsedInstruction &i) : tx(t), ix(i), resolved(true) {}
        size_t count() const { return ix.accountIndexes.size(); }
        String key(size_t n)
        {
            if (n >= ix.accountIndexes.size()) return "";
            String k = tx.accountKey(ix.accountIndexes[n]);
            if (k.isEmpty()) resolved = false;
            return k;
        }
        // for summaries: short key or a marker when the account is behind an unresolved lookup table
        static String label(const String &k) { return k.isEmpty() ? String("(account from lookup table)") : ParsedTransaction::shortKey(k); }
    };

    void makeUnknown(DecodedInstruction &d, const char *what, uint32_t tag)
    {
        d.known = false;
        d.type = "unknown";
        d.summary = String("Unrecognised ") + what + " instruction (tag " + String((unsigned long)tag) + ")";
    }

    void decodeSystem(Fields &f, DecodedInstruction &d)
    {
        const std::vector<uint8_t> &data = f.ix.data;
        uint32_t tag = data.size() >= 4 ? readU32(data, 0) : 0xffffffffu;
        if (tag == 2 && data.size() >= 12 && f.count() >= 2)
        {
            d.type = "transfer";
            d.amount = readU64(data, 4);
            d.source = f.key(0);
            d.authority = d.source;
            d.destination = f.key(1);
            d.summary = String("Transfer ") + ParsedTransaction::formatSol(d.amount) + " to " + Fields::label(d.destination);
        }
        else if (tag == 0 && data.size() >= 52 && f.count() >= 2)
        {
            d.type = "createAccount";
            d.amount = readU64(data, 4);
            uint64_t space = readU64(data, 12);
            d.source = f.key(0);
            d.authority = d.source;
            d.destination = f.key(1);
            d.owner = keyToBase58(&data[20]);
            d.summary = String("Create account ") + Fields::label(d.destination) + " (" + u64Str(space) + " bytes, owner " +
                        ParsedTransaction::shortKey(d.owner) + ") funded with " + ParsedTransaction::formatSol(d.amount);
        }
        else if (tag == 4 && data.size() >= 4 && f.count() >= 3)
        {
            d.type = "advanceNonce";
            d.destination = f.key(0); // the nonce account
            d.authority = f.key(2);
            d.summary = String("Advance nonce account ") + Fields::label(d.destination);
        }
        else
        {
            makeUnknown(d, "system", tag);
        }
    }

    void decodeToken(Fields &f, DecodedInstruction &d, bool token2022)
    {
        const std::vector<uint8_t> &data = f.ix.data;
        uint8_t tag = data.empty() ? 0xff : data[0];
        const char *what = token2022 ? "token-2022" : "spl-token";
        // layout: tag, then amount (u64) and for the "checked" variants decimals (u8)
        bool checked = tag == 12 || tag == 13 || tag == 14 || tag == 15;
        bool hasAmount = tag == 3 || tag == 4 || tag == 7 || tag == 8 || checked;
        size_t need = checked ? 10 : (hasAmount ? 9 : 1);
        if (data.empty() || !(hasAmount || tag == 9) || data.size() < need)
        {
            makeUnknown(d, what, tag);
            return;
        }
        if (hasAmount)
        {
            d.amount = readU64(data, 1);
            if (checked) d.decimals = data[9];
        }
        String amountStr = checked ? ParsedTransaction::formatUnits(d.amount, d.decimals) + " tokens"
                                   : u64Str(d.amount) + " raw token units";
        auto mintPart = [&]() { return d.mint.isEmpty() ? String("") : String(" (mint ") + Fields::label(d.mint) + ")"; };
        size_t n = f.count();
        switch (tag)
        {
        case 3: // transfer: src, dst, authority
            if (n < 3) { makeUnknown(d, what, tag); return; }
            d.type = "transfer";
            d.source = f.key(0); d.destination = f.key(1); d.authority = f.key(2);
            d.summary = String("Transfer ") + amountStr + " to " + Fields::label(d.destination);
            break;
        case 12: // transferChecked: src, mint, dst, authority
            if (n < 4) { makeUnknown(d, what, tag); return; }
            d.type = "transferChecked";
            d.source = f.key(0); d.mint = f.key(1); d.destination = f.key(2); d.authority = f.key(3);
            d.summary = String("Transfer ") + amountStr + mintPart() + " to " + Fields::label(d.destination);
            break;
        case 4: // approve: src, delegate, owner
            if (n < 3) { makeUnknown(d, what, tag); return; }
            d.type = "approve";
            d.source = f.key(0); d.destination = f.key(1); d.authority = f.key(2);
            d.summary = String("Approve ") + Fields::label(d.destination) + " to spend up to " + amountStr;
            break;
        case 13: // approveChecked: src, mint, delegate, owner
            if (n < 4) { makeUnknown(d, what, tag); return; }
            d.type = "approveChecked";
            d.source = f.key(0); d.mint = f.key(1); d.destination = f.key(2); d.authority = f.key(3);
            d.summary = String("Approve ") + Fields::label(d.destination) + " to spend up to " + amountStr + mintPart();
            break;
        case 7: // mintTo: mint, dst, authority
        case 14: // mintToChecked
            if (n < 3) { makeUnknown(d, what, tag); return; }
            d.type = tag == 7 ? "mintTo" : "mintToChecked";
            d.mint = f.key(0); d.destination = f.key(1); d.authority = f.key(2);
            d.summary = String("Mint ") + amountStr + " (mint " + Fields::label(d.mint) + ") to " + Fields::label(d.destination);
            break;
        case 8: // burn: account, mint, authority
        case 15: // burnChecked
            if (n < 3) { makeUnknown(d, what, tag); return; }
            d.type = tag == 8 ? "burn" : "burnChecked";
            d.source = f.key(0); d.mint = f.key(1); d.authority = f.key(2);
            d.summary = String("Burn ") + amountStr + " (mint " + Fields::label(d.mint) + ") from " + Fields::label(d.source);
            break;
        case 9: // closeAccount: account, destination, owner
            if (n < 3) { makeUnknown(d, what, tag); return; }
            d.type = "closeAccount";
            d.source = f.key(0); d.destination = f.key(1); d.authority = f.key(2);
            d.summary = String("Close token account ") + Fields::label(d.source) + ", remaining SOL goes to " + Fields::label(d.destination);
            break;
        }
    }

    void decodeAta(Fields &f, DecodedInstruction &d)
    {
        const std::vector<uint8_t> &data = f.ix.data;
        uint8_t tag = data.empty() ? 0 : data[0]; // the original instruction has no data
        if (tag > 1 || f.count() < 4)
        {
            makeUnknown(d, "associated-token", tag);
            return;
        }
        d.type = tag == 0 ? "create" : "createIdempotent";
        d.source = f.key(0);      // funder
        d.authority = d.source;
        d.destination = f.key(1); // the new token account
        d.owner = f.key(2);
        d.mint = f.key(3);
        d.summary = String("Create token account ") + Fields::label(d.destination) + " for owner " + Fields::label(d.owner) +
                    " (mint " + Fields::label(d.mint) + ")";
    }

    void decodeComputeBudget(Fields &f, DecodedInstruction &d)
    {
        const std::vector<uint8_t> &data = f.ix.data;
        uint8_t tag = data.empty() ? 0xff : data[0];
        if ((tag == 1 || tag == 2 || tag == 4) && data.size() >= 5)
        {
            d.amount = readU32(data, 1);
            if (tag == 1)
            {
                d.type = "requestHeapFrame";
                d.summary = String("Request a heap of ") + u64Str(d.amount) + " bytes";
            }
            else if (tag == 2)
            {
                d.type = "setComputeUnitLimit";
                d.summary = String("Set compute unit limit to ") + u64Str(d.amount);
            }
            else
            {
                d.type = "setLoadedAccountsDataSizeLimit";
                d.summary = String("Limit loaded accounts data to ") + u64Str(d.amount) + " bytes";
            }
        }
        else if (tag == 3 && data.size() >= 9)
        {
            d.type = "setComputeUnitPrice";
            d.amount = readU64(data, 1);
            d.summary = String("Set priority fee to ") + u64Str(d.amount) + " microLamports per compute unit";
        }
        else
        {
            makeUnknown(d, "compute-budget", tag);
        }
    }

    void decodeMemo(Fields &f, DecodedInstruction &d)
    {
        d.type = "memo";
        if (!validUtf8(f.ix.data))
        {
            d.summary = String("Memo (") + String((unsigned long)f.ix.data.size()) + " bytes of non-text data)";
            return;
        }
        // control characters could mess up a display, show them as spaces
        std::string clean;
        for (uint8_t c : f.ix.data) clean += (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
        d.text = String(clean.c_str());
        const size_t MAX_SHOWN = 80;
        if (clean.size() > MAX_SHOWN)
        {
            size_t cut = MAX_SHOWN;
            while (cut > 0 && ((uint8_t)clean[cut] & 0xc0) == 0x80) cut--; // stay on a character boundary
            d.summary = String("Memo: \"") + String(clean.substr(0, cut).c_str()) + "...\"";
        }
        else
        {
            d.summary = String("Memo: \"") + d.text + "\"";
        }
    }
}

DecodedInstruction ParsedTransaction::decodeInstruction(size_t index) const
{
    DecodedInstruction d;
    if (index >= instructions.size())
    {
        d.type = "unknown";
        d.program = "unknown";
        d.summary = "No such instruction";
        return d;
    }
    const ParsedInstruction &ix = instructions[index];
    d.programId = ix.programIdIndex < staticKeys.size() ? staticKeys[ix.programIdIndex] : String();
    Fields f(*this, ix);
    d.known = true;

    if (d.programId == INFRATIC_SYSTEM_PROGRAM_ID) { d.program = "system"; decodeSystem(f, d); }
    else if (d.programId == INFRATIC_TOKEN_PROGRAM_ID) { d.program = "spl-token"; decodeToken(f, d, false); }
    else if (d.programId == INFRATIC_TOKEN_2022_PROGRAM_ID) { d.program = "token-2022"; decodeToken(f, d, true); }
    else if (d.programId == INFRATIC_ASSOCIATED_TOKEN_PROGRAM_ID) { d.program = "associated-token"; decodeAta(f, d); }
    else if (d.programId == INFRATIC_COMPUTE_BUDGET_PROGRAM_ID) { d.program = "compute-budget"; decodeComputeBudget(f, d); }
    else if (d.programId == INFRATIC_MEMO_PROGRAM_ID || d.programId == MEMO_V1) { d.program = "memo"; decodeMemo(f, d); }
    else
    {
        d.program = "unknown";
        d.type = "unknown";
        d.known = false;
        d.summary = String("Unknown program ") + d.programId + " (" + String((unsigned long)ix.accountIndexes.size()) +
                    " accounts, " + String((unsigned long)ix.data.size()) + " bytes of data)";
    }
    // resolution of the accounts that were not looked at above
    for (uint8_t a : ix.accountIndexes)
        if (accountKey(a).isEmpty()) f.resolved = false;
    d.resolved = f.resolved;
    return d;
}

std::vector<DecodedInstruction> ParsedTransaction::decodeAll() const
{
    std::vector<DecodedInstruction> out;
    for (size_t i = 0; i < instructions.size(); i++) out.push_back(decodeInstruction(i));
    return out;
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

TxCostEstimate ParsedTransaction::estimateCost(const String &signer) const
{
    TxCostEstimate c;
    c.baseFee = 5000ULL * numRequiredSignatures;
    uint32_t limit = 0;
    bool haveLimit = false;
    uint64_t price = 0;
    uint32_t others = 0; // instructions that are not compute budget ones

    for (size_t i = 0; i < instructions.size(); i++)
    {
        DecodedInstruction d = decodeInstruction(i);
        if (d.program == "compute-budget")
        {
            if (d.type == "setComputeUnitLimit") { limit = (uint32_t)d.amount; haveLimit = true; }
            else if (d.type == "setComputeUnitPrice") price = d.amount;
            continue;
        }
        others++;
        if (!d.known) c.complete = false;
        if (d.program == "system" && d.source == signer && !signer.isEmpty())
        {
            if (d.type == "transfer") c.lamportsTransferred = satAdd(c.lamportsTransferred, d.amount);
            else if (d.type == "createAccount") c.lamportsFunded = satAdd(c.lamportsFunded, d.amount);
        }
        else if (d.program == "associated-token" && d.source == signer && !signer.isEmpty())
        {
            c.complete = false; // rent of the new token account is paid by the signer but not counted
        }
    }

    const uint32_t MAX_CU = 1400000, DEFAULT_PER_IX = 200000;
    if (!haveLimit)
    {
        uint64_t est = (uint64_t)DEFAULT_PER_IX * others;
        limit = est > MAX_CU ? MAX_CU : (uint32_t)est;
    }
    else if (limit > MAX_CU)
    {
        limit = MAX_CU;
    }
    c.limitRequested = haveLimit;
    c.computeUnitLimit = limit;
    c.microLamportsPerCU = price;
    c.priorityFee = price ? mulDivCeilMillion(limit, price) : 0;
    c.totalLamports = satAdd(satAdd(c.baseFee, c.priorityFee), satAdd(c.lamportsTransferred, c.lamportsFunded));
    return c;
}
