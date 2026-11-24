// Off-chain message signing (spec v0) and Sign-In With Solana.
#include "infratic_internal.h"
#include <string>

namespace
{
    const uint8_t SIGNING_DOMAIN[16] = {0xff, 's', 'o', 'l', 'a', 'n', 'a', ' ', 'o', 'f', 'f', 'c', 'h', 'a', 'i', 'n'};
    const size_t MAX_HARDWARE_WALLET_BYTES = 1232;
    const size_t MAX_EXTENDED_BODY = 0xffff;

    void setErr(String *out, const char *msg)
    {
        if (out) *out = msg;
    }

    size_t preambleLength(size_t signerCount)
    {
        // domain 16 + version 1 + app domain 32 + format 1 + signer count 1 + signers + length 2
        return 16 + 1 + 32 + 1 + 1 + signerCount * 32 + 2;
    }

    // Strict UTF-8 (no overlong forms, no surrogates, max U+10FFFF)
    bool isStrictUtf8(const std::vector<uint8_t> &d)
    {
        size_t i = 0, n = d.size();
        while (i < n)
        {
            uint8_t c = d[i];
            if (c < 0x80) { i++; continue; }
            size_t extra;
            uint32_t cp;
            if (c >= 0xc2 && c <= 0xdf) { extra = 1; cp = c & 0x1f; }
            else if ((c & 0xf0) == 0xe0) { extra = 2; cp = c & 0x0f; }
            else if (c >= 0xf0 && c <= 0xf4) { extra = 3; cp = c & 0x07; }
            else return false;
            if (i + extra >= n) return false;
            for (size_t k = 1; k <= extra; k++)
            {
                if ((d[i + k] & 0xc0) != 0x80) return false;
                cp = (cp << 6) | (d[i + k] & 0x3f);
            }
            if (extra == 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) return false;
            if (extra == 3 && (cp < 0x10000 || cp > 0x10ffff)) return false;
            i += extra + 1;
        }
        return true;
    }

    bool signerIndex(const std::vector<Pubkey> &signers, const uint8_t *pub)
    {
        for (const Pubkey &s : signers)
            if (s.data.size() == 32 && memcmp(s.data.data(), pub, 32) == 0) return true;
        return false;
    }
}

// ============================================================================
// Off-chain messages
// ============================================================================

size_t Offchain::maxBodyLength(OffchainFormat format, size_t signerCount)
{
    if (format == OffchainFormat::Utf8Extended) return MAX_EXTENDED_BODY;
    size_t pre = preambleLength(signerCount);
    return pre >= MAX_HARDWARE_WALLET_BYTES ? 0 : MAX_HARDWARE_WALLET_BYTES - pre;
}

bool Offchain::validate(const OffchainMessage &msg, String *outError)
{
    if (msg.version != 0) { setErr(outError, "unsupported version"); return false; }
    if (msg.applicationDomain.size() != 32) { setErr(outError, "application domain must be 32 bytes"); return false; }
    if (msg.signers.empty()) { setErr(outError, "at least one signer is required"); return false; }
    if (msg.signers.size() > 255) { setErr(outError, "too many signers"); return false; }
    for (const Pubkey &s : msg.signers)
        if (s.data.size() != 32) { setErr(outError, "invalid signer key"); return false; }
    uint8_t f = (uint8_t)msg.format;
    if (f > 2) { setErr(outError, "unknown message format"); return false; }
    if (msg.body.empty()) { setErr(outError, "message must not be empty"); return false; }
    if (msg.format == OffchainFormat::RestrictedAscii)
    {
        for (uint8_t c : msg.body)
            if (c < 0x20 || c > 0x7e) { setErr(outError, "character outside restricted ASCII range"); return false; }
    }
    else if (!isStrictUtf8(msg.body))
    {
        setErr(outError, "message is not valid UTF-8");
        return false;
    }
    if (msg.body.size() > maxBodyLength(msg.format, msg.signers.size()))
    {
        setErr(outError, "message too long for this format");
        return false;
    }
    return true;
}

bool Offchain::make(const String &applicationDomainBase58, OffchainFormat format, const Pubkey &signer,
                    const String &text, OffchainMessage &outMsg)
{
    uint8_t buf[64];
    size_t len = sizeof(buf);
    if (!base58Decode(applicationDomainBase58, buf, len) || len != 32) return false;
    outMsg = OffchainMessage();
    outMsg.applicationDomain.assign(buf, buf + 32);
    outMsg.format = format;
    outMsg.signers.push_back(signer);
    outMsg.body.assign((const uint8_t *)text.c_str(), (const uint8_t *)text.c_str() + text.length());
    return true;
}

bool Offchain::build(const OffchainMessage &msg, std::vector<uint8_t> &outContent, String *outError)
{
    if (!validate(msg, outError)) return false;
    std::vector<uint8_t> c;
    c.reserve(preambleLength(msg.signers.size()) + msg.body.size());
    c.insert(c.end(), SIGNING_DOMAIN, SIGNING_DOMAIN + 16);
    c.push_back(msg.version);
    c.insert(c.end(), msg.applicationDomain.begin(), msg.applicationDomain.end());
    c.push_back((uint8_t)msg.format);
    c.push_back((uint8_t)msg.signers.size());
    for (const Pubkey &s : msg.signers) c.insert(c.end(), s.data.begin(), s.data.end());
    c.push_back((uint8_t)(msg.body.size() & 0xff));
    c.push_back((uint8_t)(msg.body.size() >> 8));
    c.insert(c.end(), msg.body.begin(), msg.body.end());
    outContent.swap(c);
    return true;
}

bool Offchain::parse(const std::vector<uint8_t> &content, OffchainMessage &outMsg, String *outError)
{
    size_t n = content.size();
    if (n < 16 + 1 || memcmp(content.data(), SIGNING_DOMAIN, 16) != 0) { setErr(outError, "bad signing domain"); return false; }
    if (content[16] != 0) { setErr(outError, "unsupported version"); return false; }
    if (n < 16 + 1 + 32 + 1 + 1) { setErr(outError, "truncated preamble"); return false; }
    OffchainMessage m;
    size_t o = 17;
    m.applicationDomain.assign(content.begin() + o, content.begin() + o + 32);
    o += 32;
    if (content[o] > 2) { setErr(outError, "unknown message format"); return false; }
    m.format = (OffchainFormat)content[o++];
    size_t count = content[o++];
    if (count == 0) { setErr(outError, "at least one signer is required"); return false; }
    if (n < o + count * 32 + 2) { setErr(outError, "truncated preamble"); return false; }
    for (size_t i = 0; i < count; i++)
    {
        Pubkey k;
        k.data.assign(content.begin() + o, content.begin() + o + 32);
        m.signers.push_back(k);
        o += 32;
    }
    size_t len = content[o] | ((size_t)content[o + 1] << 8);
    o += 2;
    if (n - o != len) { setErr(outError, "message length mismatch"); return false; }
    m.body.assign(content.begin() + o, content.end());
    if (!validate(m, outError)) return false;
    outMsg = m;
    return true;
}

bool Offchain::sign(const std::vector<uint8_t> &content, const Keypair &keypair, uint8_t outSignature[64],
                    String *outError)
{
    OffchainMessage m;
    if (!parse(content, m, outError)) return false;
    if (keypair.privkey.size() < 64) { setErr(outError, "invalid keypair"); return false; }
    const uint8_t *priv = keypair.privkey.data();
    if (!signerIndex(m.signers, priv + 32)) { setErr(outError, "keypair is not a required signer"); return false; }
    Ed25519::sign(outSignature, priv, priv + 32, content.data(), content.size());
    return true;
}

bool Offchain::verify(const std::vector<uint8_t> &content, const Pubkey &signer, const uint8_t signature[64])
{
    OffchainMessage m;
    if (!parse(content, m) || signer.data.size() != 32) return false;
    if (!signerIndex(m.signers, signer.data.data())) return false;
    return Ed25519::verify(signature, signer.data.data(), content.data(), content.size());
}

bool Offchain::buildEnvelope(const std::vector<uint8_t> &content, const std::vector<Keypair> &signers,
                             std::vector<uint8_t> &outEnvelope, String *outError)
{
    OffchainMessage m;
    if (!parse(content, m, outError)) return false;
    std::vector<uint8_t> sigs(m.signers.size() * 64, 0);
    for (const Keypair &kp : signers)
    {
        if (kp.privkey.size() < 64) { setErr(outError, "invalid keypair"); return false; }
        bool found = false;
        for (size_t i = 0; i < m.signers.size(); i++)
        {
            if (memcmp(m.signers[i].data.data(), kp.privkey.data() + 32, 32) != 0) continue;
            Ed25519::sign(&sigs[i * 64], kp.privkey.data(), kp.privkey.data() + 32, content.data(), content.size());
            found = true;
        }
        if (!found) { setErr(outError, "keypair is not a required signer"); return false; }
    }
    std::vector<uint8_t> env;
    env.reserve(1 + sigs.size() + content.size());
    env.push_back((uint8_t)m.signers.size());
    env.insert(env.end(), sigs.begin(), sigs.end());
    env.insert(env.end(), content.begin(), content.end());
    outEnvelope.swap(env);
    return true;
}

bool Offchain::parseEnvelope(const std::vector<uint8_t> &envelope, std::vector<uint8_t> &outContent,
                             std::vector<std::vector<uint8_t>> &outSignatures, String *outError)
{
    if (envelope.empty()) { setErr(outError, "empty envelope"); return false; }
    size_t count = envelope[0];
    if (count == 0) { setErr(outError, "envelope has no signatures"); return false; }
    if (envelope.size() < 1 + count * 64) { setErr(outError, "truncated envelope"); return false; }
    std::vector<uint8_t> content(envelope.begin() + 1 + count * 64, envelope.end());
    OffchainMessage m;
    if (!parse(content, m, outError)) return false;
    if (m.signers.size() != count) { setErr(outError, "signature count does not match signer count"); return false; }
    outSignatures.clear();
    for (size_t i = 0; i < count; i++)
        outSignatures.push_back(std::vector<uint8_t>(envelope.begin() + 1 + i * 64, envelope.begin() + 1 + (i + 1) * 64));
    outContent.swap(content);
    return true;
}

bool Offchain::verifyEnvelope(const std::vector<uint8_t> &envelope, String *outError)
{
    std::vector<uint8_t> content;
    std::vector<std::vector<uint8_t>> sigs;
    if (!parseEnvelope(envelope, content, sigs, outError)) return false;
    OffchainMessage m;
    parse(content, m);
    for (size_t i = 0; i < sigs.size(); i++)
    {
        bool zero = true;
        for (uint8_t b : sigs[i]) if (b) { zero = false; break; }
        if (zero) { setErr(outError, "signature missing"); return false; }
        if (!Ed25519::verify(sigs[i].data(), m.signers[i].data.data(), content.data(), content.size()))
        {
            setErr(outError, "signature verification failed");
            return false;
        }
    }
    return true;
}

// ============================================================================
// Sign-In With Solana
// ============================================================================

namespace
{
    bool hasNewline(const String &s) { return s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0; }

    std::string fieldsText(const SignInMessage &m)
    {
        std::vector<std::string> f;
        auto add = [&](const char *label, const String &v) {
            if (v.length()) f.push_back(std::string(label) + v.c_str());
        };
        add("URI: ", m.uri);
        add("Version: ", m.version);
        add("Chain ID: ", m.chainId);
        add("Nonce: ", m.nonce);
        add("Issued At: ", m.issuedAt);
        add("Expiration Time: ", m.expirationTime);
        add("Not Before: ", m.notBefore);
        add("Request ID: ", m.requestId);
        if (!m.resources.empty())
        {
            f.push_back("Resources:");
            for (const String &r : m.resources) f.push_back(std::string("- ") + r.c_str());
        }
        std::string out;
        for (size_t i = 0; i < f.size(); i++)
        {
            if (i) out += "\n";
            out += f[i];
        }
        return out;
    }

    // One "\nLabel: value" field (value non-empty, no newline) at the start of s[pos..]
    bool takeField(const std::string &s, size_t &pos, const char *label, String &out)
    {
        std::string key = std::string("\n") + label;
        if (s.compare(pos, key.size(), key) != 0) return false;
        size_t start = pos + key.size();
        size_t end = s.find('\n', start);
        if (end == std::string::npos) end = s.size();
        if (end == start) return false; // value must not be empty
        out = String(s.substr(start, end - start).c_str());
        pos = end;
        return true;
    }

    // Matches the optional fields followed by "\n*" end of text, starting at s[pos..]
    bool parseFields(const std::string &s, size_t pos, SignInMessage &m)
    {
        takeField(s, pos, "URI: ", m.uri);
        takeField(s, pos, "Version: ", m.version);
        takeField(s, pos, "Chain ID: ", m.chainId);
        takeField(s, pos, "Nonce: ", m.nonce);
        takeField(s, pos, "Issued At: ", m.issuedAt);
        takeField(s, pos, "Expiration Time: ", m.expirationTime);
        takeField(s, pos, "Not Before: ", m.notBefore);
        takeField(s, pos, "Request ID: ", m.requestId);
        if (s.compare(pos, 11, "\nResources:") == 0)
        {
            pos += 11;
            while (s.compare(pos, 3, "\n- ") == 0)
            {
                size_t start = pos + 3;
                size_t end = s.find('\n', start);
                if (end == std::string::npos) end = s.size();
                if (end == start) break;
                m.resources.push_back(String(s.substr(start, end - start).c_str()));
                pos = end;
            }
        }
        while (pos < s.size() && s[pos] == '\n') pos++;
        return pos == s.size();
    }

    const char *SIWS_SUFFIX = " wants you to sign in with your Solana account:";
}

bool Siws::buildText(const SignInMessage &msg, String &outText, String *outError)
{
    if (msg.domain.isEmpty() || msg.address.isEmpty()) { setErr(outError, "domain and address are required"); return false; }
    const String *single[] = {&msg.domain, &msg.address, &msg.uri, &msg.version, &msg.chainId, &msg.nonce,
                              &msg.issuedAt, &msg.expirationTime, &msg.notBefore, &msg.requestId};
    for (const String *f : single)
        if (hasNewline(*f)) { setErr(outError, "fields must not contain line breaks"); return false; }
    for (const String &r : msg.resources)
        if (r.isEmpty() || hasNewline(r)) { setErr(outError, "invalid resource"); return false; }
    // an empty-looking or multi line statement could be confused with the fields that follow
    std::string text = std::string(msg.domain.c_str()) + SIWS_SUFFIX + "\n" + msg.address.c_str();
    if (msg.statement.length()) text += std::string("\n\n") + msg.statement.c_str();
    std::string fields = fieldsText(msg);
    if (!fields.empty()) text += "\n\n" + fields;
    outText = String(text.c_str());
    return true;
}

bool Siws::parse(const String &textStr, SignInMessage &outMsg)
{
    std::string s(textStr.c_str());
    size_t nl = s.find('\n');
    if (nl == std::string::npos) return false;
    std::string suffix(SIWS_SUFFIX);
    if (nl <= suffix.size() || s.compare(nl - suffix.size(), suffix.size(), suffix) != 0) return false;
    SignInMessage m;
    m.domain = String(s.substr(0, nl - suffix.size()).c_str());
    size_t addrStart = nl + 1;
    size_t addrEnd = s.find('\n', addrStart);
    if (addrEnd == std::string::npos) addrEnd = s.size();
    if (addrEnd == addrStart) return false;
    m.address = String(s.substr(addrStart, addrEnd - addrStart).c_str());
    // T = text after the line break that ends the address line (nothing if the text ends there)
    size_t t = addrEnd < s.size() ? addrEnd + 1 : addrEnd;

    // 1) no statement: the fields follow directly
    {
        SignInMessage f = m;
        if (parseFields(s, t, f)) { outMsg = f; return true; }
    }
    // 2) statement = shortest run of text that is followed by a line break (or the end) and then fields
    if (t >= s.size() || s[t] != '\n') return false;
    size_t start = t + 1;
    for (size_t k = start; k <= s.size(); k++)
    {
        SignInMessage f = m;
        bool ok;
        if (k == s.size()) ok = true;                                  // statement runs to the end
        else if (s[k] == '\n') ok = parseFields(s, k + 1, f);          // line break ends the statement
        else continue;
        if (ok)
        {
            f.statement = String(s.substr(start, k - start).c_str());
            outMsg = f;
            return true;
        }
    }
    return false;
}

bool Siws::sign(const SignInMessage &msg, const Keypair &keypair, String &outText, uint8_t outSignature[64],
                String *outError)
{
    if (keypair.privkey.size() < 64) { setErr(outError, "invalid keypair"); return false; }
    SignInMessage m = msg;
    String mine = base58Encode(keypair.privkey.data() + 32, 32);
    if (m.address.isEmpty()) m.address = mine;
    else if (m.address != mine) { setErr(outError, "address does not match the keypair"); return false; }
    String text;
    if (!buildText(m, text, outError)) return false;
    Ed25519::sign(outSignature, keypair.privkey.data(), keypair.privkey.data() + 32, text.c_str(), text.length());
    outText = text;
    return true;
}

bool Siws::parseTime(const String &iso, int64_t &out)
{
    std::string s(iso.c_str());
    auto num = [&](size_t pos, size_t n, int &v) {
        if (pos + n > s.size()) return false;
        v = 0;
        for (size_t i = 0; i < n; i++)
        {
            if (s[pos + i] < '0' || s[pos + i] > '9') return false;
            v = v * 10 + (s[pos + i] - '0');
        }
        return true;
    };
    int Y, M, D, h, m, sec;
    if (s.size() < 20 || !num(0, 4, Y) || s[4] != '-' || !num(5, 2, M) || s[7] != '-' || !num(8, 2, D) ||
        (s[10] != 'T' && s[10] != 't') || !num(11, 2, h) || s[13] != ':' || !num(14, 2, m) || s[16] != ':' ||
        !num(17, 2, sec))
        return false;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || sec > 60) return false;
    size_t p = 19;
    if (s[p] == '.')
    {
        p++;
        size_t d = p;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') p++;
        if (p == d) return false;
    }
    int64_t offset = 0;
    if (p < s.size() && (s[p] == 'Z' || s[p] == 'z'))
    {
        p++;
    }
    else if (p + 6 <= s.size() && (s[p] == '+' || s[p] == '-'))
    {
        int oh, om;
        if (!num(p + 1, 2, oh) || s[p + 3] != ':' || !num(p + 4, 2, om)) return false;
        offset = (oh * 3600 + om * 60) * (s[p] == '-' ? -1 : 1);
        p += 6;
    }
    else return false;
    if (p != s.size()) return false;
    // days from civil (Howard Hinnant)
    int64_t y = Y - (M <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (M + (M > 2 ? -3 : 9)) + 2) / 5 + D - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    out = days * 86400 + h * 3600 + m * 60 + sec - offset;
    return true;
}

bool Siws::verify(const SignInMessage &expected, const std::vector<uint8_t> &signedMessage, const uint8_t signature[64],
                  const Pubkey &publicKey, int64_t nowUnix, String *outError)
{
    if (publicKey.data.size() != 32) { setErr(outError, "invalid public key"); return false; }
    String text(std::string((const char *)signedMessage.data(), signedMessage.size()).c_str());
    SignInMessage got;
    if (text.length() != signedMessage.size() || !parse(text, got)) { setErr(outError, "message does not parse"); return false; }
    if (got.address != base58Encode(publicKey.data.data(), 32)) { setErr(outError, "address is not the public key"); return false; }
    if (!expected.domain.isEmpty() && expected.domain != got.domain) { setErr(outError, "domain mismatch"); return false; }
    if (!expected.address.isEmpty() && expected.address != got.address) { setErr(outError, "address mismatch"); return false; }
    if (expected.statement != got.statement || expected.uri != got.uri || expected.version != got.version ||
        expected.chainId != got.chainId || expected.nonce != got.nonce || expected.issuedAt != got.issuedAt ||
        expected.expirationTime != got.expirationTime || expected.notBefore != got.notBefore ||
        expected.requestId != got.requestId)
    {
        setErr(outError, "message fields do not match");
        return false;
    }
    if (expected.resources.size() != got.resources.size()) { setErr(outError, "resources mismatch"); return false; }
    for (size_t i = 0; i < got.resources.size(); i++)
        if (expected.resources[i] != got.resources[i]) { setErr(outError, "resources mismatch"); return false; }
    // the signed bytes must be the canonical text of the parsed fields
    String canonical;
    if (!buildText(got, canonical) || canonical != text) { setErr(outError, "message is not in canonical form"); return false; }
    if (nowUnix != 0)
    {
        int64_t t;
        if (!got.expirationTime.isEmpty() && (!parseTime(got.expirationTime, t) || t <= nowUnix))
        {
            setErr(outError, "message expired");
            return false;
        }
        if (!got.notBefore.isEmpty() && (!parseTime(got.notBefore, t) || t > nowUnix))
        {
            setErr(outError, "message not valid yet");
            return false;
        }
    }
    if (!Ed25519::verify(signature, publicKey.data.data(), signedMessage.data(), signedMessage.size()))
    {
        setErr(outError, "signature verification failed");
        return false;
    }
    return true;
}
