// Solana Pay: transfer / transaction request URLs, reference lookup, transfer validation
// and the transfer transaction builder (behaviour follows @solana/pay).
#include "infratic_internal.h"
#include <string>

using infratic_detail::fromBase64;

namespace
{
    const char *MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

    void setErr(String *out, const std::string &msg)
    {
        if (out) *out = String(msg.c_str());
    }

    bool decodeKey(const std::string &b58, std::vector<uint8_t> &out)
    {
        if (b58.empty() || b58.size() > 44) return false;
        uint8_t buf[64];
        size_t len = sizeof(buf);
        if (!base58Decode(String(b58.c_str()), buf, len) || len != 32) return false;
        out.assign(buf, buf + 32);
        return true;
    }

    // canonical base58 of a 32 byte key string, "" if invalid
    std::string canonicalKey(const std::string &b58)
    {
        std::vector<uint8_t> k;
        if (!decodeKey(b58, k)) return "";
        return std::string(base58Encode(k.data(), 32).c_str());
    }

    // ---- percent encoding ------------------------------------------------------------------
    const char *HEXU = "0123456789ABCDEF";

    // form: application/x-www-form-urlencoded (URLSearchParams); otherwise encodeURIComponent
    std::string pctEncode(const std::string &s, bool form)
    {
        std::string out;
        for (unsigned char c : s)
        {
            bool keep = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' ||
                        c == '_' || c == '.' || c == '*';
            if (!form && (c == '!' || c == '~' || c == '\'' || c == '(' || c == ')')) keep = true;
            if (keep) out += (char)c;
            else if (form && c == ' ') out += '+';
            else { out += '%'; out += HEXU[c >> 4]; out += HEXU[c & 15]; }
        }
        return out;
    }

    int hexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Replaces invalid UTF-8 bytes with U+FFFD (what a TextDecoder does)
    std::string sanitizeUtf8(const std::string &s)
    {
        std::string out;
        size_t i = 0, n = s.size();
        while (i < n)
        {
            unsigned char c = s[i];
            size_t extra = 0;
            uint32_t cp = 0;
            if (c < 0x80) { out += (char)c; i++; continue; }
            if (c >= 0xc2 && c <= 0xdf) { extra = 1; cp = c & 0x1f; }
            else if ((c & 0xf0) == 0xe0) { extra = 2; cp = c & 0x0f; }
            else if (c >= 0xf0 && c <= 0xf4) { extra = 3; cp = c & 0x07; }
            bool ok = extra && i + extra < n;
            for (size_t k = 1; ok && k <= extra; k++)
            {
                if (((unsigned char)s[i + k] & 0xc0) != 0x80) ok = false;
                else cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3f);
            }
            if (ok && ((extra == 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) ||
                       (extra == 3 && (cp < 0x10000 || cp > 0x10ffff))))
                ok = false;
            if (ok) { out.append(s, i, extra + 1); i += extra + 1; }
            else { out += "\xef\xbf\xbd"; i++; }
        }
        return out;
    }

    // query component decoding (plusAsSpace) or decodeURIComponent (strict)
    bool pctDecode(const std::string &s, bool form, std::string &out)
    {
        std::string r;
        for (size_t i = 0; i < s.size(); i++)
        {
            char c = s[i];
            if (c == '%')
            {
                if (i + 2 < s.size() && hexVal(s[i + 1]) >= 0 && hexVal(s[i + 2]) >= 0)
                {
                    r += (char)(hexVal(s[i + 1]) * 16 + hexVal(s[i + 2]));
                    i += 2;
                    continue;
                }
                if (!form) return false; // decodeURIComponent throws on a malformed escape
            }
            r += (form && c == '+') ? ' ' : c;
        }
        out = form ? sanitizeUtf8(r) : r;
        if (!form)
        {
            // decodeURIComponent also throws on invalid UTF-8
            if (sanitizeUtf8(r) != r) return false;
        }
        return true;
    }

    // ---- decimal amounts -------------------------------------------------------------------
    // "^\d+(\.\d+)?$" -> integer digits and fraction digits (trailing zeros removed)
    bool splitAmount(const std::string &a, std::string &ip, std::string &fp)
    {
        size_t dot = a.find('.');
        ip = dot == std::string::npos ? a : a.substr(0, dot);
        fp = dot == std::string::npos ? "" : a.substr(dot + 1);
        if (ip.empty() || (dot != std::string::npos && fp.empty())) return false;
        for (char c : ip) if (c < '0' || c > '9') return false;
        for (char c : fp) if (c < '0' || c > '9') return false;
        while (!fp.empty() && fp.back() == '0') fp.pop_back();
        size_t nz = ip.find_first_not_of('0');
        ip = nz == std::string::npos ? "0" : ip.substr(nz);
        return true;
    }

    // like BigNumber(a).toFixed(): no leading zeros, no trailing fraction zeros
    bool normalizeAmount(const std::string &a, std::string &out)
    {
        std::string ip, fp;
        if (!splitAmount(a, ip, fp)) return false;
        out = fp.empty() ? ip : ip + "." + fp;
        return true;
    }

    // ---- https links -----------------------------------------------------------------------
    // Minimal URL normalization like `new URL(s).href` for https links
    bool normalizeHttps(const std::string &in, std::string &out)
    {
        if (in.size() < 9) return false;
        std::string scheme = in.substr(0, 8);
        for (char &c : scheme) c = (char)tolower((unsigned char)c);
        if (scheme != "https://") return false;
        std::string enc;
        for (unsigned char c : in)
        {
            if (c <= 0x20 || c == 0x7f) return false;
            if (c >= 0x80) { enc += '%'; enc += HEXU[c >> 4]; enc += HEXU[c & 15]; } // URL parsers percent-encode non-ASCII
            else enc += (char)c;
        }
        size_t end = enc.find_first_of("/?#", 8);
        std::string auth = enc.substr(8, end == std::string::npos ? std::string::npos : end - 8);
        if (auth.empty() || auth[0] == ':' || auth.find('@') != std::string::npos) return false;
        for (char &c : auth) c = (char)tolower((unsigned char)c);
        if (auth.size() > 4 && auth.compare(auth.size() - 4, 4, ":443") == 0) auth.resize(auth.size() - 4);
        std::string rest = end == std::string::npos ? "" : enc.substr(end);
        if (rest.empty() || rest[0] != '/') rest = "/" + rest;
        out = "https://" + auth + rest;
        return true;
    }

    const size_t MAX_URL = 2048;
}

// ============================================================================
// URL encoding / parsing
// ============================================================================

bool SolanaPay::amountToBaseUnits(const String &amountStr, uint8_t decimals, uint64_t &outUnits, bool roundUp)
{
    std::string ip, fp;
    if (!splitAmount(amountStr.c_str(), ip, fp)) return false;
    bool extra = fp.size() > decimals;
    if (extra && !roundUp) return false;
    std::string digits = ip == "0" ? "" : ip;
    std::string frac = extra ? fp.substr(0, decimals) : fp;
    digits += frac + std::string(decimals - frac.size(), '0');
    uint64_t v = 0;
    for (char c : digits)
    {
        uint64_t d = (uint64_t)(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (extra) // remaining fraction digits are non-zero (trailing zeros were removed)
    {
        if (v == UINT64_MAX) return false;
        v++;
    }
    outUnits = v;
    return true;
}

String SolanaPay::encodeTransfer(const PayTransfer &req, String *outError)
{
    std::string recipient = canonicalKey(req.recipient.c_str());
    if (recipient.empty()) { setErr(outError, "recipient invalid"); return String(); }
    std::string q;
    auto add = [&](const char *key, const std::string &val) {
        q += q.empty() ? "?" : "&";
        q += key;
        q += "=";
        q += pctEncode(val, true);
    };
    if (req.amount.length())
    {
        std::string a;
        if (!normalizeAmount(req.amount.c_str(), a)) { setErr(outError, "amount invalid"); return String(); }
        add("amount", a);
    }
    if (req.splToken.length())
    {
        std::string t = canonicalKey(req.splToken.c_str());
        if (t.empty()) { setErr(outError, "spl-token invalid"); return String(); }
        add("spl-token", t);
    }
    for (const String &r : req.references)
    {
        std::string k = canonicalKey(r.c_str());
        if (k.empty()) { setErr(outError, "reference invalid"); return String(); }
        add("reference", k);
    }
    if (req.label.length()) add("label", req.label.c_str());
    if (req.message.length()) add("message", req.message.c_str());
    if (req.memo.length()) add("memo", req.memo.c_str());
    return String(("solana:" + recipient + q).c_str());
}

String SolanaPay::encodeTransactionRequest(const PayTransactionRequest &req, String *outError)
{
    std::string link;
    if (!normalizeHttps(req.link.c_str(), link) || link.find('#') != std::string::npos)
    {
        setErr(outError, "link invalid");
        return String();
    }
    size_t qm = link.find('?');
    std::string path;
    if (qm != std::string::npos && qm + 1 < link.size()) // non-empty search
    {
        size_t p = link.find("/?");
        if (p != std::string::npos) link.erase(p, 1); // replace "/?" with "?"
        path = pctEncode(link, false);
    }
    else
    {
        if (!link.empty() && link.back() == '/') link.pop_back();
        path = link;
    }
    std::string q;
    auto add = [&](const char *key, const String &val) {
        if (!val.length()) return;
        q += q.empty() ? "?" : "&";
        q += key;
        q += "=";
        q += pctEncode(val.c_str(), true);
    };
    add("label", req.label);
    add("message", req.message);
    // an empty "?" at the end of the link is replaced by the new query
    if (!q.empty() && !path.empty() && path.back() == '?') path.pop_back();
    return String(("solana:" + path + q).c_str());
}

PayUrlKind SolanaPay::parse(const String &urlIn, PayTransfer &outTransfer, PayTransactionRequest &outTx, String *outError)
{
    std::string url(urlIn.c_str());
    if (url.size() > MAX_URL) { setErr(outError, "length invalid"); return PayUrlKind::Invalid; }
    // URL parsing: trim control characters / spaces, drop tabs and line breaks
    size_t b = 0, e = url.size();
    while (b < e && (unsigned char)url[b] <= 0x20) b++;
    while (e > b && (unsigned char)url[e - 1] <= 0x20) e--;
    std::string u;
    for (size_t i = b; i < e; i++)
        if (url[i] != '\t' && url[i] != '\n' && url[i] != '\r') u += url[i];
    if (u.size() < 7)
    {
        setErr(outError, "protocol invalid");
        return PayUrlKind::Invalid;
    }
    std::string scheme = u.substr(0, 7);
    for (char &c : scheme) c = (char)tolower((unsigned char)c);
    if (scheme != "solana:") { setErr(outError, "protocol invalid"); return PayUrlKind::Invalid; }
    std::string rest = u.substr(7);
    size_t hash = rest.find('#');
    if (hash != std::string::npos) rest.erase(hash);
    size_t qm = rest.find('?');
    std::string pathname = rest.substr(0, qm);
    std::string query = qm == std::string::npos ? "" : rest.substr(qm + 1);
    if (pathname.empty()) { setErr(outError, "pathname missing"); return PayUrlKind::Invalid; }

    // query parameters (first value wins for get(), all values for reference)
    std::vector<std::pair<std::string, std::string>> params;
    size_t pos = 0;
    while (pos <= query.size() && !query.empty())
    {
        size_t amp = query.find('&', pos);
        std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (!part.empty())
        {
            size_t eq = part.find('=');
            std::string k, v;
            pctDecode(part.substr(0, eq), true, k);
            if (eq != std::string::npos) pctDecode(part.substr(eq + 1), true, v);
            params.push_back(std::make_pair(k, v));
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    auto get = [&](const char *key, std::string &out) {
        for (const auto &p : params)
            if (p.first == key) { out = p.second; return true; }
        return false;
    };

    if (pathname.find_first_of(":%") != std::string::npos)
    {
        std::string decoded, link;
        if (!pctDecode(pathname, false, decoded) || !normalizeHttps(decoded, link))
        {
            setErr(outError, "link invalid");
            return PayUrlKind::Invalid;
        }
        PayTransactionRequest t;
        t.link = String(link.c_str());
        std::string v;
        if (get("label", v) && !v.empty()) t.label = String(v.c_str());
        if (get("message", v) && !v.empty()) t.message = String(v.c_str());
        outTx = t;
        return PayUrlKind::Transaction;
    }

    PayTransfer r;
    std::string recipient = canonicalKey(pathname);
    if (recipient.empty()) { setErr(outError, "recipient invalid"); return PayUrlKind::Invalid; }
    r.recipient = String(recipient.c_str());
    std::string v;
    if (get("amount", v))
    {
        std::string a;
        if (!normalizeAmount(v, a)) { setErr(outError, "amount invalid"); return PayUrlKind::Invalid; }
        r.amount = String(a.c_str());
    }
    if (get("spl-token", v))
    {
        std::string t = canonicalKey(v);
        if (t.empty()) { setErr(outError, "spl-token invalid"); return PayUrlKind::Invalid; }
        r.splToken = String(t.c_str());
    }
    for (const auto &p : params)
    {
        if (p.first != "reference") continue;
        std::string k = canonicalKey(p.second);
        if (k.empty()) { setErr(outError, "reference invalid"); return PayUrlKind::Invalid; }
        r.references.push_back(String(k.c_str()));
    }
    if (get("label", v) && !v.empty()) r.label = String(v.c_str());
    if (get("message", v) && !v.empty()) r.message = String(v.c_str());
    if (get("memo", v) && !v.empty()) r.memo = String(v.c_str());
    outTransfer = r;
    return PayUrlKind::Transfer;
}

bool SolanaPay::parseTransfer(const String &url, PayTransfer &out, String *outError)
{
    PayTransactionRequest t;
    PayTransfer r;
    if (parse(url, r, t, outError) != PayUrlKind::Transfer)
    {
        if (outError && outError->isEmpty()) *outError = "not a transfer request";
        return false;
    }
    out = r;
    return true;
}

bool SolanaPay::parseTransactionRequest(const String &url, PayTransactionRequest &out, String *outError)
{
    PayTransactionRequest t;
    PayTransfer r;
    if (parse(url, r, t, outError) != PayUrlKind::Transaction)
    {
        if (outError && outError->isEmpty()) *outError = "not a transaction request";
        return false;
    }
    out = t;
    return true;
}

// ============================================================================
// findReference
// ============================================================================

bool Infratic::findReference(const String &reference, String &outSignature, const String &commitment, String *outError)
{
    if (canonicalKey(reference.c_str()).empty())
    {
        setErr(outError, "reference invalid");
        return false;
    }
    const unsigned PAGE = 100;
    String before, oldest;
    // newest first: the oldest signature is the last entry of the last page
    for (int page = 0; page < 100; page++)
    {
        String params = "[\"" + reference + R"(",{"limit":)" + String(PAGE) + R"(,"commitment":")" + commitment + "\"";
        if (!before.isEmpty()) params += R"(,"before":")" + before + "\"";
        params += "}]";
        String response;
        if (!rpcCall("getSignaturesForAddress", params, response))
        {
            setErr(outError, "RPC request failed");
            return false;
        }
        DynamicJsonDocument filter(256);
        filter["result"][0]["signature"] = true;
        DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
        if (deserializeJson(doc, response, DeserializationOption::Filter(filter)) || !doc["result"].is<JsonArray>())
        {
            setErr(outError, "unexpected RPC response");
            return false;
        }
        JsonArray arr = doc["result"].as<JsonArray>();
        if (arr.size() == 0) break;
        oldest = arr[arr.size() - 1]["signature"] | "";
        if (oldest.isEmpty()) { setErr(outError, "unexpected RPC response"); return false; }
        if (arr.size() < PAGE) break;
        before = oldest;
    }
    if (oldest.isEmpty())
    {
        setErr(outError, "not found");
        return false;
    }
    outSignature = oldest;
    return true;
}

// ============================================================================
// validateTransfer
// ============================================================================

namespace
{
    struct PayIx
    {
        std::string program;
        std::vector<std::string> accounts;
        std::vector<uint8_t> data;
    };

    struct TokenBal
    {
        bool found = false;
        uint64_t amount = 0;
        int decimals = -1;
    };

    TokenBal findTokenBalance(JsonArray arr, int index)
    {
        TokenBal b;
        for (JsonObject o : arr)
        {
            if (o["accountIndex"].as<int>() != index || !o["accountIndex"].is<int>()) continue;
            b.found = true;
            b.amount = strtoull(o["uiTokenAmount"]["amount"] | "0", nullptr, 10);
            b.decimals = o["uiTokenAmount"]["decimals"] | -1;
            break;
        }
        return b;
    }

    bool decodeIxData(const char *b58, std::vector<uint8_t> &out)
    {
        size_t cap = strlen(b58) + 1;
        std::vector<uint8_t> buf(cap);
        size_t len = cap;
        if (cap > 1 && !base58Decode(String(b58), buf.data(), len)) return false;
        if (cap <= 1) len = 0;
        buf.resize(len);
        out.swap(buf);
        return true;
    }
}

bool Infratic::validateTransfer(const String &signature, const PayTransfer &expected, String *outError,
                                const String &commitment)
{
    std::string recipient = canonicalKey(expected.recipient.c_str());
    std::string mint = expected.splToken.length() ? canonicalKey(expected.splToken.c_str()) : "";
    if (recipient.empty() || (expected.splToken.length() && mint.empty()))
    {
        setErr(outError, "invalid expected transfer");
        return false;
    }
    std::vector<std::string> refs;
    for (const String &r : expected.references)
    {
        std::string k = canonicalKey(r.c_str());
        if (k.empty()) { setErr(outError, "invalid expected transfer"); return false; }
        refs.push_back(k);
    }

    String params = "[\"" + signature + R"(",{"encoding":"json","commitment":")" + commitment +
                    R"(","maxSupportedTransactionVersion":0}])";
    String response;
    if (!rpcCall("getTransaction", params, response))
    {
        setErr(outError, "RPC request failed");
        return false;
    }

    DynamicJsonDocument filter(2048);
    JsonObject fm = filter["result"].createNestedObject("meta");
    fm["err"] = true;
    fm["preBalances"] = true;
    fm["postBalances"] = true;
    fm["preTokenBalances"][0]["accountIndex"] = true;
    fm["preTokenBalances"][0]["uiTokenAmount"]["amount"] = true;
    fm["preTokenBalances"][0]["uiTokenAmount"]["decimals"] = true;
    fm["postTokenBalances"][0]["accountIndex"] = true;
    fm["postTokenBalances"][0]["uiTokenAmount"]["amount"] = true;
    fm["postTokenBalances"][0]["uiTokenAmount"]["decimals"] = true;
    fm["loadedAddresses"] = true;
    filter["result"]["transaction"]["message"]["accountKeys"] = true;
    filter["result"]["transaction"]["message"]["instructions"][0]["programIdIndex"] = true;
    filter["result"]["transaction"]["message"]["instructions"][0]["accounts"] = true;
    filter["result"]["transaction"]["message"]["instructions"][0]["data"] = true;

    DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter)))
    {
        setErr(outError, "unexpected RPC response");
        return false;
    }
    JsonObject result = doc["result"];
    if (result.isNull()) { setErr(outError, "not found"); return false; }
    JsonObject meta = result["meta"];
    if (meta.isNull()) { setErr(outError, "missing meta"); return false; }
    if (!meta["err"].isNull())
    {
        String e;
        serializeJson(meta["err"], e);
        setErr(outError, std::string("transaction failed: ") + e.c_str());
        return false;
    }

    // account keys: static keys, then keys loaded from lookup tables (writable first)
    std::vector<std::string> keys;
    for (JsonVariant k : result["transaction"]["message"]["accountKeys"].as<JsonArray>()) keys.push_back(k.as<const char *>() ? k.as<const char *>() : "");
    for (JsonVariant k : meta["loadedAddresses"]["writable"].as<JsonArray>()) keys.push_back(k.as<const char *>() ? k.as<const char *>() : "");
    for (JsonVariant k : meta["loadedAddresses"]["readonly"].as<JsonArray>()) keys.push_back(k.as<const char *>() ? k.as<const char *>() : "");

    std::vector<PayIx> ixs;
    for (JsonObject o : result["transaction"]["message"]["instructions"].as<JsonArray>())
    {
        PayIx ix;
        size_t pi = o["programIdIndex"] | 0;
        ix.program = pi < keys.size() ? keys[pi] : "";
        for (JsonVariant a : o["accounts"].as<JsonArray>())
        {
            size_t ai = a.as<size_t>();
            ix.accounts.push_back(ai < keys.size() ? keys[ai] : "");
        }
        if (!decodeIxData(o["data"] | "", ix.data))
        {
            setErr(outError, "invalid instruction data");
            return false;
        }
        ixs.push_back(ix);
    }
    if (ixs.empty()) { setErr(outError, "missing transfer instruction"); return false; }
    const PayIx &transfer = ixs.back();

    auto checkReferences = [&](size_t firstExtra) -> bool {
        size_t extras = transfer.accounts.size() > firstExtra ? transfer.accounts.size() - firstExtra : 0;
        if (extras != refs.size()) { setErr(outError, "invalid references"); return false; }
        for (size_t i = 0; i < refs.size(); i++)
            if (transfer.accounts[firstExtra + i] != refs[i])
            {
                setErr(outError, "invalid reference " + std::to_string(i));
                return false;
            }
        return true;
    };

    uint64_t pre = 0, post = 0, wanted = 0;
    if (mint.empty())
    {
        int idx = -1;
        for (size_t i = 0; i < keys.size(); i++)
            if (keys[i] == recipient) { idx = (int)i; break; }
        if (idx < 0) { setErr(outError, "recipient not found"); return false; }
        if (!refs.empty())
        {
            // must be a system transfer: u32 LE 2 + u64 lamports, accounts from, to, references...
            if (transfer.program != INFRATIC_SYSTEM_PROGRAM_ID || transfer.data.size() < 12 || transfer.data[0] != 2 ||
                transfer.data[1] || transfer.data[2] || transfer.data[3] || transfer.accounts.size() < 2)
            {
                setErr(outError, "invalid transfer");
                return false;
            }
            if (!checkReferences(2)) return false;
        }
        JsonArray preB = meta["preBalances"], postB = meta["postBalances"];
        pre = idx < (int)preB.size() ? preB[idx].as<uint64_t>() : 0;
        post = idx < (int)postB.size() ? postB[idx].as<uint64_t>() : 0;
        if (expected.amount.length() && !SolanaPay::amountToBaseUnits(expected.amount, 9, wanted, true))
        {
            setErr(outError, "amount invalid");
            return false;
        }
    }
    else
    {
        // recipient's associated token account, for both token programs
        int idx = -1;
        const char *programs[2] = {INFRATIC_TOKEN_PROGRAM_ID, INFRATIC_TOKEN_2022_PROGRAM_ID};
        for (int p = 0; p < 2 && idx < 0; p++)
        {
            String ata;
            if (!getAssociatedTokenAddress(String(recipient.c_str()), String(mint.c_str()), ata, programs[p])) continue;
            for (size_t i = 0; i < keys.size(); i++)
                if (keys[i] == ata.c_str()) { idx = (int)i; break; }
        }
        if (idx < 0) { setErr(outError, "recipient not found"); return false; }
        if (!refs.empty())
        {
            bool tokenProgram = transfer.program == INFRATIC_TOKEN_PROGRAM_ID || transfer.program == INFRATIC_TOKEN_2022_PROGRAM_ID;
            // Transfer (3): source, destination, owner, signers... TransferChecked (12): source, mint, destination, owner, signers...
            if (!tokenProgram || transfer.data.empty() || (transfer.data[0] != 3 && transfer.data[0] != 12))
            {
                setErr(outError, "invalid transfer");
                return false;
            }
            if (!checkReferences(transfer.data[0] == 3 ? 3 : 4)) return false;
        }
        TokenBal preT = findTokenBalance(meta["preTokenBalances"], idx);
        TokenBal postT = findTokenBalance(meta["postTokenBalances"], idx);
        pre = preT.amount;
        post = postT.amount;
        int decimals = postT.found ? postT.decimals : preT.decimals;
        if (expected.amount.length())
        {
            if (decimals < 0 || decimals > 255 || !SolanaPay::amountToBaseUnits(expected.amount, (uint8_t)decimals, wanted, true))
            {
                setErr(outError, "amount not transferred");
                return false;
            }
        }
    }
    if (post < pre || post - pre < wanted)
    {
        setErr(outError, "amount not transferred");
        return false;
    }

    if (expected.memo.length())
    {
        if (ixs.size() < 2) { setErr(outError, "missing memo instruction"); return false; }
        const PayIx &m = ixs[ixs.size() - 2];
        if (m.program != MEMO_PROGRAM_ID) { setErr(outError, "invalid memo program"); return false; }
        if (!m.accounts.empty()) { setErr(outError, "invalid memo keys"); return false; }
        std::string want(expected.memo.c_str());
        if (m.data.size() != want.size() || memcmp(m.data.data(), want.data(), want.size()) != 0)
        {
            setErr(outError, "invalid memo");
            return false;
        }
    }
    return true;
}

bool Infratic::validateTransfer(const String &signature, const String &recipient, const String &amount,
                                const String &splToken, const String &reference, String *outError)
{
    PayTransfer t;
    t.recipient = recipient;
    t.amount = amount;
    t.splToken = splToken;
    if (!reference.isEmpty()) t.references.push_back(reference);
    return validateTransfer(signature, t, outError);
}

// ============================================================================
// createPayTransfer
// ============================================================================

namespace
{
    struct PayAccountInfo
    {
        bool exists = false;
        uint64_t lamports = 0;
        String owner;
        bool executable = false;
        std::vector<uint8_t> data;
    };

    // 1 = ok (exists may be false), 0 = RPC / parse error
    int fetchAccount(Infratic &sol, const String &address, bool withData, PayAccountInfo &out)
    {
        String params = "[\"" + address + R"(",{"encoding":"base64","commitment":"confirmed")" +
                        (withData ? "" : R"(,"dataSlice":{"offset":0,"length":0})") + "}]";
        String response;
        if (!sol.rpcCall("getAccountInfo", params, response)) return 0;
        DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
        if (deserializeJson(doc, response)) return 0;
        JsonObject value = doc["result"]["value"];
        out = PayAccountInfo();
        if (value.isNull()) return 1;
        out.exists = true;
        out.lamports = value["lamports"] | 0ULL;
        out.owner = value["owner"] | "";
        out.executable = value["executable"] | false;
        if (withData)
        {
            const char *b64 = value["data"][0] | "";
            if (!fromBase64(b64, out.data)) return 0;
        }
        return 1;
    }

    uint64_t readU64LE(const std::vector<uint8_t> &d, size_t o)
    {
        uint64_t v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | d[o + i];
        return v;
    }
}

bool Infratic::createPayTransfer(const PayTransfer &req, const String &senderBase58, Transaction &outTx, String *outError)
{
    std::string recipient = canonicalKey(req.recipient.c_str());
    std::string sender = canonicalKey(senderBase58.c_str());
    if (recipient.empty()) { setErr(outError, "recipient invalid"); return false; }
    if (sender.empty()) { setErr(outError, "sender invalid"); return false; }
    if (req.amount.isEmpty()) { setErr(outError, "amount missing"); return false; }
    std::string mint = req.splToken.length() ? canonicalKey(req.splToken.c_str()) : "";
    if (req.splToken.length() && mint.empty()) { setErr(outError, "spl-token invalid"); return false; }
    for (const String &r : req.references)
        if (canonicalKey(r.c_str()).empty()) { setErr(outError, "reference invalid"); return false; }

    Pubkey senderKey = Pubkey::fromBase58(String(sender.c_str()));
    Pubkey recipientKey = Pubkey::fromBase58(String(recipient.c_str()));

    PayAccountInfo senderInfo, recipientInfo;
    if (!fetchAccount(*this, String(sender.c_str()), false, senderInfo)) { setErr(outError, "RPC request failed"); return false; }
    if (!senderInfo.exists) { setErr(outError, "sender not found"); return false; }
    if (!fetchAccount(*this, String(recipient.c_str()), false, recipientInfo)) { setErr(outError, "RPC request failed"); return false; }
    if (!recipientInfo.exists) { setErr(outError, "recipient not found"); return false; }

    Instruction transfer(Pubkey(), {}, {});
    if (mint.empty())
    {
        if (senderInfo.owner != INFRATIC_SYSTEM_PROGRAM_ID) { setErr(outError, "sender owner invalid"); return false; }
        if (senderInfo.executable) { setErr(outError, "sender executable"); return false; }
        if (recipientInfo.owner != INFRATIC_SYSTEM_PROGRAM_ID) { setErr(outError, "recipient owner invalid"); return false; }
        if (recipientInfo.executable) { setErr(outError, "recipient executable"); return false; }
        uint64_t lamports;
        if (!SolanaPay::amountToBaseUnits(req.amount, 9, lamports)) { setErr(outError, "amount decimals invalid"); return false; }
        if (lamports > senderInfo.lamports) { setErr(outError, "insufficient funds"); return false; }
        // SystemProgram.Transfer: u32 LE 2 + u64 lamports
        std::vector<uint8_t> data = encodeU32LE(2);
        std::vector<uint8_t> amt = encodeU64LE(lamports);
        data.insert(data.end(), amt.begin(), amt.end());
        transfer = Instruction(Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID),
                               {AccountMeta::writable(senderKey, true), AccountMeta::writable(recipientKey, false)}, data);
    }
    else
    {
        PayAccountInfo mintInfo;
        if (!fetchAccount(*this, String(mint.c_str()), true, mintInfo)) { setErr(outError, "RPC request failed"); return false; }
        if (!mintInfo.exists) { setErr(outError, "mint not found"); return false; }
        String tokenProgramId = mintInfo.owner == INFRATIC_TOKEN_2022_PROGRAM_ID ? INFRATIC_TOKEN_2022_PROGRAM_ID : INFRATIC_TOKEN_PROGRAM_ID;
        if (mintInfo.owner != tokenProgramId || mintInfo.data.size() < 82) { setErr(outError, "mint invalid"); return false; }
        if (mintInfo.data[45] != 1) { setErr(outError, "mint not initialized"); return false; }
        uint8_t decimals = mintInfo.data[44];
        uint64_t tokens;
        if (!SolanaPay::amountToBaseUnits(req.amount, decimals, tokens)) { setErr(outError, "amount decimals invalid"); return false; }

        String senderAta, recipientAta;
        if (!getAssociatedTokenAddress(String(sender.c_str()), String(mint.c_str()), senderAta, tokenProgramId) ||
            !getAssociatedTokenAddress(String(recipient.c_str()), String(mint.c_str()), recipientAta, tokenProgramId))
        {
            setErr(outError, "cannot derive token accounts");
            return false;
        }
        PayAccountInfo sAcc, rAcc;
        if (!fetchAccount(*this, senderAta, true, sAcc) || !fetchAccount(*this, recipientAta, true, rAcc)) { setErr(outError, "RPC request failed"); return false; }
        // token account: mint 0..32, owner 32..64, amount 64..72, state at 108 (1 = initialized, 2 = frozen)
        if (!sAcc.exists || sAcc.owner != tokenProgramId || sAcc.data.size() < 165) { setErr(outError, "sender not initialized"); return false; }
        if (sAcc.data[108] == 0) { setErr(outError, "sender not initialized"); return false; }
        if (sAcc.data[108] == 2) { setErr(outError, "sender frozen"); return false; }
        if (!rAcc.exists || rAcc.owner != tokenProgramId || rAcc.data.size() < 165) { setErr(outError, "recipient not initialized"); return false; }
        if (rAcc.data[108] == 0) { setErr(outError, "recipient not initialized"); return false; }
        if (rAcc.data[108] == 2) { setErr(outError, "recipient frozen"); return false; }
        if (tokens > readU64LE(sAcc.data, 64)) { setErr(outError, "insufficient funds"); return false; }
        transfer = transferCheckedIx(Pubkey::fromBase58(senderAta), Pubkey::fromBase58(String(mint.c_str())),
                                     Pubkey::fromBase58(recipientAta), senderKey, tokens, decimals,
                                     Pubkey::fromBase58(tokenProgramId));
    }
    // reference keys are read-only, non-signer extra accounts on the transfer instruction
    for (const String &r : req.references)
        transfer.accounts.push_back(AccountMeta{Pubkey::fromBase58(r), false, false});

    String blockhash;
    uint64_t lastValid;
    if (!getLatestBlockhash(blockhash, lastValid)) { setErr(outError, "RPC request failed"); return false; }

    Transaction tx;
    tx.fee_payer = senderKey;
    tx.recent_blockhash = blockhash;
    if (req.memo.length())
    {
        std::string memo(req.memo.c_str());
        tx.add(Instruction(Pubkey::fromBase58(MEMO_PROGRAM_ID), {}, std::vector<uint8_t>(memo.begin(), memo.end())));
    }
    tx.add(transfer);
    outTx = tx;
    return true;
}
