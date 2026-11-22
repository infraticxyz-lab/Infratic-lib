// Anchor helpers: Borsh reader/writer, event discriminators and event parsing.
#include "infratic_internal.h"
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
#define INFRATIC_SHA256 mbedtls_sha256
#else
#define INFRATIC_SHA256 mbedtls_sha256_ret
#endif

// ----------------------------------------------------------------------------
// BorshReader
// ----------------------------------------------------------------------------

bool BorshReader::need(size_t n)
{
    if (!ok || pos + n > buf.size()) ok = false;
    return ok;
}

uint8_t BorshReader::u8() { return need(1) ? buf[pos++] : 0; }

uint16_t BorshReader::u16()
{
    if (!need(2)) return 0;
    uint16_t v = buf[pos] | (buf[pos + 1] << 8);
    pos += 2;
    return v;
}

uint32_t BorshReader::u32()
{
    if (!need(4)) return 0;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)buf[pos + i] << (8 * i);
    pos += 4;
    return v;
}

uint64_t BorshReader::u64()
{
    if (!need(8)) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)buf[pos + i] << (8 * i);
    pos += 8;
    return v;
}

int64_t BorshReader::i64() { return (int64_t)u64(); }

bool BorshReader::boolean() { return u8() != 0; }

String BorshReader::pubkey()
{
    if (!need(32)) return "";
    String s = base58Encode(buf.data() + pos, 32);
    pos += 32;
    return s;
}

std::vector<uint8_t> BorshReader::bytes(size_t n)
{
    if (!need(n)) return {};
    std::vector<uint8_t> v(buf.begin() + pos, buf.begin() + pos + n);
    pos += n;
    return v;
}

String BorshReader::str(size_t maxLen)
{
    uint32_t len = u32();
    if (!ok || len > maxLen || !need(len))
    {
        ok = false;
        return "";
    }
    String s((const char *)buf.data() + pos, len);
    pos += len;
    return s;
}

std::vector<uint8_t> BorshReader::vecU8()
{
    uint32_t len = u32();
    return ok ? bytes(len) : std::vector<uint8_t>();
}

// ----------------------------------------------------------------------------
// BorshWriter
// ----------------------------------------------------------------------------

BorshWriter &BorshWriter::u8(uint8_t v)
{
    data.push_back(v);
    return *this;
}

BorshWriter &BorshWriter::u16(uint16_t v)
{
    data.push_back(v & 0xFF);
    data.push_back(v >> 8);
    return *this;
}

BorshWriter &BorshWriter::u32(uint32_t v)
{
    std::vector<uint8_t> b = encodeU32LE(v);
    data.insert(data.end(), b.begin(), b.end());
    return *this;
}

BorshWriter &BorshWriter::u64(uint64_t v)
{
    std::vector<uint8_t> b = encodeU64LE(v);
    data.insert(data.end(), b.begin(), b.end());
    return *this;
}

BorshWriter &BorshWriter::i64(int64_t v) { return u64((uint64_t)v); }

BorshWriter &BorshWriter::boolean(bool v) { return u8(v ? 1 : 0); }

BorshWriter &BorshWriter::pubkey(const String &base58)
{
    std::vector<uint8_t> k = base58ToPubkey(base58);
    if (k.size() != 32) k.assign(32, 0);
    data.insert(data.end(), k.begin(), k.end());
    return *this;
}

BorshWriter &BorshWriter::bytes(const std::vector<uint8_t> &v)
{
    data.insert(data.end(), v.begin(), v.end());
    return *this;
}

BorshWriter &BorshWriter::str(const String &s)
{
    appendBorshString(data, s);
    return *this;
}

BorshWriter &BorshWriter::vecU8(const std::vector<uint8_t> &v)
{
    u32(v.size());
    return bytes(v);
}

// ----------------------------------------------------------------------------
// Events
// ----------------------------------------------------------------------------

namespace
{
    std::vector<uint8_t> prefixedHash8(const String &prefix, const String &name)
    {
        String input = prefix + name;
        uint8_t hash[32];
        INFRATIC_SHA256((const unsigned char *)input.c_str(), input.length(), hash, 0);
        return std::vector<uint8_t>(hash, hash + 8);
    }
}

std::vector<uint8_t> Infratic::eventDiscriminator(const String &eventName)
{
    return prefixedHash8("event:", eventName);
}

std::vector<uint8_t> Infratic::accountDiscriminator(const String &accountName)
{
    return prefixedHash8("account:", accountName);
}

bool AnchorEvent::is(const String &eventName) const
{
    return discriminator == Infratic::eventDiscriminator(eventName);
}

bool Infratic::parseAnchorEvents(const std::vector<String> &logs, std::vector<AnchorEvent> &outEvents,
                                 const String &programIdFilter)
{
    // Track the invoke stack so each "Program data:" line belongs to the right program
    std::vector<String> stack;
    for (const String &line : logs)
    {
        if (line.startsWith("Program ") && line.indexOf(" invoke [") > 0)
        {
            stack.push_back(line.substring(8, line.indexOf(" invoke [")));
        }
        else if (line.startsWith("Program ") && (line.endsWith(" success") || line.indexOf(" failed") > 0) &&
                 !stack.empty() && line.substring(8).startsWith(stack.back()))
        {
            stack.pop_back();
        }
        else if (line.startsWith("Program data: "))
        {
            String program = stack.empty() ? String("") : stack.back();
            if (!programIdFilter.isEmpty() && program != programIdFilter)
            {
                continue;
            }
            std::vector<uint8_t> raw;
            String b64 = line.substring(14);
            b64.trim();
            if (!infratic_detail::fromBase64(b64.c_str(), raw) || raw.size() < 8)
            {
                continue;
            }
            AnchorEvent ev;
            ev.programId = program;
            ev.discriminator.assign(raw.begin(), raw.begin() + 8);
            ev.data.assign(raw.begin() + 8, raw.end());
            outEvents.push_back(ev);
        }
    }
    return !outEvents.empty();
}

bool Infratic::getTransactionLogs(const String &signature, std::vector<String> &outLogs)
{
    String response;
    String params = "[\"" + signature + R"(",{"encoding":"json","commitment":"confirmed","maxSupportedTransactionVersion":0}])";
    if (!rpcCall("getTransaction", params, response))
    {
        return false;
    }

    // only keep the logs, the rest of the transaction can be large
    StaticJsonDocument<256> filter;
    filter["result"]["meta"]["logMessages"] = true;
    DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
    if (deserializeJson(doc, response, DeserializationOption::Filter(filter)))
    {
        return false;
    }

    JsonArray logs = doc["result"]["meta"]["logMessages"];
    if (logs.isNull())
    {
        _logErr.println("❌ Transaction not found: " + signature);
        return false;
    }
    outLogs.clear();
    for (JsonVariant l : logs)
    {
        outLogs.push_back(l.as<String>());
    }
    return true;
}
