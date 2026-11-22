// Solana RPC WebSocket subscriptions over a small built-in RFC 6455 client.
#include "infratic_internal.h"
#include <WiFiClientSecure.h>
#include <mbedtls/sha1.h>
#include <mbedtls/version.h>
#include <map>
#include <string>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
#define INFRATIC_SHA1 mbedtls_sha1
#else
#define INFRATIC_SHA1 mbedtls_sha1_ret
#endif

namespace
{
    enum SubKind
    {
        SUB_ACCOUNT = 0,
        SUB_PROGRAM = 1,
        SUB_LOGS = 2,
        SUB_SIGNATURE = 3
    };

    const char *UNSUBSCRIBE_METHODS[] = {"accountUnsubscribe", "programUnsubscribe", "logsUnsubscribe",
                                         "signatureUnsubscribe"};

    const uint32_t WS_TIMEOUT_MS = 5000;
    const uint32_t WS_PING_INTERVAL_MS = 30000;
    const uint32_t WS_RECONNECT_INTERVAL_MS = 5000;
}

struct InfraticWsState
{
    struct Sub
    {
        int kind;
        String method;
        String params;
        String extra; // signature for signatureSubscribe
        int64_t serverId;
    };

    String url;
    String host;
    String path = "/";
    uint16_t port = 443;
    bool secure = true;

    std::unique_ptr<WiFiClient> client;
    bool connected = false;
    bool autoReconnect = true;
    size_t maxMessage = 65536;

    std::vector<uint8_t> rx;
    std::string fragment;
    bool inFragment = false;

    int nextRequestId = 1;
    int nextHandle = 0;
    std::map<int, Sub> subs;

    AccountChangeCallback onAccount;
    ProgramAccountCallback onProgram;
    LogsCallback onLogs;
    SignatureCallback onSignature;

    unsigned long lastActivity = 0;
    unsigned long lastReconnectTry = 0;

    bool parseUrl(const String &u)
    {
        int schemeEnd = u.indexOf("://");
        if (schemeEnd < 0) return false;
        String scheme = u.substring(0, schemeEnd);
        secure = (scheme == "wss" || scheme == "https");
        port = secure ? 443 : 80;

        String rest = u.substring(schemeEnd + 3);
        int slash = rest.indexOf('/');
        int question = rest.indexOf('?');
        int cut = slash;
        if (cut < 0 || (question >= 0 && question < cut)) cut = question;
        String hostPort = cut < 0 ? rest : rest.substring(0, cut);
        path = cut < 0 ? String("/") : rest.substring(cut);
        if (path.startsWith("?")) path = "/" + path;

        int colon = hostPort.indexOf(':');
        if (colon >= 0)
        {
            host = hostPort.substring(0, colon);
            port = (uint16_t)hostPort.substring(colon + 1).toInt();
        }
        else
        {
            host = hostPort;
        }
        url = u;
        return !host.isEmpty();
    }

    size_t writeAll(const uint8_t *data, size_t len)
    {
        size_t sent = 0;
        while (client && sent < len)
        {
            size_t n = client->write(data + sent, len - sent);
            if (n == 0) break;
            sent += n;
        }
        return sent;
    }

    bool sendFrame(uint8_t opcode, const uint8_t *payload, size_t len)
    {
        if (!client || !connected) return false;
        std::vector<uint8_t> frame;
        frame.reserve(len + 14);
        frame.push_back(0x80 | opcode); // FIN
        if (len < 126)
        {
            frame.push_back(0x80 | (uint8_t)len); // client frames are always masked
        }
        else if (len <= 0xFFFF)
        {
            frame.push_back(0x80 | 126);
            frame.push_back((len >> 8) & 0xFF);
            frame.push_back(len & 0xFF);
        }
        else
        {
            frame.push_back(0x80 | 127);
            for (int i = 7; i >= 0; i--) frame.push_back(((uint64_t)len >> (8 * i)) & 0xFF);
        }
        uint32_t r = esp_random();
        uint8_t mask[4] = {(uint8_t)r, (uint8_t)(r >> 8), (uint8_t)(r >> 16), (uint8_t)(r >> 24)};
        frame.insert(frame.end(), mask, mask + 4);
        for (size_t i = 0; i < len; i++) frame.push_back(payload[i] ^ mask[i & 3]);
        return writeAll(frame.data(), frame.size()) == frame.size();
    }

    void close()
    {
        if (client)
        {
            if (connected) sendFrame(0x8, nullptr, 0);
            client->stop();
        }
        connected = false;
        rx.clear();
        fragment.clear();
        inFragment = false;
    }
};

namespace
{
    String wsAcceptFor(const String &key)
    {
        String in = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t digest[20];
        INFRATIC_SHA1((const unsigned char *)in.c_str(), in.length(), digest);
        return infratic_detail::toBase64(digest, 20);
    }

    bool readHandshake(InfraticWsState &s, String &headers)
    {
        unsigned long start = millis();
        std::vector<uint8_t> buf;
        while (millis() - start < WS_TIMEOUT_MS)
        {
            while (s.client->available() > 0)
            {
                uint8_t chunk[256];
                int n = s.client->read(chunk, sizeof(chunk));
                if (n <= 0) break;
                buf.insert(buf.end(), chunk, chunk + n);
            }
            for (size_t i = 3; i < buf.size(); i++)
            {
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n')
                {
                    headers = String((const char *)buf.data(), i + 1);
                    s.rx.assign(buf.begin() + i + 1, buf.end()); // frames that came with the response
                    return true;
                }
            }
            if (buf.size() > 4096) return false;
            delay(10);
        }
        return false;
    }
}

InfraticWsState &Infratic::ws()
{
    if (!_ws)
    {
        _ws = std::make_shared<InfraticWsState>();
        String u = _rpcUrl;
        if (u.startsWith("https://")) u = "wss://" + u.substring(8);
        else if (u.startsWith("http://")) u = "ws://" + u.substring(7);
        int p = u.indexOf(":8899");
        if (p > 0) u = u.substring(0, p) + ":8900" + u.substring(p + 5); // solana-test-validator
        _ws->parseUrl(u);
    }
    return *_ws;
}

void Infratic::setWsUrl(const String &wsUrl)
{
    InfraticWsState &s = ws();
    s.close();
    if (!s.parseUrl(wsUrl))
    {
        _logErr.println("❌ Invalid WebSocket URL: " + wsUrl);
    }
}

void Infratic::setWsAutoReconnect(bool enabled) { ws().autoReconnect = enabled; }
void Infratic::setWsMaxMessageSize(size_t bytes) { ws().maxMessage = bytes; }
bool Infratic::wsConnected() const { return _ws && _ws->connected; }

void Infratic::onAccountChange(AccountChangeCallback cb) { ws().onAccount = cb; }
void Infratic::onProgramAccountChange(ProgramAccountCallback cb) { ws().onProgram = cb; }
void Infratic::onLogs(LogsCallback cb) { ws().onLogs = cb; }
void Infratic::onSignature(SignatureCallback cb) { ws().onSignature = cb; }

bool Infratic::wsConnect()
{
    InfraticWsState &s = ws();
    s.close();

    if (s.secure)
    {
        WiFiClientSecure *c = new WiFiClientSecure();
        c->setInsecure();
        s.client.reset(c);
    }
    else
    {
        s.client.reset(new WiFiClient());
    }

    if (!s.client->connect(s.host.c_str(), s.port))
    {
        _logErr.println("❌ WebSocket connect failed: " + s.host);
        return false;
    }

    uint8_t keyBytes[16];
    for (int i = 0; i < 16; i += 4)
    {
        uint32_t r = esp_random();
        memcpy(keyBytes + i, &r, 4);
    }
    String key = infratic_detail::toBase64(keyBytes, 16);

    String req = "GET " + s.path + " HTTP/1.1\r\n" +
                 "Host: " + s.host + "\r\n" +
                 "Upgrade: websocket\r\n" +
                 "Connection: Upgrade\r\n" +
                 "Sec-WebSocket-Key: " + key + "\r\n" +
                 "Sec-WebSocket-Version: 13\r\n\r\n";
    s.writeAll((const uint8_t *)req.c_str(), req.length());

    String headers;
    if (!readHandshake(s, headers) || headers.indexOf(" 101") < 0)
    {
        _logErr.println("❌ WebSocket handshake failed");
        s.client->stop();
        return false;
    }

    String accept = wsAcceptFor(key);
    String lower = headers;
    for (unsigned i = 0; i < lower.length(); i++) lower.setCharAt(i, tolower(lower.charAt(i)));
    int a = lower.indexOf("sec-websocket-accept:");
    String got = a < 0 ? String("") : headers.substring(a + 21, headers.indexOf("\r\n", a));
    got.trim();
    if (got != accept)
    {
        _logErr.println("❌ WebSocket handshake: bad Sec-WebSocket-Accept");
        s.client->stop();
        return false;
    }

    s.connected = true;
    s.lastActivity = millis();
    _logInfo.println("🔌 WebSocket connected: " + s.host);
    return true;
}

void Infratic::wsDisconnect()
{
    if (_ws)
    {
        _ws->close();
        _ws->subs.clear();
    }
}

bool Infratic::wsSendText(const String &text)
{
    return ws().sendFrame(0x1, (const uint8_t *)text.c_str(), text.length());
}

void Infratic::wsHandleMessage(const String &msg, int waitForId, int64_t *outResult, bool *gotResult)
{
    InfraticWsState &s = ws();
    DynamicJsonDocument doc(infratic_detail::jsonCapacity(msg));
    if (deserializeJson(doc, msg))
    {
        _logErr.println("❌ WebSocket: JSON parse error");
        return;
    }

    if (!doc["id"].isNull())
    {
        if (waitForId > 0 && doc["id"].as<int>() == waitForId)
        {
            *gotResult = true;
            if (doc["error"].isNull())
            {
                *outResult = doc["result"].is<bool>() ? (doc["result"].as<bool>() ? 1 : 0) : doc["result"].as<long long>();
            }
            else
            {
                *outResult = -1;
                _logErr.println("❌ WebSocket RPC error: " + doc["error"]["message"].as<String>());
            }
        }
        return;
    }

    String method = doc["method"] | "";
    int64_t serverId = doc["params"]["subscription"] | -1LL;
    int handle = -1;
    for (auto &kv : s.subs)
    {
        if (kv.second.serverId == serverId)
        {
            handle = kv.first;
            break;
        }
    }
    if (handle < 0)
    {
        return;
    }

    JsonVariant result = doc["params"]["result"];
    uint64_t slot = result["context"]["slot"] | 0ULL;
    JsonVariant value = result["value"];

    if (method == "accountNotification" && s.onAccount)
    {
        std::vector<uint8_t> data;
        const char *b64 = value["data"][0];
        if (b64) infratic_detail::fromBase64(b64, data);
        s.onAccount(handle, data, value["lamports"] | 0ULL, slot);
    }
    else if (method == "programNotification" && s.onProgram)
    {
        std::vector<uint8_t> data;
        const char *b64 = value["account"]["data"][0];
        if (b64) infratic_detail::fromBase64(b64, data);
        s.onProgram(handle, value["pubkey"] | "", data, slot);
    }
    else if (method == "logsNotification" && s.onLogs)
    {
        std::vector<String> logs;
        for (JsonVariant l : value["logs"].as<JsonArray>()) logs.push_back(l.as<String>());
        s.onLogs(handle, value["signature"] | "", logs, !value["err"].isNull(), slot);
    }
    else if (method == "signatureNotification")
    {
        String sig = s.subs[handle].extra;
        s.subs.erase(handle); // the server removes signature subscriptions after one notification
        if (s.onSignature) s.onSignature(handle, sig, !value["err"].isNull());
    }
}

bool Infratic::wsProcessIncoming(uint32_t waitMs, int waitForId, int64_t *outResult)
{
    InfraticWsState &s = ws();
    unsigned long start = millis();
    bool gotResult = false;

    do
    {
        if (!s.client || !s.client->connected())
        {
            if (s.connected) _logErr.println("⚠️  WebSocket disconnected");
            s.connected = false;
            return false;
        }

        while (s.client->available() > 0)
        {
            uint8_t chunk[512];
            int n = s.client->read(chunk, sizeof(chunk));
            if (n <= 0) break;
            s.rx.insert(s.rx.end(), chunk, chunk + n);
            s.lastActivity = millis();
        }

        // parse every complete frame in the buffer
        while (s.rx.size() >= 2)
        {
            uint8_t b0 = s.rx[0], b1 = s.rx[1];
            bool fin = b0 & 0x80;
            uint8_t opcode = b0 & 0x0F;
            bool masked = b1 & 0x80;
            uint64_t len = b1 & 0x7F;
            size_t pos = 2;
            if (len == 126)
            {
                if (s.rx.size() < 4) break;
                len = ((uint64_t)s.rx[2] << 8) | s.rx[3];
                pos = 4;
            }
            else if (len == 127)
            {
                if (s.rx.size() < 10) break;
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | s.rx[2 + i];
                pos = 10;
            }
            if (len > s.maxMessage)
            {
                _logErr.printf("❌ WebSocket message too large (%llu bytes), closing\n", (unsigned long long)len);
                s.close();
                return false;
            }
            uint8_t mask[4] = {0, 0, 0, 0};
            if (masked)
            {
                if (s.rx.size() < pos + 4) break;
                memcpy(mask, s.rx.data() + pos, 4);
                pos += 4;
            }
            if (s.rx.size() < pos + len) break;

            std::vector<uint8_t> payload(s.rx.begin() + pos, s.rx.begin() + pos + len);
            if (masked)
                for (size_t i = 0; i < payload.size(); i++) payload[i] ^= mask[i & 3];
            s.rx.erase(s.rx.begin(), s.rx.begin() + pos + len);

            if (opcode == 0x9) // ping -> pong with the same payload
            {
                s.sendFrame(0xA, payload.data(), payload.size());
            }
            else if (opcode == 0x8) // close
            {
                s.close();
                return gotResult;
            }
            else if (opcode == 0x1 || opcode == 0x0)
            {
                if (opcode == 0x1)
                {
                    s.fragment.clear();
                    s.inFragment = true;
                }
                if (!s.inFragment) continue;
                s.fragment.append((const char *)payload.data(), payload.size());
                if (s.fragment.size() > s.maxMessage)
                {
                    _logErr.println("❌ WebSocket message too large, closing");
                    s.close();
                    return false;
                }
                if (fin)
                {
                    String msg(s.fragment.c_str());
                    s.fragment.clear();
                    s.inFragment = false;
                    wsHandleMessage(msg, waitForId, outResult, &gotResult);
                }
            }
        }

        if (gotResult) return true;
        if (waitMs == 0) break;
        delay(10);
    } while (millis() - start < waitMs);

    return gotResult;
}

int Infratic::wsSubscribe(const String &method, const String &params, int kind, const String &extra)
{
    InfraticWsState &s = ws();
    if (!s.connected && !wsConnect())
    {
        return -1;
    }

    int id = s.nextRequestId++;
    String req = String(R"({"jsonrpc":"2.0","id":)") + String(id) + R"(,"method":")" + method + R"(","params":)" + params + "}";
    int64_t serverId = -1;
    if (!wsSendText(req) || !wsProcessIncoming(WS_TIMEOUT_MS, id, &serverId) || serverId < 0)
    {
        _logErr.println("❌ " + method + " failed");
        return -1;
    }

    int handle = s.nextHandle++;
    s.subs[handle] = InfraticWsState::Sub{kind, method, params, extra, serverId};
    _logInfo.printf("📡 %s -> handle %d\n", method.c_str(), handle);
    return handle;
}

int Infratic::accountSubscribe(const String &accountBase58, const String &commitment)
{
    String params = "[\"" + accountBase58 + R"(",{"encoding":"base64","commitment":")" + commitment + "\"}]";
    return wsSubscribe("accountSubscribe", params, SUB_ACCOUNT, "");
}

int Infratic::programSubscribe(const String &programIdBase58, const std::vector<AccountFilter> &filters,
                               const String &commitment)
{
    String params = "[\"" + programIdBase58 + R"(",{"encoding":"base64","commitment":")" + commitment + "\"";
    if (!filters.empty())
    {
        params += ",\"filters\":" + infratic_detail::filtersJson(filters);
    }
    params += "}]";
    return wsSubscribe("programSubscribe", params, SUB_PROGRAM, "");
}

int Infratic::logsSubscribe(const String &mentionsBase58, const String &commitment)
{
    String filter = mentionsBase58 == "all" ? String("\"all\"") : "{\"mentions\":[\"" + mentionsBase58 + "\"]}";
    String params = "[" + filter + R"(,{"commitment":")" + commitment + "\"}]";
    return wsSubscribe("logsSubscribe", params, SUB_LOGS, "");
}

int Infratic::signatureSubscribe(const String &signature, const String &commitment)
{
    String params = "[\"" + signature + R"(",{"commitment":")" + commitment + "\"}]";
    return wsSubscribe("signatureSubscribe", params, SUB_SIGNATURE, signature);
}

bool Infratic::unsubscribe(int handle)
{
    InfraticWsState &s = ws();
    auto it = s.subs.find(handle);
    if (it == s.subs.end())
    {
        return false;
    }
    int64_t serverId = it->second.serverId;
    int kind = it->second.kind;
    s.subs.erase(it);
    if (!s.connected)
    {
        return true;
    }

    int id = s.nextRequestId++;
    String req = String(R"({"jsonrpc":"2.0","id":)") + String(id) + R"(,"method":")" + UNSUBSCRIBE_METHODS[kind] +
                 R"(","params":[)" + String((long long)serverId) + "]}";
    int64_t ok = 0;
    return wsSendText(req) && wsProcessIncoming(WS_TIMEOUT_MS, id, &ok) && ok == 1;
}

void Infratic::wsLoop()
{
    InfraticWsState &s = ws();

    if (!s.connected)
    {
        if (!s.autoReconnect || s.subs.empty() || millis() - s.lastReconnectTry < WS_RECONNECT_INTERVAL_MS)
        {
            return;
        }
        s.lastReconnectTry = millis();
        _logInfo.println("🔄 WebSocket reconnecting...");
        if (!wsConnect())
        {
            return;
        }
        // re-subscribe, handles stay the same
        for (auto &kv : s.subs)
        {
            int id = s.nextRequestId++;
            String req = String(R"({"jsonrpc":"2.0","id":)") + String(id) + R"(,"method":")" + kv.second.method +
                         R"(","params":)" + kv.second.params + "}";
            int64_t serverId = -1;
            if (wsSendText(req) && wsProcessIncoming(WS_TIMEOUT_MS, id, &serverId) && serverId >= 0)
            {
                kv.second.serverId = serverId;
            }
        }
        return;
    }

    wsProcessIncoming(0, 0, nullptr);

    if (s.connected && millis() - s.lastActivity > WS_PING_INTERVAL_MS)
    {
        s.sendFrame(0x9, nullptr, 0);
        s.lastActivity = millis();
    }
}
