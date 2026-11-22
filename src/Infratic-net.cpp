#include "infratic_internal.h"
#include "infratic_roots.h"

// ============================================================================
// HTTP / TLS
// ============================================================================

void Infratic::setRootCA(const char *pem)
{
    _rootCA = pem;
}

void Infratic::setTlsInsecure(bool insecure)
{
    _tlsInsecure = insecure;
}

void Infratic::configureTls(WiFiClientSecure &client)
{
    if (_tlsInsecure)
    {
        client.setInsecure();
    }
    else
    {
        client.setCACert(_rootCA ? _rootCA : INFRATIC_DEFAULT_ROOT_CA);
    }
}

void Infratic::setTimeout(uint32_t ms)
{
    _timeoutMs = ms;
}

void Infratic::addRpcEndpoint(const String &url)
{
    for (const String &u : _rpcUrls)
        if (u == url) return;
    _rpcUrls.push_back(url);
}

void Infratic::clearRpcEndpoints()
{
    _rpcUrls.resize(1);
    useRpc(0);
}

void Infratic::useRpc(size_t index)
{
    if (index == _activeRpc && _rpcUrl == _rpcUrls[index]) return;
    _activeRpc = index;
    _rpcUrl = _rpcUrls[index];
    _switchedAt = millis();
    _logInfo.println("🔀 RPC endpoint: " + _rpcUrl);
}

bool Infratic::httpPost(const String &body, String &outResponse, int &outCode)
{
    if (_activeRpc != 0 && millis() - _switchedAt >= _primaryRetryMs)
    {
        useRpc(0); // give the primary another chance
    }

    size_t n = _rpcUrls.size();
    for (size_t attempt = 0; attempt < n; attempt++)
    {
        bool ok = httpPostOnce(body, outResponse, outCode);
        bool endpointProblem = outCode < 0 || outCode == 429 || outCode >= 500;
        if (ok || !endpointProblem || n == 1) return ok;
        _logErr.printf("⚠️ RPC %s failed (%d), trying next endpoint\n", _rpcUrl.c_str(), outCode);
        useRpc((_activeRpc + 1) % n);
    }
    return false;
}

bool Infratic::httpPostOnce(const String &body, String &outResponse, int &outCode)
{
    WiFiClientSecure client;
    HTTPClient http;
    bool ok;
    if (_rpcUrl.startsWith("http://"))
    {
        ok = http.begin(_rpcUrl);
    }
    else
    {
        configureTls(client);
        ok = http.begin(client, _rpcUrl);
    }
    if (!ok)
    {
        outCode = -1;
        _logErr.println("❌ HTTP begin failed");
        return false;
    }

    http.setConnectTimeout(_timeoutMs);
    http.setTimeout(_timeoutMs > 65535 ? 65535 : (uint16_t)_timeoutMs);
    http.addHeader("Content-Type", "application/json");
    outCode = http.POST(body);
    outResponse = http.getString();
    http.end();
    if (outCode < 0)
    {
        _logErr.println("❌ HTTP failed (TLS or connection): " + HTTPClient::errorToString(outCode));
    }
    return outCode == 200;
}

bool Infratic::rpcCall(const String &method, const String &paramsJson, String &outResponse)
{
    String body = String(R"({"jsonrpc":"2.0","id":1,"method":")") + method + R"(","params":)" + paramsJson + "}";
    int code = 0;
    if (!httpPost(body, outResponse, code))
    {
        _logErr.printf("❌ %s: HTTP code %d\n", method.c_str(), code);
        return false;
    }

    StaticJsonDocument<32> filter;
    filter["error"] = true;
    DynamicJsonDocument err(512);
    if (deserializeJson(err, outResponse, DeserializationOption::Filter(filter)))
    {
        _logErr.println("❌ " + method + ": JSON parse error");
        return false;
    }
    if (!err["error"].isNull())
    {
        _logErr.println("❌ " + method + " RPC error: " + err["error"]["message"].as<String>());
        return false;
    }
    return true;
}
