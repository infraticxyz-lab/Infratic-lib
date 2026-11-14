// Mock HTTPClient: requests are routed to g_httpHandler so tests can
// inspect the exact JSON-RPC bodies the library sends.
#pragma once
#include <Arduino.h>
#include <functional>
#include <string>
#include "WiFiClientSecure.h"

struct MockHttpResponse { int code; std::string body; };
extern std::function<MockHttpResponse(const std::string &url, const std::string &body)> g_httpHandler;

class HTTPClient {
public:
    bool begin(WiFiClientSecure &, const String &url) { _url = url.s; return true; }
    bool begin(const String &url) { _url = url.s; return true; }
    void addHeader(const String &, const String &) {}
    void setTimeout(uint16_t) {}
    void setConnectTimeout(int32_t) {}
    int POST(const String &body) {
        MockHttpResponse r = g_httpHandler ? g_httpHandler(_url, body.s) : MockHttpResponse{-1, ""};
        _resp = r.body; return r.code;
    }
    String getString() { return String(_resp); }
    void end() {}
    static String errorToString(int c) { return String("mock error ") + String(c); }
private:
    std::string _url, _resp;
};
