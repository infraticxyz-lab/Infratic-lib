// Mock TCP client: everything goes to g_mockSocket so tests can play the server side.
#pragma once
#include <Arduino.h>
#include <string>

struct MockSocket
{
    virtual ~MockSocket() {}
    virtual bool connect(const std::string &host, uint16_t port) = 0;
    virtual size_t write(const uint8_t *buf, size_t len) = 0;
    virtual int available() = 0;
    virtual int read(uint8_t *buf, size_t len) = 0;
    virtual bool connected() = 0;
    virtual void stop() = 0;
};
extern MockSocket *g_mockSocket;

class WiFiClient
{
public:
    virtual ~WiFiClient() {}
    virtual int connect(const char *host, uint16_t port) { return g_mockSocket && g_mockSocket->connect(host, port); }
    virtual size_t write(const uint8_t *buf, size_t len) { return g_mockSocket ? g_mockSocket->write(buf, len) : 0; }
    virtual int available() { return g_mockSocket ? g_mockSocket->available() : 0; }
    virtual int read(uint8_t *buf, size_t len) { return g_mockSocket ? g_mockSocket->read(buf, len) : -1; }
    virtual uint8_t connected() { return g_mockSocket && g_mockSocket->connected(); }
    virtual void stop() { if (g_mockSocket) g_mockSocket->stop(); }
    void setTimeout(uint32_t) {}
};
