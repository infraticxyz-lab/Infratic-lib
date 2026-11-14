#pragma once
#include <Arduino.h>
#include "WiFiClientSecure.h"
typedef enum { WL_IDLE_STATUS = 0, WL_CONNECTED = 3, WL_DISCONNECTED = 6 } wl_status_t;
struct IPAddress { String toString() const { return String("127.0.0.1"); } operator String() const { return toString(); } };
inline String operator+(const String &a, const IPAddress &) { return a + String("127.0.0.1"); }
class WiFiClass {
public:
    void begin(const char *, const char *) {}
    wl_status_t status() { return WL_CONNECTED; }
    bool reconnect() { return true; }
    IPAddress localIP() { return IPAddress(); }
    int RSSI() { return -50; }
    void mode(int) {}
    void disconnect(bool = false) {}
};
extern WiFiClass WiFi;
#define WIFI_STA 1
