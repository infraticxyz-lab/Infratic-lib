#pragma once
#include <Arduino.h>
#include "WiFiClientSecure.h"
typedef enum { WL_IDLE_STATUS = 0, WL_CONNECTED = 3, WL_DISCONNECTED = 6 } wl_status_t;
struct IPAddress { String toString() const { return String("127.0.0.1"); } operator String() const { return toString(); } };
inline String operator+(const String &a, const IPAddress &) { return a + String("127.0.0.1"); }

// host test hooks: a fast connect (channel + bssid given) succeeds only if it matches the "real" AP
struct MockWifi { int32_t apChannel = 6; uint8_t apBssid[6] = {1, 2, 3, 4, 5, 6}; bool reachable = true;
                  int fastBegins = 0, scanBegins = 0, mode = 0; bool connected = false; };
extern MockWifi g_wifi;

class WiFiClass {
public:
    wl_status_t begin(const char *, const char *, int32_t channel = 0, const uint8_t *bssid = nullptr, bool = true)
    {
        if (channel && bssid) { g_wifi.fastBegins++; g_wifi.connected = g_wifi.reachable && channel == g_wifi.apChannel && memcmp(bssid, g_wifi.apBssid, 6) == 0; }
        else { g_wifi.scanBegins++; g_wifi.connected = g_wifi.reachable; }
        return status();
    }
    wl_status_t status() { return g_wifi.connected ? WL_CONNECTED : WL_DISCONNECTED; }
    bool reconnect() { return true; }
    IPAddress localIP() { return IPAddress(); }
    int RSSI() { return -50; }
    void mode(int m) { g_wifi.mode = m; }
    void persistent(bool) {}
    void disconnect(bool = false) { g_wifi.connected = false; }
    int32_t channel() { return g_wifi.apChannel; }
    uint8_t *BSSID() { return g_wifi.apBssid; }
};
extern WiFiClass WiFi;
#define WIFI_OFF 0
#define WIFI_STA 1
