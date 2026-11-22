#pragma once
#include <Arduino.h>
#include "WiFiClient.h"
extern int g_tlsInsecureCount;
extern const char *g_tlsLastCA;
class WiFiClientSecure : public WiFiClient
{
public:
    void setInsecure() { g_tlsInsecureCount++; g_tlsLastCA = nullptr; }
    void setCACert(const char *pem) { g_tlsLastCA = pem; }
};
