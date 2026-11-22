#pragma once
#include <Arduino.h>
#include "WiFiClient.h"
class WiFiClientSecure : public WiFiClient
{
public:
    void setInsecure() {}
    void setCACert(const char *) {}
};
