#pragma once
#include <Arduino.h>
class WiFiClientSecure {
public:
    void setInsecure() {}
    void setCACert(const char *) {}
    void setTimeout(uint32_t) {}
};
