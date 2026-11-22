// Minimal Arduino/ESP32 runtime for host tests
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <cctype>
#include "WString.h"

#ifndef ESP32
#define ESP32 1
#endif

unsigned long millis();
void delay(unsigned long ms);
uint32_t esp_random();
long random(long max);
long random(long min, long max);
void randomSeed(unsigned long);
inline void yield() {}

extern bool g_serialQuiet;
#define HEX 16
#define DEC 10

class HardwareSerial {
public:
    void begin(unsigned long) {}
    template <typename T> size_t print(const T &v) { return out(String(v)); }
    size_t print(const String &v) { return out(v); }
    size_t print(const char *v) { return out(String(v)); }
    template <typename T> size_t println(const T &v) { return out(String(v)) + out(String("\n")); }
    size_t println(const String &v) { return out(v) + out(String("\n")); }
    size_t println(const char *v) { return out(String(v)) + out(String("\n")); }
    size_t println() { return out(String("\n")); }
    size_t print(double v, int digits) { return out(String(v, (unsigned)digits)); }
    size_t println(double v, int digits) { return out(String(v, (unsigned)digits)) + out(String("\n")); }
    size_t print(int v, int base) { return out(String(v, base)); }
    size_t print(unsigned v, int base) { return out(String(v, base)); }
    size_t print(uint8_t v, int base) { return out(String(v, base)); }
    size_t println(int v, int base) { return out(String(v, base)) + out(String("\n")); }
    size_t println(uint8_t v, int base) { return out(String(v, base)) + out(String("\n")); }
    size_t printf(const char *fmt, ...) __attribute__((format(printf, 2, 3))) {
        char b[2048]; va_list a; va_start(a, fmt); int n = vsnprintf(b, sizeof b, fmt, a); va_end(a);
        out(String(b)); return n;
    }
    operator bool() const { return true; }
private:
    size_t out(const String &s) { if (!g_serialQuiet) fputs(s.c_str(), stdout); return s.length(); }
};
extern HardwareSerial Serial;
