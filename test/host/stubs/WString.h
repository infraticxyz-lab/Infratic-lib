// Minimal Arduino String for host tests
#pragma once
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>

class String {
public:
    std::string s;
    String() {}
    String(const char *c) : s(c ? c : "") {}
    String(const char *c, size_t n) : s(c, n) {}
    String(const std::string &x) : s(x) {}
    String(char c) : s(1, c) {}
    String(int v) : s(std::to_string(v)) {}
    String(unsigned int v) : s(std::to_string(v)) {}
    String(long v) : s(std::to_string(v)) {}
    String(unsigned long v) : s(std::to_string(v)) {}
    String(long long v) : s(std::to_string(v)) {}
    String(unsigned long long v) : s(std::to_string(v)) {}
    String(float v, unsigned d = 2) { char b[64]; snprintf(b, sizeof b, "%.*f", d, v); s = b; }
    String(double v, unsigned d = 2) { char b[64]; snprintf(b, sizeof b, "%.*f", d, v); s = b; }
    String(int v, int base) { char b[70]; if (base == 16) snprintf(b, sizeof b, "%x", v); else snprintf(b, sizeof b, "%d", v); s = b; }
    String(unsigned int v, int base) { char b[70]; if (base == 16) snprintf(b, sizeof b, "%x", v); else snprintf(b, sizeof b, "%u", v); s = b; }
    String(unsigned char v, int base = 10) { char b[8]; if (base == 16) snprintf(b, sizeof b, "%x", v); else snprintf(b, sizeof b, "%u", v); s = b; }

    const char *c_str() const { return s.c_str(); }
    unsigned int length() const { return (unsigned)s.size(); }
    bool isEmpty() const { return s.empty(); }
    bool reserve(unsigned n) { s.reserve(n); return true; }
    char *begin() { return &s[0]; }
    char *end() { return &s[0] + s.size(); }
    const char *begin() const { return s.data(); }
    const char *end() const { return s.data() + s.size(); }
    char charAt(unsigned i) const { return i < s.size() ? s[i] : 0; }
    char operator[](unsigned i) const { return charAt(i); }
    String substring(unsigned from) const { return from >= s.size() ? String() : String(s.substr(from)); }
    String substring(unsigned from, unsigned to) const {
        if (from > to) std::swap(from, to);
        if (from >= s.size()) return String();
        if (to > s.size()) to = s.size();
        return String(s.substr(from, to - from));
    }
    int indexOf(const String &x, unsigned from = 0) const { auto p = s.find(x.s, from); return p == std::string::npos ? -1 : (int)p; }
    int indexOf(char c, unsigned from = 0) const { auto p = s.find(c, from); return p == std::string::npos ? -1 : (int)p; }
    bool startsWith(const String &x) const { return s.rfind(x.s, 0) == 0; }
    bool endsWith(const String &x) const { return s.size() >= x.s.size() && s.compare(s.size() - x.s.size(), x.s.size(), x.s) == 0; }
    long toInt() const { return strtol(s.c_str(), nullptr, 10); }
    float toFloat() const { return strtof(s.c_str(), nullptr); }
    bool concat(const char *c) { s += c; return true; }
    bool concat(const char *c, unsigned n) { s.append(c, n); return true; }
    bool concat(char c) { s += c; return true; }
    void toCharArray(char *buf, unsigned n) const { if (!n) return; strncpy(buf, s.c_str(), n - 1); buf[n - 1] = 0; }
    void trim() { size_t a = s.find_first_not_of(" \t\r\n"); size_t b = s.find_last_not_of(" \t\r\n"); s = a == std::string::npos ? "" : s.substr(a, b - a + 1); }

    String &operator+=(const String &o) { s += o.s; return *this; }
    String &operator+=(const char *o) { s += o; return *this; }
    String &operator+=(char c) { s += c; return *this; }
    template <typename T> String &operator+=(T v) { s += String(v).s; return *this; }
    bool operator==(const String &o) const { return s == o.s; }
    bool operator!=(const String &o) const { return s != o.s; }
    bool operator==(const char *o) const { return s == o; }
    bool operator!=(const char *o) const { return s != o; }
    bool operator<(const String &o) const { return s < o.s; }
};

inline String operator+(const String &a, const String &b) { return String(a.s + b.s); }
inline String operator+(const String &a, const char *b) { return String(a.s + b); }
inline String operator+(const char *a, const String &b) { return String(std::string(a) + b.s); }
inline String operator+(const String &a, char b) { return String(a.s + b); }
template <typename T> inline String operator+(const String &a, T v) { return String(a.s + String(v).s); }
