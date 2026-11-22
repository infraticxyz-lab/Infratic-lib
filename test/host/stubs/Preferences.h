// In-memory Preferences (NVS) for host tests.
#pragma once
#include <Arduino.h>
#include <map>
#include <string>
#include <vector>

extern std::map<std::string, std::map<std::string, std::vector<uint8_t>>> g_nvs;

class Preferences
{
public:
    bool begin(const char *ns, bool readOnly = false) { _ns = ns; _ro = readOnly; return true; }
    void end() {}
    size_t putBytes(const char *key, const void *v, size_t len)
    {
        if (_ro) return 0;
        g_nvs[_ns][key].assign((const uint8_t *)v, (const uint8_t *)v + len);
        return len;
    }
    size_t getBytesLength(const char *key) { auto &m = g_nvs[_ns]; auto it = m.find(key); return it == m.end() ? 0 : it->second.size(); }
    size_t getBytes(const char *key, void *buf, size_t len)
    {
        auto &m = g_nvs[_ns]; auto it = m.find(key);
        if (it == m.end() || it->second.size() > len) return 0;
        memcpy(buf, it->second.data(), it->second.size());
        return it->second.size();
    }
    size_t putUChar(const char *key, uint8_t v) { return putBytes(key, &v, 1); }
    uint8_t getUChar(const char *key, uint8_t def = 0) { uint8_t v = def; return getBytes(key, &v, 1) == 1 ? v : def; }
    size_t putUInt(const char *key, uint32_t v) { return putBytes(key, &v, 4); }
    uint32_t getUInt(const char *key, uint32_t def = 0) { uint32_t v = def; return getBytes(key, &v, 4) == 4 ? v : def; }
    size_t putString(const char *key, const String &v) { return putBytes(key, v.c_str(), v.length()); }
    String getString(const char *key, const String &def = String())
    {
        auto &m = g_nvs[_ns]; auto it = m.find(key);
        return it == m.end() ? def : String((const char *)it->second.data(), it->second.size());
    }
    bool remove(const char *key) { if (_ro) return false; return g_nvs[_ns].erase(key) > 0; }
    bool clear() { if (_ro) return false; g_nvs[_ns].clear(); return true; }
    bool isKey(const char *key) { return g_nvs[_ns].count(key) > 0; }

private:
    std::string _ns;
    bool _ro = false;
};
