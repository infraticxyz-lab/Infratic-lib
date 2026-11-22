#include "infratic_internal.h"
#include <WiFi.h>
#include <Preferences.h>
#include <esp_sleep.h>
#include <esp_attr.h>

// ============================================================================
// LOW POWER
// ============================================================================

namespace
{
    // RTC memory keeps its value in deep sleep, it is cleared on power loss
    RTC_DATA_ATTR uint32_t rtcBootCount = 0;
    RTC_DATA_ATTR uint8_t rtcWifiValid = 0;
    RTC_DATA_ATTR int32_t rtcWifiChannel = 0;
    RTC_DATA_ATTR uint8_t rtcWifiBssid[6];
    RTC_DATA_ATTR uint32_t rtcWifiSsidHash = 0;
    bool lastFast = false;

    uint32_t fnv1a(const char *s)
    {
        uint32_t h = 2166136261u;
        while (s && *s) { h ^= (uint8_t)*s++; h *= 16777619u; }
        return h;
    }

    bool waitConnected(uint32_t timeoutMs)
    {
        unsigned long start = millis();
        while (WiFi.status() != WL_CONNECTED)
        {
            if (millis() - start >= timeoutMs) return false;
            delay(20);
        }
        return true;
    }
}

uint32_t LowPower::begin()
{
    return ++rtcBootCount;
}

uint32_t LowPower::bootCount()
{
    return rtcBootCount;
}

bool LowPower::wokeFromTimer()
{
    return esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER;
}

bool LowPower::connectWiFi(const char *ssid, const char *password, uint32_t timeoutMs)
{
    lastFast = false;
    unsigned long start = millis();
    WiFi.persistent(false); // don't write the credentials to flash on every wake
    WiFi.mode(WIFI_STA);

    uint32_t h = fnv1a(ssid);
    if (rtcWifiValid && rtcWifiSsidHash == h)
    {
        WiFi.begin(ssid, password, rtcWifiChannel, rtcWifiBssid, true);
        if (waitConnected(timeoutMs / 2))
        {
            lastFast = true;
            return true;
        }
        _logInfo.println("📶 Cached AP not reachable, scanning");
        rtcWifiValid = 0;
        WiFi.disconnect();
    }

    WiFi.begin(ssid, password);
    unsigned long used = millis() - start;
    if (!waitConnected(used < timeoutMs ? timeoutMs - used : 0))
    {
        _logErr.println("❌ WiFi connect failed");
        return false;
    }

    const uint8_t *b = WiFi.BSSID();
    if (b)
    {
        memcpy(rtcWifiBssid, b, 6);
        rtcWifiChannel = WiFi.channel();
        rtcWifiSsidHash = h;
        rtcWifiValid = 1;
    }
    return true;
}

bool LowPower::lastConnectWasFast()
{
    return lastFast;
}

void LowPower::forgetWiFi()
{
    rtcWifiValid = 0;
}

void LowPower::sleep(uint64_t seconds)
{
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    esp_sleep_enable_timer_wakeup(seconds * 1000000ULL);
    esp_deep_sleep_start();
}

// ============================================================================
// DATA QUEUE (NVS)
// ============================================================================

static const char *Q_NAMESPACE = "infratic_q";

DataQueue::DataQueue(const String &name, uint16_t capacity)
    : _name(name.substring(0, 9)), _capacity(capacity ? capacity : 1) {}

String DataQueue::slot(uint16_t i) const
{
    return _name + String((unsigned)i);
}

bool DataQueue::load(uint16_t &head, uint16_t &count)
{
    Preferences p;
    if (!p.begin(Q_NAMESPACE, true))
    {
        head = count = 0;
        return true; // namespace not created yet = empty
    }
    uint32_t v = p.getUInt((_name + "_s").c_str(), 0);
    p.end();
    head = v & 0xFFFF;
    count = v >> 16;
    if (head >= _capacity || count > _capacity) head = count = 0;
    return true;
}

bool DataQueue::store(uint16_t head, uint16_t count)
{
    Preferences p;
    if (!p.begin(Q_NAMESPACE, false)) return false;
    bool ok = p.putUInt((_name + "_s").c_str(), ((uint32_t)count << 16) | head) == 4;
    p.end();
    return ok;
}

bool DataQueue::push(const std::vector<uint8_t> &data)
{
    uint16_t head, count;
    load(head, count);
    if (count == _capacity)
    {
        head = (head + 1) % _capacity; // drop the oldest
        count--;
    }
    Preferences p;
    if (!p.begin(Q_NAMESPACE, false)) return false;
    uint16_t idx = (head + count) % _capacity;
    String key = slot(idx);
    p.remove(key.c_str()); // an empty entry has no key
    bool ok = data.empty() || p.putBytes(key.c_str(), data.data(), data.size()) == data.size();
    p.end();
    return ok && store(head, count + 1);
}

bool DataQueue::push(const String &text)
{
    std::vector<uint8_t> d((const uint8_t *)text.c_str(), (const uint8_t *)text.c_str() + text.length());
    return push(d);
}

uint16_t DataQueue::size()
{
    uint16_t head, count;
    load(head, count);
    return count;
}

bool DataQueue::peek(uint16_t index, std::vector<uint8_t> &out)
{
    uint16_t head, count;
    load(head, count);
    if (index >= count) return false;
    Preferences p;
    if (!p.begin(Q_NAMESPACE, true)) return false;
    String key = slot((head + index) % _capacity);
    size_t len = p.getBytesLength(key.c_str());
    out.assign(len, 0);
    bool ok = len == 0 || p.getBytes(key.c_str(), out.data(), len) == len;
    p.end();
    return ok;
}

bool DataQueue::pop(uint16_t n)
{
    uint16_t head, count;
    load(head, count);
    if (n > count) n = count;
    Preferences p;
    if (p.begin(Q_NAMESPACE, false))
    {
        for (uint16_t i = 0; i < n; i++) p.remove(slot((head + i) % _capacity).c_str());
        p.end();
    }
    return store((head + n) % _capacity, count - n);
}

void DataQueue::clear()
{
    pop(size());
    store(0, 0);
}
