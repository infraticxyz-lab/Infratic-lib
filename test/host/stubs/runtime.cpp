#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <random>
#include <chrono>

HardwareSerial Serial;
WiFiClass WiFi;
bool g_serialQuiet = true;
MockSocket *g_mockSocket = nullptr;
int g_tlsInsecureCount = 0;
const char *g_tlsLastCA = nullptr;
std::map<std::string, std::map<std::string, std::vector<uint8_t>>> g_nvs;
std::function<MockHttpResponse(const std::string &, const std::string &)> g_httpHandler;

static unsigned long g_fakeMillis = 0;
unsigned long millis() { return g_fakeMillis += 1; }
void delay(unsigned long ms) { g_fakeMillis += ms; }
static std::mt19937 &rng() { static std::mt19937 r(12345); return r; }
uint32_t esp_random() { return rng()(); }
long random(long max) { return max <= 0 ? 0 : (long)(esp_random() % (uint32_t)max); }
long random(long min, long max) { return max <= min ? min : min + random(max - min); }
void randomSeed(unsigned long s) { rng().seed(s); }
