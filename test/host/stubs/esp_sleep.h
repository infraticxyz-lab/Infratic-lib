#pragma once
#include <stdint.h>
typedef enum { ESP_SLEEP_WAKEUP_UNDEFINED = 0, ESP_SLEEP_WAKEUP_TIMER = 4 } esp_sleep_wakeup_cause_t;
extern esp_sleep_wakeup_cause_t g_wakeCause;
extern uint64_t g_sleepUs;
extern int g_deepSleeps;
inline esp_sleep_wakeup_cause_t esp_sleep_get_wakeup_cause() { return g_wakeCause; }
inline int esp_sleep_enable_timer_wakeup(uint64_t us) { g_sleepUs = us; return 0; }
inline void esp_deep_sleep_start() { g_deepSleeps++; }
