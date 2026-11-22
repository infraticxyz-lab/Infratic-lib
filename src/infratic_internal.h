// Internal helpers shared by the library source files. Not part of the public API.
#ifndef INFRATIC_INTERNAL_H
#define INFRATIC_INTERNAL_H

#include "Infratic-lib.h"
#include <stdarg.h>

namespace infratic_detail
{
    extern uint8_t logLevel;

    struct InfraticLog
    {
        uint8_t level;

        bool on() const { return logLevel >= level; }
        template <typename T>
        void print(const T &v) { if (on()) Serial.print(v); }
        template <typename T>
        void println(const T &v) { if (on()) Serial.println(v); }
        void println() { if (on()) Serial.println(); }
        void printf(const char *fmt, ...) __attribute__((format(printf, 2, 3)))
        {
            if (!on()) return;
            char buf[256];
            va_list args;
            va_start(args, fmt);
            vsnprintf(buf, sizeof(buf), fmt, args);
            va_end(args);
            Serial.print(buf);
        }
    };

    extern InfraticLog logErr;
    extern InfraticLog logInfo;

    String toBase64(const uint8_t *data, size_t len);
    bool fromBase64(const char *in, std::vector<uint8_t> &out);
    size_t jsonCapacity(const String &response);
}

#define _logErr infratic_detail::logErr
#define _logInfo infratic_detail::logInfo

#endif
