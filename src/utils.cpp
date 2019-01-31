//
// Created by denn on 2019-01-29.
//

#include <string>
#include <stdlib.h>
#include <stdarg.h>
#include "ed25519.hpp"

namespace ed25519 {
    const std::string StringFormat(const char* format, ...)
    {
        char buffer[1024] = {};
        va_list ap = {};

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        va_end(ap);

        return std::string(buffer);
    }
}