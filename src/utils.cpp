#include <cstdarg>
#include <cstdlib>
#include <string>

#include "ed25519.hpp"

namespace ed25519 {
std::string StringFormat(const char* format, ...) {
	char buffer[1024] = {};
	va_list ap = {};

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	return std::string(buffer);
}
}  // namespace ed25519
