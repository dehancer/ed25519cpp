//
// Created by denn on 2019-01-29.
//

#include "ed25519.hpp"
#include "btc_base58.hpp"
#include <memory>

namespace ed25519{

    namespace base58 {

        std::string encode(const std::vector<unsigned char> &data) {
            return EncodeBase58(data);
        }

        bool decode(const std::string &str, std::vector<unsigned char> &data) {
            return DecodeBase58Check(str, data);
        }

        bool validate(const std::string &str) {
            return Base58Check(str);
        }
    }

    error_category::error_category(const std::string &message):mess_(message) {}

    const char *error_category::name() const noexcept {
        return "base58 error";
    }

    std::string error_category::message(int ev) const {
        switch (ev) {
            case error::BADFORMAT:
                return mess_.empty() ? "base58 check string decode error" : mess_;
            case error::UNEXPECTED_SIZE:
                return mess_.empty() ? "unexpected data size " : mess_;
            case error::EMPTY:
                return mess_.empty() ? "data is empty" : mess_;
            default:
                return std::generic_category().message(ev);
        }
    }
}
