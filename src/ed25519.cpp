//
// Created by denn on 2019-01-29.
//

#include "ed25519.h"
#include "ed25519.hpp"
#include "sha3.hpp"
#include "ed25519_ext.hpp"
#include <iostream>

namespace ed25519 {

    namespace keys {

        Seed::Seed(const std::string &phrase) {
            fill(0);
            sha3_256((const unsigned char*) phrase.c_str(), phrase.length(), this->data());
        }

        Seed::Seed():seed_data() {
            fill(0);
            ed25519_create_seed(this->data());
        }

        Pair::Pair() {
            clean();
        }

        std::optional<Pair> Pair::Random() {

            Pair pair;

            Seed seed;
            ed25519_create_keypair(pair.publicKey_.data(), pair.privateKey_.data(), seed.data());
            return std::make_optional(pair);
        }

        std::optional<Pair> Pair::FromPrivateKey(const std::string &privateKey, const ErrorHandler &error) {

            if (privateKey.empty())
            {
                std::error_code ec(static_cast<int>(error::EMPTY),error_category("private keyis empty"));
                error(ec);
                return std::nullopt;
            }

            auto  pair = Pair();

            if (!pair.privateKey_.decode(privateKey, error))
            {
                return std::nullopt;
            }

            ed25519_restore_from_private_key(pair.publicKey_.data(), pair.privateKey_.data());

            return std::make_optional(pair);
        }

        std::optional<Pair> Pair::WithSecret(const std::string &phrase,
                                             const ed25519::ErrorHandler &error) {
            if (phrase.empty())
            {
                std::error_code ec(static_cast<int>(error::EMPTY),error_category("secret phrase is empty"));
                error(ec);
                return std::nullopt;
            }

            Pair pair;
            Seed seed(phrase);
            ed25519_create_keypair(pair.publicKey_.data(), pair.privateKey_.data(), seed.data());

            return std::make_optional(pair);
        }

        void  Pair::clean() {
            publicKey_.clean();
            privateKey_.clean();
        }

        bool Pair::validate() {
            return publicKey_.validate() && privateKey_.validate();
        }

        std::unique_ptr<Signature> Pair::sign(const std::vector<unsigned char>& message){

            auto signature = std::unique_ptr<Signature>{new Signature()};

            ed25519_sign(signature->data(),
                    message.data(), message.size(),
                    publicKey_.data(),
                    privateKey_.data());

            return signature;
        }

        std::unique_ptr<Signature> Pair::sign(const std::string &message){
            std::vector<unsigned char> v(message.begin(), message.end());
            return std::move(sign(v));
        }

        std::unique_ptr<Signature> Pair::sign(const Digest& digest){

            auto signature = std::unique_ptr<Signature>{new Signature()};

            ed25519_sign(signature->data(),
                         digest.data(), digest.size(),
                         publicKey_.data(),
                         privateKey_.data());

            return signature;
        }
    }

    std::optional<Signature> Signature::Decode(const std::string &base58, const ErrorHandler &error){
        auto s = Signature();
        if (s.decode(base58,error)){
            return std::make_optional(s);
        }
        return std::nullopt;
    }

    bool Signature::verify(const ed25519::Digest &digest, const ed25519::keys::Public &key) const {
        return ed25519_verify(data(), digest.data(), digest.size(), key.data()) == 1;
    }

    bool Signature::verify(const std::string &message, const ed25519::keys::Public &key) const {
        std::vector<unsigned char> v(message.begin(), message.end());
        return verify(v,key);
    }

    bool Signature::verify(const std::vector<unsigned char> &message, const ed25519::keys::Public &key) const {
        return ed25519_verify(data(), message.data(), message.size(), key.data()) == 1;
    }

}