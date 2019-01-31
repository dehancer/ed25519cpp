//
// Created by denn on 2019-01-30.
//

#include "ed25519.h"
#include "ed25519.hpp"
#include "sha3.hpp"
#include "ed25519_ext.hpp"
#include <iostream>
#include <arpa/inet.h>

namespace ed25519 {

    struct CalculatorImpl: public Digest::Calculator{

        void append(const variant_t &value) override;
        void set_endian(endian) override ;
        endian get_endian() override ;

        CalculatorImpl(Digest *digest): ctx_({}), digest_(digest), endian_(little){

            if ( htonl(47) == 47 ) {
                endian_ = big;
            } else {
                endian_ = little;
            }

            sha3_Init256(&ctx_);
        }

        ~CalculatorImpl() {
            sha3_Finalize(&ctx_, digest_->data());
        }

    private:
        sha3_context ctx_;
        Digest *digest_;
        Digest::Calculator::endian endian_;

    };


    Digest::Digest(context handler):Data<size::digest>() {
        CalculatorImpl calculator(this);
        handler(calculator);
    }

    Digest::Digest():Data<size::digest>() {}

    std::optional<Digest> Digest::Decode(const std::string &base58, const ed25519::ErrorHandler &error) {
        auto s = Digest();
        if (s.decode(base58,error)){
            return std::make_optional(s);
        }
        return std::nullopt;
    }

    void CalculatorImpl::set_endian(Digest::Calculator::endian e) {
        endian_ = e;
    }

    Digest::Calculator::endian CalculatorImpl::get_endian() {
        return endian_;
    }

    void CalculatorImpl::append(const Digest::Calculator::variant_t &value) {

        std::visit([&](auto&& arg) {

            using T = std::decay_t<decltype(arg)>;

            if constexpr (std::is_same_v<T, bool>){
                unsigned char data = arg ? 1 : 0;
                sha3_Update((void *)&ctx_, &data, 1);
            }

            else if constexpr (std::is_same_v<T, unsigned char>){
                unsigned char data = arg;
                sha3_Update((void *)&ctx_, &data, 1);
            }

            else if constexpr (std::is_same_v<T, short int>){
                std::vector<unsigned char> message;
                if (endian_ == little)
                {
                    message.push_back(static_cast<unsigned char>(arg & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 8) & 0xff));
                }
                else
                {
                    message.push_back(static_cast<unsigned char>((arg >> 8) & 0xff));
                    message.push_back(static_cast<unsigned char>(arg & 0xff));
                }
                sha3_Update(&ctx_, message.data(), message.size());
            }

            else if constexpr (std::is_same_v<T, int>){
                std::vector<unsigned char> message;

                if (endian_ == little)
                {
                    message.push_back(static_cast<unsigned char>(arg & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 8) & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 16) & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 24) & 0xff));
                }
                else
                {
                    message.push_back(static_cast<unsigned char>((arg >> 24) & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 16) & 0xff));
                    message.push_back(static_cast<unsigned char>((arg >> 8) & 0xff));
                    message.push_back(static_cast<unsigned char>(arg & 0xff));
                }
                sha3_Update(&ctx_, message.data(), message.size());
            }

            else if constexpr (std::is_same_v<T, std::string>){
                sha3_Update(&ctx_, arg.data(), arg.size());
            }

            else if constexpr (std::is_same_v<T, std::vector<unsigned char>>){
                sha3_Update(&ctx_, arg.data(), arg.size());
            }

            else if constexpr (std::is_same_v<T, Data<size::hash>>){
                sha3_Update(&ctx_, arg.data(), arg.size());
            }

            else if constexpr (std::is_same_v<T, Data<size::double_hash>>){
                sha3_Update(&ctx_, arg.data(), arg.size());
            }


        }, value);

    }

}