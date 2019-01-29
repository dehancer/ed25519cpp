//
// Created by denn on 2019-01-29.
//

#define BOOST_TEST_MODULE api_test

#include "ed25519.hpp"
#include "ed25519.h"
#include <boost/test/included/unit_test.hpp>
#include <array>

typedef  std::array<unsigned char, ed25519::size::seed> seed_data;

auto error_handler = [](const std::error_code code){
    BOOST_TEST_MESSAGE("Test error: " + ed25519::StringFormat("code: %i, message: %s", code.value(), + code.message().c_str()));
};

BOOST_AUTO_TEST_CASE( ed25519_api ){

        seed_data seed;

        BOOST_CHECK_EQUAL(0,ed25519_create_seed(seed.data()));

        std::string ssed = ed25519::base58::encode(seed).c_str();

        BOOST_TEST_MESSAGE("Seed   : ");
        BOOST_TEST_MESSAGE(ssed.c_str());

        seed_data data2;

        BOOST_CHECK_EQUAL(true,ed25519::base58::decode(ssed, data2));
        BOOST_TEST_MESSAGE(ssed.c_str());

        std::string wrang_ssed;
        BOOST_CHECK_EQUAL(false,ed25519::base58::decode(wrang_ssed,data2,error_handler));

}

BOOST_AUTO_TEST_CASE( keys_seed ) {

        ed25519::keys::Seed seed;
        ed25519::keys::Seed secret("some secret prase");

        BOOST_TEST_MESSAGE("Random seed   : ");
        BOOST_TEST_MESSAGE(seed.encode());

        BOOST_TEST_MESSAGE("Secret seed   : ");
        BOOST_TEST_MESSAGE(secret.encode());


        ed25519::keys::Seed from_secret(seed);

        BOOST_TEST_MESSAGE("From seed   : ");
        BOOST_TEST_MESSAGE(from_secret.encode());

        BOOST_CHECK(from_secret == seed);

        BOOST_TEST_MESSAGE("From secret seed  : ");
        from_secret.decode(secret.encode());

        BOOST_TEST_MESSAGE(from_secret.encode());

        BOOST_CHECK(from_secret == secret);
}

BOOST_AUTO_TEST_CASE( pair_keys) {

        auto pair = ed25519::keys::Pair::Random();

        BOOST_TEST_MESSAGE("Private random: " +  pair->get_public_key().encode());
        BOOST_TEST_MESSAGE("Public  random: " + pair->get_public_key().encode());

}

BOOST_AUTO_TEST_CASE( pair_key_with_secret ) {
        auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");

        BOOST_TEST_MESSAGE("Private secret: " + secret_pair->get_private_key().encode());
        BOOST_TEST_MESSAGE("Public  secret: " + secret_pair->get_public_key().encode());

        BOOST_CHECK(!ed25519::keys::Pair::WithSecret("", error_handler));

}

BOOST_AUTO_TEST_CASE( pair_key_from_private ) {
        auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");

        if (auto pair = ed25519::keys::Pair::FromPrivateKey(secret_pair->get_private_key().encode(), error_handler)){
                BOOST_TEST_MESSAGE("Private from private: " + pair->get_private_key().encode());
                BOOST_TEST_MESSAGE("Public  from private: " + pair->get_public_key().encode());

                BOOST_CHECK(pair->get_public_key() == secret_pair->get_public_key());

        } else {
                BOOST_CHECK(false);
        }
}
