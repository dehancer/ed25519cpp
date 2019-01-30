//
// Created by denn on 2019-01-29.
//

#define BOOST_TEST_MODULE api_test

#include "ed25519.hpp"
#include <boost/test/included/unit_test.hpp>


auto error_handler = [](const std::error_code code){
    BOOST_TEST_MESSAGE("Test error: " + ed25519::StringFormat("code: %i, message: %s", code.value(), + code.message().c_str()));
};

BOOST_AUTO_TEST_CASE( ed25519_api ){

        ed25519::keys::Seed seed;

        std::string ssed = ed25519::base58::encode(seed).c_str();

        BOOST_TEST_MESSAGE("Seed   : ");
        BOOST_TEST_MESSAGE(ssed.c_str());

        ed25519::keys::Seed data2;

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

BOOST_AUTO_TEST_CASE( validate_public ) {
    auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
    auto pk = ed25519::keys::Public();

    BOOST_CHECK(secret_pair->get_public_key().validate());
    BOOST_TEST_MESSAGE("Validate public from secret: " + secret_pair->get_public_key().encode());

    BOOST_CHECK(pk.validate());
    BOOST_TEST_MESSAGE("Validate public from empty: " + pk.encode());
}

BOOST_AUTO_TEST_CASE( validate_private ) {
        auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
        auto pvk = ed25519::keys::Private();

        BOOST_CHECK(secret_pair->get_private_key().validate());
        BOOST_TEST_MESSAGE("Validate private from secret: " + secret_pair->get_private_key().encode());

        BOOST_CHECK(pvk.validate());
        BOOST_TEST_MESSAGE("Validate private from empty: " + pvk.encode());
}

BOOST_AUTO_TEST_CASE( validate_base58 ) {
        auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
        auto pvk = std::string("....");

        BOOST_CHECK(ed25519::base58::validate(secret_pair->get_private_key().encode()));
        BOOST_TEST_MESSAGE("Validate base58 private from secret: " + secret_pair->get_private_key().encode());

        BOOST_CHECK(!ed25519::base58::validate(pvk));
        BOOST_TEST_MESSAGE("Validate private from empty: " + pvk);

        BOOST_CHECK(!ed25519::keys::Private::validate(pvk));
        BOOST_TEST_MESSAGE("Validate private from empty: " + pvk);

}