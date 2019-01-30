//
// Created by denn on 2019-01-30.
//


#define BOOST_TEST_MODULE digest_test

#include "ed25519.hpp"
#include <boost/test/included/unit_test.hpp>
#include <boost/chrono.hpp>
#include <boost/date_time.hpp>
#include <string>
#include <iostream>

using namespace ed25519;

BOOST_AUTO_TEST_CASE( digest_calculator ) {
    auto pair = keys::Pair::WithSecret("some secret phrase");

    auto digest = Digest([pair](auto &calculator) {

        BOOST_TEST_MESSAGE("Calculator ..." + StringFormat(" endian: %i", calculator.get_endian()));

        calculator.append(true);

        calculator.append(1);

        calculator.append((int)(1.12f * 100));

        std::string title = "123";

        calculator.append(title);

        std::vector<unsigned char> v(title.begin(), title.end());

        calculator.append(v);

        calculator.append(pair->get_public_key());

        calculator.append(pair->get_private_key());

    });

    BOOST_TEST_MESSAGE("Digest: " + digest.encode() );

    auto siganture = pair->sign(digest);

    BOOST_TEST_MESSAGE("Digest signature: " + siganture->encode() );

    BOOST_CHECK(siganture->verify(digest, pair->get_public_key()));
}