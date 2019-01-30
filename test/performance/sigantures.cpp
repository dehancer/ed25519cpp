//
// Created by denn on 2019-01-30.
//


#define BOOST_TEST_MODULE signature_test

#include "ed25519.hpp"
#include <boost/test/included/unit_test.hpp>
#include <boost/chrono.hpp>
#include <boost/date_time.hpp>
#include <string>
#include <iostream>

using namespace ed25519;

BOOST_AUTO_TEST_CASE( siganture_rate ){

    auto pair = ed25519::keys::Pair::WithSecret("some secret phrase");
    std::string message;
    auto tests = {256, 4096, 60000};
    int nc = 1000;

    for(auto i: tests ) {
        for (int j = 0; j < i/size::seed; ++j) {
            message.append(keys::Seed().encode());
        }

        auto signature = pair->sign(message);

        auto tick = boost::posix_time::microsec_clock::local_time();

        int vc = 0;
        for (int k = 0; k < nc; ++k) {
            if (signature->verify(message, pair->get_public_key())) {
                vc ++;
            }
        }

        auto diff = (float)
                            (boost::posix_time::microsec_clock::local_time()
                             - tick).total_milliseconds()/1000.0f;

        std::cout << "verified signatures[message size="<<i<<"b]: " << vc << " time: " << diff << "sec, " << float(vc)/diff << "sps" <<std::endl;

    }
}
