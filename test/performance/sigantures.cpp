//
// Created by denn on 2019-01-30.
//

#include "ed25519.hpp"

#include "gtest/gtest.h"
#include <chrono>
#include <string>
#include <iostream>

using namespace ed25519;

TEST(TEST, siganture_rate){

  auto pair = keys::Pair::WithSecret("some secret phrase");
  std::string message;
  auto tests = {256, 4096, 60000};
  int nc = 1000;

  for(auto i: tests ) {
    for (size_t j = 0; j < i/size::seed; ++j) {
      message.append(Seed().encode());
    }

    auto signature = pair->sign(message);

    auto start = std::chrono::high_resolution_clock::now();

    int vc = 0;
    for (int k = 0; k < nc; ++k) {
      if (signature->verify(message, pair->get_public_key())) {
        vc ++;
      }
    }

    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = finish - start;

    auto diff = (float)elapsed.count()/1000;

    std::cout << "verified signatures[message size="<<i<<"b]: " << vc << " time: " << diff << "sec, " << float(vc)/diff << "sps" <<std::endl;

  }
}
