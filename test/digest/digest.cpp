//
// Created by denn on 2019-01-30.
//


#include "ed25519.hpp"
#include <string>
#include <iostream>

#include "gtest/gtest.h"
#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

using namespace ed25519;

auto error_handler = [](const std::error_code& code){
    GTEST_COUT << "Test error: " << ed25519::StringFormat("code: %i, message: %s", code.value(), + code.message().c_str()) << std::endl;
};

TEST(TEST, digest_calculator) {
  auto pair = keys::Pair::WithSecret("some secret phrase");

  auto digest = Digest([pair](auto &calculator) {

      GTEST_COUT <<"Calculator ..." + StringFormat(" endian: %i", calculator.get_endian()) << std::endl;

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

  GTEST_COUT << "Digest: " + digest.encode()  << std::endl;

  auto siganture = pair->sign(digest);

  GTEST_COUT << "Digest signature: " + siganture->encode()  << std::endl;

  auto digest_restored = Digest::Decode(digest.encode(), error_handler);

  std::optional<ed25519::keys::Public> pk = ed25519::keys::Public::Decode(pair->get_public_key().encode(), default_error_handler);

  GTEST_COUT << siganture->verify(*digest_restored, *pk) << std::endl;
}