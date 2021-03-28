//
// Created by denn on 2019-01-29.
//

#include "ed25519.hpp"
#include <iostream>
#include "gtest/gtest.h"

#define ALL_TESTS 1

#define GOUT(STREAM) \
    do \
    { \
        std::cout << "[MESSAGE   ] "<< STREAM << std::endl; \
    } while (false);

auto error_handler = [](const std::error_code code){
    GOUT("Test error: " + ed25519::StringFormat("code: %i, message: %s", code.value(), + code.message().c_str()));
};


TEST(TEST_API, ed25519_api_initial ){
    std::cout << "ed25519_api_initial" << std::endl;
}

#if ALL_TESTS

TEST(TEST_API, ed25519_api ){

  ed25519::Seed seed;

  std::string ssed = ed25519::base58::encode(seed).c_str();

  GOUT("Seed   : ");
  GOUT(ssed.c_str());

  ed25519::Seed data2;

  EXPECT_EQ(true,ed25519::base58::decode(ssed, data2));
  GOUT(ssed.c_str());

  std::string wrang_ssed;
  EXPECT_EQ(false,ed25519::base58::decode(wrang_ssed,data2,error_handler));

}

TEST(TEST_API, keys_seed ) {

  ed25519::Seed seed;
  ed25519::Seed secret("some secret prase");

  GOUT("Random seed   : ");
  GOUT(seed.encode());

  GOUT("Secret seed   : ");
  GOUT(secret.encode());


  ed25519::Seed from_secret(seed);

  GOUT("From seed   : ");
  GOUT(from_secret.encode());

  EXPECT_TRUE(from_secret == seed);

  GOUT("From secret seed  : ");
  from_secret.decode(secret.encode());

  GOUT(from_secret.encode());

  EXPECT_TRUE(from_secret == secret);
}

TEST(TEST_API, pair_keys) {

  auto pair = ed25519::keys::Pair::Random();

  GOUT("Private random: " +  pair->get_private_key().encode());
  GOUT("Public  random: " + pair->get_public_key().encode());

}

TEST(TEST_API, pair_key_with_secret ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");

  GOUT("Private secret: " + secret_pair->get_private_key().encode());
  GOUT("Public  secret: " + secret_pair->get_public_key().encode());

  EXPECT_TRUE(!ed25519::keys::Pair::WithSecret("", error_handler));

}

TEST(TEST_API, pair_key_from_private ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");

  if (auto pair = ed25519::keys::Pair::FromPrivateKey(secret_pair->get_private_key().encode(), error_handler)){
    GOUT("Private from private: " + pair->get_private_key().encode());
    GOUT("Public  from private: " + pair->get_public_key().encode());

    EXPECT_TRUE(pair->get_public_key() == secret_pair->get_public_key());

  } else {
    EXPECT_TRUE(false);
  }
}

TEST(TEST_API, validate_public ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
  auto pk = ed25519::keys::Public();

  EXPECT_TRUE(secret_pair->get_public_key().validate());
  GOUT("Validate public from secret: " + secret_pair->get_public_key().encode());

  EXPECT_TRUE(pk.validate());
  GOUT("Validate public from empty: " + pk.encode());
}

TEST(TEST_API, validate_private ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
  auto pvk = ed25519::keys::Private();

  EXPECT_TRUE(secret_pair->get_private_key().validate());
  GOUT("Validate private from secret: " + secret_pair->get_private_key().encode());

  EXPECT_TRUE(pvk.validate());
  GOUT("Validate private from empty: " + pvk.encode());
}

TEST(TEST_API, validate_base58 ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
  auto pvk = std::string("....");

  EXPECT_TRUE(ed25519::base58::validate(secret_pair->get_private_key().encode()));
  GOUT("Validate base58 private from secret: " + secret_pair->get_private_key().encode());

  EXPECT_TRUE(!ed25519::base58::validate(pvk));
  GOUT("Validate private from empty: " + pvk);

  EXPECT_TRUE(!ed25519::keys::Private::validate(pvk));
  GOUT("Validate private from empty: " + pvk);

}

TEST(TEST_API, signature ) {
  auto secret_pair = ed25519::keys::Pair::WithSecret("some secret phrase");
  auto secret_pair2 = ed25519::keys::Pair::WithSecret("some secret other phrase");

  std::string message = "some message or token string";

  auto signature = secret_pair->sign(message);

  GOUT("Signature: " + signature->encode());

  std::optional<ed25519::keys::Public> pp = ed25519::keys::Public::Decode(secret_pair->get_public_key().encode());

  GOUT("Signature 1 ppp : " + pp->encode());

  auto ppp = secret_pair2->get_public_key();
  //
  // This is not permitted
  //
  // ppp.decode(secret_pair2->get_public_key().encode());

  GOUT("Signature 2 ppp : " + ppp.encode());

  EXPECT_TRUE(signature->verify(message, secret_pair->get_public_key()));
  EXPECT_TRUE(!signature->verify(message,secret_pair2->get_public_key()));

  auto signature_test = *signature;

  GOUT("Signature copy: -> " + signature_test.encode() + " <- " + signature->encode());

  if (auto signature = ed25519::Signature::Decode("", error_handler)){
    ///
  }
  else {
    GOUT("Wrong siganture deccoding tested");

    auto signature_test_copy = ed25519::Signature::Decode(signature_test.encode(), error_handler);

    EXPECT_TRUE(signature_test_copy == signature_test);
    EXPECT_TRUE(signature_test_copy != *secret_pair2->sign(message));

  }
}

#endif