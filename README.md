
# ed25519cpp - Ed25519 C++17 implementation

This is a portable implementation of [Ed25519](http://ed25519.cr.yp.to/) based
on the SUPERCOP "ref10" implementation. The ed25519cpp wraps c-based implementing modern c++17 dialect. Additionally there is some extension which make easier the work with base58-encoded strings and pair of keys based on ed25519.

## Home pages explains ed25519
1. https://ed25519.cr.yp.to/
1. https://en.wikipedia.org/wiki/EdDSA 

## Requirements
1. c++17
1. cmake
1. boost unitest installed includes (>=1.66, exclude 1.68!)

## Build
    git clone https://github.com/dnevera/ed25519cpp/
    cd ./ed25519cpp; mkdir build; cd ./build
    git clone https://github.com/dnevera/base64cpp
    cd ./base64cpp; mkdir build; cd ./build
    
    # mac os M1 universal bin
    cmake -DCMAKE_OSX_ARCHITECTURES=arm64;x86_64 ..
    cmake --build . && cmake --build . --target=install 

    # or mac os Intel
    cmake -DCMAKE_OSX_ARCHITECTURES=x86_64 ..
    cmake --build . && cmake --build . --target=install 
    ctest -C Debug -V

## Build ios
    # https://blog.tomtasche.at/2019/05/how-to-include-cmake-project-in-xcode.html

    git clone https://github.com/dehancer/ios-cmake
    cmake -G Xcode \
    -DCMAKE_TOOLCHAIN_FILE=~/Develop/Dehancer/Dehancer-Plugins/ios-cmake/ios.toolchain.cmake\
    -DENABLE_BITCODE=ON
    -DPLATFORM=OS64COMBINED -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX=~/Develop/local/ios/dehancer
    cmake --build . --config Release && cmake --install . --config Release

## Tested
1. Centos7 (gcc v7.0)
1. Ubuntu 18.04
1. OSX 10.13, XCode10

## [API](https://htmlpreview.github.io/?https://github.com/dnevera/ed25519cpp/blob/master/docs/html/namespaces.html)


## Examples
### Random seed generator

```c++
#include "ed25519.hpp"


ed25519::Seed seed;
std::cout << "Seed base58 string: "<< seed.encode() << std::endl;

```

### Create random keys pair

```c++
#include "ed25519.hpp"

if (auto pair = ed25519::keys::Pair::Random()){
    std::cout << "ed25519 random keys pair: "<< pair->get_public_key.encode() << "/" <<  pair->get_private_key().encode() << std::endl;
}


```

### Create keys pair from private key

```c++
#include "ed25519.hpp"

auto error_handler = [](const std::error_code code){
    BOOST_TEST_MESSAGE("Test error: " + ed25519::StringFormat("code: %i, message: %s", code.value(), + code.message().c_str()));
};

if (auto pair = ed25519::keys::Pair::FromPrivateKey(secret_pair->get_private_key().encode(), error_handler)){
    std::cout << "ed25519 random keys pair: "<< pair->get_public_key.encode() << "/" <<  pair->get_private_key().encode() << std::endl;
}
else{
    // handling error
}


```

### Create keys pair with secret phrase

```c++
#include "ed25519.hpp"


if (auto pair = ed25519::keys::Pair::WithSecret("some secret phrase", error_handler)){
    std::cout << "ed25519 random keys pair: "<< pair->get_public_key.encode() << "/" <<  pair->get_private_key().encode() << std::endl;
}
else{
    // handling error
}


```

### Sign message

```c++
#include "ed25519.hpp"

// create pair
auto pair           = ed25519::keys::Pair::WithSecret("some secret phrase");

// some message 
std::string message = "some message or token string";

// sign message return uniq_ptr siganture
auto signature      = pair->sign(message);

if (signature->verify(message, pair->get_public_key())) {
   // handle verified
}

//
// It is not available to create empty signature:
// auto signature = ed25519::keys::Pair::Siganture()
// only copy operations or restore from base58-encoded string 
//
auto another_signature = ed25519::Signature::Decode(signature->encode());

//
// Handle errors when restoration
//

if (auto signature = ed25519::Signature::Decode("...some wrong encoded string ...", error_handler)){
    // handle verified
}
else {
    // handle error
}

```

### Create digest hash from variant types 

```c++

auto digest = Digest([pair](auto &calculator) {

        //
        // set big endian 
        // little endian is default
        //
        
        calculator.set_endian(Digest::Calculator::endian::big);
        
        std::cout << "Calculator endian: " << calculator.get_endian() << std::endl;

        calculator.append(true);

        calculator.append(1);

        calculator.append((int)(1.12f * 100));

        std::string title = "123";

        calculator.append(title);

        std::vector<unsigned char> v(title.begin(), title.end());

        calculator.append(v);

    });

//
// Encode to base58
//
auto base58 = digest.encode();

//
// Sign digest
//
auto siganture = pair->sign(digest);

if (siganture->verify(digest, pair->get_public_key())) {
    //
    // handle verified digest
    //
}

//
// Restore from base58-encded string
//
auto digest_restored = Digest::Decode(digest.encode(), error_handler);

if (digest_restored && siganture->verify(*digest_restored, pair->get_public_key())) {
    //
    // handle restored and verified
    //     
}
```


### Windows
    # Requrements: 
    # Visual Studio, English Language Pack!
    # https://vcpkg.info/
    # GitBash

    cd C:
    git clone https://github.com/microsoft/vcpkg
    cd /c/vcpkg/
    ./bootstrap-vcpkg.sh
    /c/vcpkg/vcpkg integrate install
    /c/vcpkg/vcpkg install gtest

    # cmake integration
    -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake