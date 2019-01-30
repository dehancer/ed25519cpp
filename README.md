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
    $ git clone https://github.com/dnevera/ed25519cpp/
    $ cd ./ed25519cpp; mkdir build; cd ./build
    $ cmake ..; make -j4
    $ make test

## Tested
1. Centos7 (gcc v7.0)
1. Ubuntu 18.04
1. OSX 10.13, XCode10

## [API](https://github.com/dnevera/ed25519cpp/docs/html/namespaces.html)


## Examples
### Random seed generator

```c++
#include "ed25519.hpp"


ed25519::keys::Seed seed;
std::cout << "Seed base58 string: "<< seed.encode() << std::endl;

```