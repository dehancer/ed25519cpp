# ed25519cpp

C++17 wrapper around the bundled Ed25519 C implementation, based on SUPERCOP
ref10. Provides key generation, signing and verification, Base58 serialization,
and SHA3-256 digests.

## Build and install

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
cmake --install build --parallel $(nproc)
```

Make sure to set proper `CMAKE_PREFIX_PATH` and `CMAKE_INSTALL_PREFIX`
to discover dependencies and install.

Use `-DBUILD_SHARED_LIBS=ON` for a shared library; the default is static.

`CMAKE_POSITION_INDEPENDENT_CODE` is set to `ON`.

## Windows build

We build in [Git Bash](https://gitforwindows.org) with `clang-cl`
and we add a magic string to CMake to select runtime.

Use Ninja as a make file generator.

Set `PATH` to include `clang-cl.exe` from VS.

```sh
export PATH="$PATH:/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin"
```

Add this to cmake configuration:

```
-G Ninja \
-DCMAKE_C_COMPILER=clang-cl \
-DCMAKE_CXX_COMPILER=clang-cl \
-DCMAKE_MSVC_RUNTIME_LIBRARY='MultiThreaded$<$<CONFIG:Debug>:Debug>'
```

## Usage in CMake

Installed package:

```cmake
find_package(ed25519cpp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE ed25519cpp::ed25519cpp)
```

## Usage with pkg-config

Disabled by default. Configure with `-DCREATE_PKG_CONFIG=ON` to generate and
install `ed25519cpp.pc`.

```sh
export PKG_CONFIG_PATH="$HOME/local-dehancer/lib/pkgconfig"
pkg-config --cflags --libs ed25519cpp
```

## Tests

Install GoogleTest, then:

```sh
cmake -B build -DBUILD_TESTING=ON
cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure
```

# Usage

## Sign and verify

```cpp
#include <ed25519.hpp>
#include <iostream>
#include <string>

int main() {
    auto pair = ed25519::keys::Pair::Random();
    if (!pair) {
        return 1;
    }

    const std::string message = "Hello, Ed25519";
    auto signature = pair->sign(message);
    if (!signature->verify(message, pair->get_public_key())) {
        return 1;
    }

    std::cout << "Public key: " << pair->get_public_key().encode() << '\n';
    std::cout << "Signature: " << signature->encode() << '\n';

    auto public_key = ed25519::keys::Public::Decode(pair->get_public_key().encode());
    auto restored_signature = ed25519::Signature::Decode(signature->encode());
    if (!public_key || !restored_signature) {
        return 1;
    }

    return restored_signature->verify(message, *public_key) ? 0 : 1;
}
```

`sign()` returns `std::unique_ptr<ed25519::Signature>`. Signing and verification
accept `std::string`, `std::vector<unsigned char>`, or `ed25519::Digest`.
Verification returns `bool`.

## Keys and serialization

| API | Result |
| --- | --- |
| `keys::Pair::Random()` | Random key pair |
| `keys::Pair::WithSecret(phrase)` | Deterministic key pair from a SHA3-256 seed derived from the phrase |
| `keys::Pair::FromPrivateKey(encoded)` | Key pair restored from its Base58 private key |
| `Seed()` | Random 32-byte seed |
| `Seed(phrase)` | SHA3-256 hash of the phrase |

These types live in the `ed25519` namespace. Pair factories and `Decode()`
methods return `std::optional`; check the result before accessing it.
`WithSecret()` hashes the phrase directly, without salt or password stretching.

Keys, seeds, signatures, and digests expose `encode()` for Base58 serialization.
Restore public keys, private keys, signatures, and digests with their static
`Decode()` methods. Restore a seed with its `decode()` method.

| Value | Raw size |
| --- | --- |
| Seed, public key, digest | 32 bytes |
| Private key, signature | 64 bytes |

Encoded values include a four-byte, little-endian CRC32 checksum. This format
differs from Bitcoin Base58Check. Private keys contain the expanded SHA-512
seed hash with its scalar clamped; they are neither raw seeds nor seed/public-key
concatenations.

### Restore a key pair

Inside the example above, after creating `pair`:

```cpp
const auto encoded_private_key = pair->get_private_key().encode();
auto restored_pair = ed25519::keys::Pair::FromPrivateKey(encoded_private_key);
if (!restored_pair) {
    return 1;
}
```

### Handle errors

Decoding and key restoration accept an optional `ed25519::ErrorHandler`.
The default handler ignores errors; failure is still reported by the return
value. Error codes are `BADFORMAT`, `UNEXPECTED_SIZE`, and `EMPTY`.

```cpp
const auto on_error = [](const std::error_code& error) {
    std::cerr << "Decode failed: " << error.value() << '\n';
};

auto public_key = ed25519::keys::Public::Decode("invalid key", on_error);
if (!public_key) {
    return 1;
}
```

## Digests

`Digest` computes SHA3-256 over appended values. The calculator accepts `bool`,
`unsigned char`, `short int`, `int`, `std::string`, byte vectors, and 32- or
64-byte `Data` values. Set integer byte order explicitly for a stable format.
Values are concatenated without type tags or length prefixes.

With `pair` from the signing example:

```cpp
ed25519::Digest digest([](ed25519::Digest::Calculator& calculator) {
    calculator.set_endian(ed25519::Digest::Calculator::endian::big);
    calculator.append(true);
    calculator.append(42);
    calculator.append(std::string("example"));
});

auto digest_signature = pair->sign(digest);
auto restored_digest = ed25519::Digest::Decode(digest.encode());
if (!restored_digest ||
    !digest_signature->verify(*restored_digest, pair->get_public_key())) {
    return 1;
}
```

Signing a digest signs its 32 bytes as an Ed25519 message.

# License

[MIT](LICENSE).
