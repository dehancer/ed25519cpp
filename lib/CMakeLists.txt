add_library(ed25519cpp
    ../src/base58.cpp
    ../src/digest.cpp
    ../src/ed25519.cpp
    ../src/utils.cpp
    ../src/external/btc_base58.cpp
    ../src/external/ed25519_ext.cpp
    ../src/external/sha3.cpp
    ../external/ed25519/src/add_scalar.c
    ../external/ed25519/src/fe.c
    ../external/ed25519/src/ge.c
    ../external/ed25519/src/key_exchange.c
    ../external/ed25519/src/keypair.c
    ../external/ed25519/src/sc.c
    ../external/ed25519/src/seed.c
    ../external/ed25519/src/sha512.c
    ../external/ed25519/src/sign.c
    ../external/ed25519/src/verify.c
)
add_library(ed25519cpp::ed25519cpp ALIAS ed25519cpp)

target_compile_features(ed25519cpp PUBLIC cxx_std_17)

target_sources(ed25519cpp PUBLIC
    FILE_SET HEADERS
    BASE_DIRS ../include
    FILES
        ../include/ed25519.hpp
        ../include/ed25519/c++17/variant.hpp
)

target_include_directories(ed25519cpp PRIVATE
    ../external/ed25519/include
    ../src/external
)

set_target_properties(ed25519cpp PROPERTIES
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)

if(WIN32)
    target_link_libraries(ed25519cpp PRIVATE advapi32)
endif()

install(TARGETS ed25519cpp
    EXPORT ed25519cppTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    FILE_SET HEADERS DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
