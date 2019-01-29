
set (MILE_TEST_LIB ed25519cpp_api_test)

set (BOOST_COMPONENTS
        unit_test_framework
        )

include_directories(
        ./
        ../include
)

find_package (Boost REQUIRED COMPONENTS ${BOOST_COMPONENTS})

add_subdirectory(api)
enable_testing ()
