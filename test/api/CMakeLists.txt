
file (GLOB TESTS_SOURCES ${TESTS_SOURCES}
        ./*.cpp
        )

set (TEST api_${PROJECT_LIB})

add_executable(${TEST} ${TESTS_SOURCES})

target_link_libraries (
        ${TEST}
        ${PROJECT_LIB}
        ${Boost_LIBRARIES})

add_test (test ${TEST})
enable_testing ()
