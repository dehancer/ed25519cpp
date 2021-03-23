if (GTEST_FOUND)
    include_directories(${GTEST_INCLUDE_DIRS})
    set(TEST_LIBRARIES ${GTEST_BOTH_LIBRARIES})
else()
    set(TEST_LIBRARIES gtest;gtest_main)
endif()

file (GLOB TESTS_SOURCES ${TESTS_SOURCES}
        ./*.cpp
        )


file (GLOB TESTS_SOURCES ${TESTS_SOURCES}
        ./*.cpp
        )

set (TEST digest_${PROJECT_LIB})

add_executable(${TEST} ${TESTS_SOURCES})


if (COMMON_DEPENDENCIES)
    message(STATUS "${TEST} DEPENDENCIES: ${COMMON_DEPENDENCIES}")
    add_dependencies(
            ${TEST}
            ${COMMON_DEPENDENCIES}
    )
endif ()

target_link_libraries (
        ${TEST}
        ${PROJECT_LIB}
        ${TEST_LIBRARIES})

add_test (test ${TEST})
enable_testing ()
