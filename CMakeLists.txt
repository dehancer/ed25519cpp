cmake_minimum_required(VERSION 3.8)
set(PROJECT_LIB ed25519cpp)
project(${PROJECT_LIB} VERSION 1.3.6)

option(DEHANCER_TARGET_ARCH "")

set(CMAKE_CXX_STANDARD 17)

if (DEHANCER_TARGET_ARCH)
    #
    # x86_64-apple-macos10.13
    # or
    # arm64-apple-macos11
    #
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -target ${DEHANCER_TARGET_ARCH}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target ${DEHANCER_TARGET_ARCH}")
endif ()

if (WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -EHsc -Wno-deprecated-declarations")
    add_definitions(/MT /DWIN32=1 /D_ITERATOR_DEBUG_LEVEL=0)
    string(TOLOWER  ${CMAKE_BUILD_TYPE} BUILD_TYPE)
    if (${BUILD_TYPE} STREQUAL "debug")
        add_definitions(/MTd)
    endif()
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=default")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Ofast -ffast-math")
endif ()


set (EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)
option(BUILD_TESTING "Enable creation of Eigen tests." OFF)
# first we can indicate the documentation build as an option and set it to ON by default
option(BUILD_DOC "Build documentation" OFF)

include(ExternalProject)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

message(STATUS ${CMAKE_CURRENT_SOURCE_DIR} )

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")

    message(STATUS "Using Clang" )

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

    message(STATUS "Using gcc" )

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -W -Wall -Wextra -Wvariadic-macros -static-libgcc -static-libstdc++ ")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

    if (${CMAKE_SYSTEM_NAME} STREQUAL Linux)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DX86_LINUX")
    endif()

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")

    message( FATAL_ERROR "The project does not support Intel compiler" )

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")

    message( FATAL_ERROR "The project does not support MSVC compiler" )

endif()

# check if Doxygen is installed
if(BUILD_DOC)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        # set input and output files
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        # request to configure the file
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        message("Doxygen build started")

        # note the option ALL which allows to build the docs together with the application
        add_custom_target( doc_doxygen ALL
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM )
    else (DOXYGEN_FOUND)
        message("Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif()

#
# Google Test
#
if (BUILD_TESTING)
    find_package(GTest)
    if (NOT GTEST_FOUND)

        string(STRIP "${CMAKE_C_FLAGS} -D_ITERATOR_DEBUG_LEVEL=0" C_FLAGS)
        string(STRIP "${CMAKE_CXX_FLAGS} -D_ITERATOR_DEBUG_LEVEL=0" CXX_FLAGS)

        ExternalProject_Add(googletest
                GIT_REPOSITORY https://github.com/google/googletest
                GIT_TAG release-1.11.0
                CMAKE_ARGS
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                -DCMAKE_C_FLAGS=${C_FLAGS}
                -DCMAKE_CXX_FLAGS=${CXX_FLAGS}
                PREFIX ${DEHANCER_COMMON_DIR}
                )
        set(COMMON_DEPENDENCIES ${COMMON_DEPENDENCIES};googletest)
    endif ()
endif ()

#
# Details
#
include_directories(
        ${EXTERNAL_INSTALL_LOCATION}/include
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/external
        ${SQLITE3_INCLUDE_DIRS}
)

link_directories(
        ${EXTERNAL_INSTALL_LOCATION}/lib
)

add_subdirectory(lib)

if (BUILD_TESTING)
    add_subdirectory(test)
    enable_testing ()
endif ()

# Install package
#
if (NOT CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR  lib)
endif ()
if (NOT CMAKE_INSTALL_INCLUDEDIR)
    set(CMAKE_INSTALL_INCLUDEDIR  include)
endif ()

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")

configure_file(${CMAKE_SOURCE_DIR}/ed25519cpp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ed25519cpp.pc @ONLY)

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ed25519cpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
        )
