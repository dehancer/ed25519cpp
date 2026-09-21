cmake_minimum_required(VERSION 4.2)

project(ed25519cpp VERSION 1.5.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BUILD_TESTING "Build tests" OFF)
option(ED25519CPP_BUILD_TESTING "Build ed25519cpp tests" OFF)

option(BUILD_DOC "Build documentation" OFF)
option(CREATE_PKG_CONFIG "Generate and install pkg-config metadata" OFF)

add_subdirectory(lib)

set(ed25519cpp_cmake_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/ed25519cpp")

configure_package_config_file(
    lib/cmake/Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/ed25519cppConfig.cmake"
    INSTALL_DESTINATION "${ed25519cpp_cmake_install_dir}"
)

install(EXPORT ed25519cppTargets
    FILE ed25519cppTargets.cmake
    NAMESPACE ed25519cpp::
    DESTINATION "${ed25519cpp_cmake_install_dir}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ed25519cppConfig.cmake"
    DESTINATION "${ed25519cpp_cmake_install_dir}"
)

if(CREATE_PKG_CONFIG)
    if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
        set(prefix "${CMAKE_INSTALL_PREFIX}")
    else()
        file(RELATIVE_PATH ed25519cpp_pc_prefix
            "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig"
            "${CMAKE_INSTALL_PREFIX}"
        )
        set(prefix "\${pcfiledir}/${ed25519cpp_pc_prefix}")
    endif()
    set(exec_prefix "\${prefix}")
    foreach(directory IN ITEMS LIBDIR INCLUDEDIR)
        if(IS_ABSOLUTE "${CMAKE_INSTALL_${directory}}")
            set(ed25519cpp_pc_${directory} "${CMAKE_INSTALL_${directory}}")
        else()
            set(ed25519cpp_pc_${directory} "\${prefix}/${CMAKE_INSTALL_${directory}}")
        endif()
    endforeach()
    set(libdir "${ed25519cpp_pc_LIBDIR}")
    set(includedir "${ed25519cpp_pc_INCLUDEDIR}")
    set(requires_private "")
    set(libs_private "")
    if(WIN32)
        set(libs_private "-ladvapi32")
    endif()
    configure_file(ed25519cpp.pc.in ed25519cpp.pc @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ed25519cpp.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    )
endif()

if(BUILD_DOC)
    find_package(Doxygen REQUIRED)
    configure_file(docs/Doxyfile.in Doxyfile @ONLY)
    add_custom_target(doc_doxygen ALL
        COMMAND Doxygen::doxygen "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        VERBATIM
    )
endif()

if(PROJECT_IS_TOP_LEVEL AND BUILD_TESTING)
    enable_testing()
    find_package(GTest REQUIRED)
    set(PROJECT_LIB ed25519cpp)
    add_subdirectory(test)
endif()
