set(CMAKE_INSTALL_PREFIX /usr/local/${PROJECT_LIB})

include_directories(
        ../include
        ../external/ed25519/include
        ../
        ../src/
        ../src/external
)

FILE(GLOB PUBLIC_INCLUDE_FILES
        ../include/*.hpp
        )

FILE(GLOB PUBLIC_INCLUDE_CPP17_FILES
        ../include/ed25519/c++17/*.hpp
        )

FILE(GLOB INCLUDE_FILES
        ${PUBLIC_INCLUDE_FILES}
        )

FILE(GLOB SOURCES
        ../src/*.cpp
        ../src/external/*.cpp
        ../external/ed25519/src/*.c
        )

add_library(${PROJECT_LIB}  ${SOURCES})

target_link_libraries (
        ${PROJECT_LIB}  PUBLIC
        ${Boost_LIBRARIES}
)

target_include_directories(
        ${PROJECT_LIB}
        PUBLIC
        ../include
)

set(config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

# Configuration
set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}")
set(namespace "${PROJECT_NAME}::")

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
        "${version_config}" COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
        "cmake/Config.cmake.in"
        "${project_config}"
        INSTALL_DESTINATION "${config_install_dir}"
)

install(TARGETS ${PROJECT_LIB}   DESTINATION lib)
install(FILES   ${PUBLIC_INCLUDE_FILES} DESTINATION include)
install(FILES   ${PUBLIC_INCLUDE_CPP17_FILES} DESTINATION include/ed25519/c++17)
install(FILES   ${project_config} ${version_config} DESTINATION lib/cmake/${PROJECT_LIB})
install(FILES   cmake/${PROJECT_LIB}.cmake DESTINATION lib/cmake/${PROJECT_LIB})