
include_directories(
        ./
        ../include
)

add_subdirectory(api)
add_subdirectory(digest)
add_subdirectory(performance)
enable_testing ()
