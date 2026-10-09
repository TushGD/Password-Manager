cmake_minimum_required(VERSION 3.20)
project(password_manager CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# All of the project's actual logic lives in this library. The CLI
# executable and the test binary both link against it, so the classes
# only get compiled once and tests exercise the exact same object code
# the shipped program runs - not a separate copy.
add_library(password_manager_lib
    src/Credential.cpp
    src/Vault.cpp
    src/Storage.cpp
    src/PasswordGenerator.cpp
    src/Crypto.cpp
    src/PasswordManager.cpp
)

target_include_directories(password_manager_lib PUBLIC include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(password_manager_lib PUBLIC ${SODIUM_LIBRARIES})
target_compile_options(password_manager_lib PUBLIC ${SODIUM_CFLAGS_OTHER})

add_executable(password_manager src/main.cpp)
target_link_libraries(password_manager PRIVATE password_manager_lib)

option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
