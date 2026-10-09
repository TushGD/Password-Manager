include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)

# GoogleTest recommends forcing this on Windows so it links the same
# C runtime as the rest of the project; harmless elsewhere.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(password_manager_tests
    test_vault.cpp
    test_password_generator.cpp
    test_crypto.cpp
    test_storage.cpp
    test_password_manager.cpp
)

target_link_libraries(password_manager_tests PRIVATE password_manager_lib GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(password_manager_tests)
