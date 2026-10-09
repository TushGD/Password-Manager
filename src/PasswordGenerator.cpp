#include "PasswordGenerator.hpp"

#include <random>
#include <stdexcept>

namespace {

const std::string kUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string kLowercase = "abcdefghijklmnopqrstuvwxyz";
const std::string kDigits = "0123456789";
const std::string kSymbols = "!@#$%^&*()-_=+[]{};:,.?";

std::string buildCharacterPool(const PasswordGenerator::Options& options) {
    std::string pool;
    if (options.includeUppercase) pool += kUppercase;
    if (options.includeLowercase) pool += kLowercase;
    if (options.includeDigits) pool += kDigits;
    if (options.includeSymbols) pool += kSymbols;
    return pool;
}

}  // namespace

std::string PasswordGenerator::generate(const Options& options) {
    if (options.length <= 0) {
        throw std::invalid_argument("Password length must be positive");
    }

    const std::string pool = buildCharacterPool(options);
    if (pool.empty()) {
        throw std::invalid_argument("At least one character class must be enabled");
    }

    // std::random_device is the standard library's handle to the
    // operating system's non-deterministic random source (/dev/urandom
    // on Linux, BCryptGenRandom on Windows). It's not meant for
    // generating huge volumes of data quickly, but a password is only
    // a few dozen characters, so drawing directly from it per character
    // is fine here and avoids using a fast-but-predictable PRNG like
    // mt19937 for something security-sensitive.
    std::random_device randomSource;
    std::uniform_int_distribution<std::size_t> distribution(0, pool.size() - 1);

    std::string password;
    password.reserve(static_cast<std::size_t>(options.length));
    for (int i = 0; i < options.length; ++i) {
        password += pool[distribution(randomSource)];
    }

    return password;
}
