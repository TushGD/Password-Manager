#pragma once

#include <string>

// Generates random passwords for the user to adopt for a credential.
//
// This is unrelated to the vault's own cryptography (Crypto.hpp, added
// in Phase 5) - that encrypts the vault file. This generates passwords
// for the sites/accounts the vault stores, using the same category of
// random source a real cryptographic key would need, since a guessable
// generated password defeats the purpose of a password manager.
namespace PasswordGenerator {

struct Options {
    int length = 16;
    bool includeUppercase = true;
    bool includeLowercase = true;
    bool includeDigits = true;
    bool includeSymbols = true;
};

// Throws std::invalid_argument if length is not positive, or if every
// character class is disabled (there would be nothing to draw from).
std::string generate(const Options& options);

}  // namespace PasswordGenerator
