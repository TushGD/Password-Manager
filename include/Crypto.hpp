#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Key derivation and authenticated encryption for the vault, built on
// libsodium. This file does not implement any cryptographic primitive
// itself - it only calls into libsodium and manages the inputs/outputs
// (salts, nonces, keys) those primitives need.
//
// Three distinct operations live here, and it's worth keeping them
// straight:
//   - Key derivation (deriveKey): turns a human-memorable master
//     password into a fixed-size secret key. Deliberately slow, to
//     make brute-forcing the master password expensive.
//   - Encryption (encrypt/decrypt): uses that key to make vault data
//     unreadable, and, via the authentication tag, detects if it was
//     ever modified.
//   - Random number generation: used here to generate salts and
//     nonces, both of which must be unpredictable but do not need to
//     be secret themselves.
namespace Crypto {

using Bytes = std::vector<std::uint8_t>;

// A password-encrypted blob of data, ready to be written to disk
// alongside the vault format version. The salt and nonce are not
// secret - they're stored in plaintext next to the ciphertext, which
// is normal and required for this construction to be decryptable.
struct EncryptedBlob {
    Bytes salt;
    Bytes nonce;
    Bytes ciphertext;
};

// Returns a fresh, random salt suitable for deriveKey().
Bytes generateSalt();

// Derives a fixed-size secret key from a master password and salt
// using Argon2id. The same password and salt always produce the same
// key; changing either changes the key completely.
Bytes deriveKey(const std::string& masterPassword, const Bytes& salt);

// Encrypts plaintext under a key derived from masterPassword, using a
// freshly generated salt and nonce. Throws std::runtime_error if
// libsodium fails to initialize.
EncryptedBlob encrypt(const std::string& plaintext, const std::string& masterPassword);

// Decrypts a blob produced by encrypt(), re-deriving the key from
// masterPassword and the blob's stored salt.
//
// Throws std::runtime_error if the password is wrong OR the ciphertext
// was tampered with/corrupted. These two cases are indistinguishable
// by design: authenticated encryption fails the same way for both, and
// that's a deliberate security property, not a limitation to work
// around - a system that could tell an attacker "that's not quite the
// right password" vs. "that data was corrupted" would be leaking
// information that helps guess the password.
std::string decrypt(const EncryptedBlob& blob, const std::string& masterPassword);

}  // namespace Crypto
