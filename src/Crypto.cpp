#include "Crypto.hpp"

#include <sodium.h>

#include <stdexcept>

namespace {

// Magic statics (a function-local static initialized via an
// immediately-invoked lambda) run their initializer exactly once, the
// first time this function is called, and the standard guarantees that
// initialization is thread-safe. That makes this a simple, hidden
// "run once" check - callers of deriveKey/encrypt/decrypt never need
// to remember to call an explicit Crypto::init() themselves.
void ensureLibsodiumInitialized() {
    static const bool initialized = [] {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        return true;
    }();
    (void)initialized;
}

}  // namespace

Crypto::Bytes Crypto::generateSalt() {
    ensureLibsodiumInitialized();
    Bytes salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

Crypto::Bytes Crypto::deriveKey(const std::string& masterPassword, const Bytes& salt) {
    ensureLibsodiumInitialized();

    if (salt.size() != crypto_pwhash_SALTBYTES) {
        throw std::invalid_argument("Salt has the wrong length for key derivation");
    }

    Bytes key(crypto_secretbox_KEYBYTES);

    // Argon2id (crypto_pwhash's default algorithm) is the modern,
    // memory-hard choice for turning a password into a key - "memory
    // hard" means an attacker trying to brute-force it in parallel on a
    // GPU needs a large amount of memory per guess, not just time,
    // which is what makes GPU/ASIC cracking of password hashes
    // expensive. INTERACTIVE limits keep vault unlock under roughly a
    // second on typical hardware; MODERATE or SENSITIVE would be
    // slower but harder to brute-force offline if the vault file were
    // ever stolen.
    const int result = crypto_pwhash(
        key.data(), key.size(),
        masterPassword.c_str(), masterPassword.size(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT);

    if (result != 0) {
        // In practice this means the process ran out of memory for the
        // memory-hard hashing step, not that the password was "wrong".
        throw std::runtime_error("Key derivation failed (likely out of memory)");
    }

    return key;
}

Crypto::EncryptedBlob Crypto::encrypt(const std::string& plaintext, const std::string& masterPassword) {
    ensureLibsodiumInitialized();

    EncryptedBlob blob;
    blob.salt = generateSalt();
    Bytes key = deriveKey(masterPassword, blob.salt);

    blob.nonce.resize(crypto_secretbox_NONCEBYTES);
    randombytes_buf(blob.nonce.data(), blob.nonce.size());

    blob.ciphertext.resize(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(
        blob.ciphertext.data(),
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        blob.nonce.data(),
        key.data());

    // The key only ever needs to exist long enough to encrypt this one
    // message. Zeroing it here (rather than just letting the vector's
    // destructor run) ensures the key bytes don't linger in freed-but-
    // not-yet-overwritten memory.
    sodium_memzero(key.data(), key.size());

    return blob;
}

std::string Crypto::decrypt(const EncryptedBlob& blob, const std::string& masterPassword) {
    ensureLibsodiumInitialized();

    if (blob.nonce.size() != crypto_secretbox_NONCEBYTES) {
        throw std::runtime_error("Incorrect password or corrupted vault file");
    }
    if (blob.ciphertext.size() < crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Incorrect password or corrupted vault file");
    }

    Bytes key = deriveKey(masterPassword, blob.salt);

    Bytes plaintext(blob.ciphertext.size() - crypto_secretbox_MACBYTES);
    const int result = crypto_secretbox_open_easy(
        plaintext.data(),
        blob.ciphertext.data(), blob.ciphertext.size(),
        blob.nonce.data(),
        key.data());

    sodium_memzero(key.data(), key.size());

    if (result != 0) {
        throw std::runtime_error("Incorrect password or corrupted vault file");
    }

    std::string result_text(plaintext.begin(), plaintext.end());
    sodium_memzero(plaintext.data(), plaintext.size());
    return result_text;
}
