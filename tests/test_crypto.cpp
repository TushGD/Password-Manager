#include "Crypto.hpp"

#include <gtest/gtest.h>

namespace {

const std::string kPassword = "my master password";
const std::string kMessage = "sensitive vault data";

}  // namespace

TEST(CryptoTest, RoundTripReturnsOriginalPlaintext) {
    const auto blob = Crypto::encrypt(kMessage, kPassword);
    EXPECT_EQ(Crypto::decrypt(blob, kPassword), kMessage);
}

TEST(CryptoTest, EmptyPlaintextRoundTrips) {
    const auto blob = Crypto::encrypt("", kPassword);
    EXPECT_EQ(Crypto::decrypt(blob, kPassword), "");
}

TEST(CryptoTest, CiphertextDoesNotContainPlaintext) {
    const auto blob = Crypto::encrypt(kMessage, kPassword);
    const std::string ciphertext(blob.ciphertext.begin(), blob.ciphertext.end());
    EXPECT_EQ(ciphertext.find(kMessage), std::string::npos);
}

TEST(CryptoTest, WrongPasswordFailsToDecrypt) {
    const auto blob = Crypto::encrypt(kMessage, kPassword);
    EXPECT_THROW(Crypto::decrypt(blob, "not the password"), std::runtime_error);
}

TEST(CryptoTest, TamperedCiphertextFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.ciphertext[0] ^= 0xFF;
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

TEST(CryptoTest, TamperedAuthenticationTagFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.ciphertext.back() ^= 0x01;
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

TEST(CryptoTest, TamperedNonceFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.nonce[0] ^= 0xFF;
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

TEST(CryptoTest, TamperedSaltFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.salt[0] ^= 0xFF;
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

TEST(CryptoTest, TruncatedCiphertextFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.ciphertext.resize(3);  // shorter than the authentication tag
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

TEST(CryptoTest, WrongNonceLengthFailsToDecrypt) {
    auto blob = Crypto::encrypt(kMessage, kPassword);
    blob.nonce.pop_back();
    EXPECT_THROW(Crypto::decrypt(blob, kPassword), std::runtime_error);
}

// Reusing a salt or nonce would weaken the scheme, so two encryptions
// of identical input must never share them.
TEST(CryptoTest, EncryptingTwiceUsesFreshSaltAndNonce) {
    const auto first = Crypto::encrypt(kMessage, kPassword);
    const auto second = Crypto::encrypt(kMessage, kPassword);

    EXPECT_NE(first.salt, second.salt);
    EXPECT_NE(first.nonce, second.nonce);
    EXPECT_NE(first.ciphertext, second.ciphertext);
}

TEST(CryptoTest, DeriveKeyIsDeterministicForSamePasswordAndSalt) {
    const auto salt = Crypto::generateSalt();
    EXPECT_EQ(Crypto::deriveKey(kPassword, salt), Crypto::deriveKey(kPassword, salt));
}

TEST(CryptoTest, DeriveKeyDiffersForDifferentSalts) {
    const auto saltA = Crypto::generateSalt();
    const auto saltB = Crypto::generateSalt();
    EXPECT_NE(Crypto::deriveKey(kPassword, saltA), Crypto::deriveKey(kPassword, saltB));
}

TEST(CryptoTest, DeriveKeyDiffersForDifferentPasswords) {
    const auto salt = Crypto::generateSalt();
    EXPECT_NE(Crypto::deriveKey("password one", salt), Crypto::deriveKey("password two", salt));
}

TEST(CryptoTest, DeriveKeyRejectsWrongSaltLength) {
    const Crypto::Bytes badSalt(3, 0);
    EXPECT_THROW(Crypto::deriveKey(kPassword, badSalt), std::invalid_argument);
}
