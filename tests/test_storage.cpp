#include "Storage.hpp"
#include "Vault.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>

namespace {

const std::string kPassword = "my master password";

class StorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = std::filesystem::path(::testing::TempDir()) / (std::string("pm_storage_") + info->name());
        std::filesystem::remove_all(directory_);
        std::filesystem::create_directories(directory_);
    }

    void TearDown() override { std::filesystem::remove_all(directory_); }

    std::filesystem::path pathFor(const std::string& name) const { return directory_ / name; }

    static std::string readAll(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    static void writeAll(const std::filesystem::path& path, const std::string& content) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    std::filesystem::path directory_;
};

Vault makeSampleVault() {
    Vault vault;
    vault.addCredential("github.com", "tushar", "hunter2", "personal account");
    vault.addCredential("gmail.com", "tushar.dev", "correct-horse");
    vault.addCredential("no-username.com", "", "pw", "");
    return vault;
}

}  // namespace

TEST_F(StorageTest, RoundTripPreservesCredentials) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    const Vault loaded = Storage::load(path, kPassword);
    ASSERT_EQ(loaded.size(), 3u);
    EXPECT_EQ(loaded.getCredential(1).site(), "github.com");
    EXPECT_EQ(loaded.getCredential(1).notes(), "personal account");
    EXPECT_EQ(loaded.getCredential(2).username(), "tushar.dev");
    EXPECT_EQ(loaded.getCredential(3).username(), "");
    EXPECT_EQ(loaded.getCredential(3).notes(), "");
}

TEST_F(StorageTest, EmptyVaultRoundTrips) {
    const auto path = pathFor("empty.dat");
    Storage::save(Vault{}, path, kPassword);

    const Vault loaded = Storage::load(path, kPassword);
    EXPECT_EQ(loaded.size(), 0u);
}

TEST_F(StorageTest, SaveCreatesMissingParentDirectories) {
    const auto path = pathFor("nested/dir/vault.dat");
    EXPECT_NO_THROW(Storage::save(makeSampleVault(), path, kPassword));
    EXPECT_TRUE(std::filesystem::exists(path));
}

TEST_F(StorageTest, IdCounterSurvivesSaveAndLoad) {
    Vault vault;
    vault.addCredential("a.com", "u", "p");
    vault.addCredential("b.com", "u", "p");
    vault.removeCredential(1);

    const auto path = pathFor("ids.dat");
    Storage::save(vault, path, kPassword);

    Vault loaded = Storage::load(path, kPassword);
    EXPECT_EQ(loaded.addCredential("c.com", "u", "p").id(), 3);
}

TEST_F(StorageTest, FileDoesNotContainPlaintextCredentials) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    const std::string raw = readAll(path);
    EXPECT_EQ(raw.find("github.com"), std::string::npos);
    EXPECT_EQ(raw.find("hunter2"), std::string::npos);
    EXPECT_EQ(raw.find("correct-horse"), std::string::npos);
}

TEST_F(StorageTest, WrongPasswordThrows) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    EXPECT_THROW(Storage::load(path, "wrong password"), std::runtime_error);
}

TEST_F(StorageTest, MissingFileThrows) {
    EXPECT_THROW(Storage::load(pathFor("does-not-exist.dat"), kPassword), std::runtime_error);
}

TEST_F(StorageTest, UnrecognizedFileFormatThrows) {
    const auto path = pathFor("not-a-vault.dat");
    writeAll(path, "this is not a vault file at all");

    EXPECT_THROW(Storage::load(path, kPassword), std::runtime_error);
}

TEST_F(StorageTest, EmptyFileThrows) {
    const auto path = pathFor("zero-bytes.dat");
    writeAll(path, "");

    EXPECT_THROW(Storage::load(path, kPassword), std::runtime_error);
}

TEST_F(StorageTest, TruncatedFileThrows) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    const std::string raw = readAll(path);
    writeAll(path, raw.substr(0, raw.size() / 2));

    EXPECT_THROW(Storage::load(path, kPassword), std::runtime_error);
}

TEST_F(StorageTest, TamperedCiphertextByteThrows) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    std::string raw = readAll(path);
    raw[raw.size() - 5] ^= static_cast<char>(0xFF);  // inside the ciphertext/tag region
    writeAll(path, raw);

    EXPECT_THROW(Storage::load(path, kPassword), std::runtime_error);
}

TEST_F(StorageTest, AbsurdLengthFieldIsRejectedWithoutHugeAllocation) {
    const auto path = pathFor("vault.dat");
    Storage::save(makeSampleVault(), path, kPassword);

    std::string raw = readAll(path);
    // Bytes 8..11 hold the salt length; claim the salt is ~4 GB.
    raw[8] = static_cast<char>(0xFF);
    raw[9] = static_cast<char>(0xFF);
    raw[10] = static_cast<char>(0xFF);
    raw[11] = static_cast<char>(0xFF);
    writeAll(path, raw);

    EXPECT_THROW(Storage::load(path, kPassword), std::runtime_error);
}

TEST_F(StorageTest, SavingTwiceProducesDifferentFiles) {
    const Vault vault = makeSampleVault();
    Storage::save(vault, pathFor("a.dat"), kPassword);
    Storage::save(vault, pathFor("b.dat"), kPassword);

    EXPECT_NE(readAll(pathFor("a.dat")), readAll(pathFor("b.dat")));
}

TEST_F(StorageTest, FieldContainingReservedSeparatorIsRejectedOnSave) {
    Vault vault;
    vault.addCredential(std::string("bad") + '\x1F' + "site", "u", "p");

    const auto path = pathFor("vault.dat");
    EXPECT_THROW(Storage::save(vault, path, kPassword), std::invalid_argument);
    EXPECT_FALSE(std::filesystem::exists(path));  // a failed save leaves no file behind
}

TEST_F(StorageTest, FieldContainingNewlineIsRejectedOnSave) {
    Vault vault;
    vault.addCredential("site.com", "u", "line1\nline2");

    EXPECT_THROW(Storage::save(vault, pathFor("vault.dat"), kPassword), std::invalid_argument);
}
