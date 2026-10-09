#include "PasswordManager.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>

namespace {

using namespace std::chrono_literals;

const std::string kPassword = "my master password";

class PasswordManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = std::filesystem::path(::testing::TempDir()) / (std::string("pm_manager_") + info->name());
        std::filesystem::remove_all(directory_);
        std::filesystem::create_directories(directory_);
        vaultPath_ = directory_ / "vault.dat";
    }

    void TearDown() override { std::filesystem::remove_all(directory_); }

    std::filesystem::path directory_;
    std::filesystem::path vaultPath_;
};

}  // namespace

TEST_F(PasswordManagerTest, NewManagerReportsNoVaultAndIsLocked) {
    PasswordManager manager(vaultPath_);
    EXPECT_FALSE(manager.vaultExists());
    EXPECT_FALSE(manager.isUnlocked());
}

TEST_F(PasswordManagerTest, CreateVaultWritesFileAndUnlocks) {
    PasswordManager manager(vaultPath_);
    manager.createVault(kPassword);

    EXPECT_TRUE(manager.vaultExists());
    EXPECT_TRUE(manager.isUnlocked());
    EXPECT_TRUE(manager.allCredentials().empty());
}

TEST_F(PasswordManagerTest, CreateVaultRefusesToOverwriteExistingVault) {
    PasswordManager first(vaultPath_);
    first.createVault(kPassword);

    PasswordManager second(vaultPath_);
    EXPECT_THROW(second.createVault("another password"), std::runtime_error);
}

TEST_F(PasswordManagerTest, SavedCredentialsSurviveANewInstance) {
    {
        PasswordManager manager(vaultPath_);
        manager.createVault(kPassword);
        manager.addCredential("github.com", "tushar", "hunter2", "notes");
        manager.save();
    }

    PasswordManager reopened(vaultPath_);
    reopened.unlock(kPassword);
    ASSERT_EQ(reopened.allCredentials().size(), 1u);
    EXPECT_EQ(reopened.getCredential(1).site(), "github.com");
}

TEST_F(PasswordManagerTest, UnlockWithWrongPasswordThrowsAndStaysLocked) {
    {
        PasswordManager manager(vaultPath_);
        manager.createVault(kPassword);
    }

    PasswordManager reopened(vaultPath_);
    EXPECT_THROW(reopened.unlock("wrong"), std::runtime_error);
    EXPECT_FALSE(reopened.isUnlocked());
}

TEST_F(PasswordManagerTest, UnlockMissingVaultThrows) {
    PasswordManager manager(vaultPath_);
    EXPECT_THROW(manager.unlock(kPassword), std::runtime_error);
    EXPECT_FALSE(manager.isUnlocked());
}

TEST_F(PasswordManagerTest, OperationsThrowWhileLocked) {
    PasswordManager manager(vaultPath_);

    EXPECT_THROW(manager.addCredential("a.com", "u", "p"), std::logic_error);
    EXPECT_THROW(manager.getCredential(1), std::logic_error);
    EXPECT_THROW(manager.removeCredential(1), std::logic_error);
    EXPECT_THROW(manager.searchCredentials("a"), std::logic_error);
    EXPECT_THROW(manager.allCredentials(), std::logic_error);
    EXPECT_THROW(manager.save(), std::logic_error);
}

TEST_F(PasswordManagerTest, LockBlocksAccessUntilUnlockedAgain) {
    PasswordManager manager(vaultPath_);
    manager.createVault(kPassword);
    manager.addCredential("a.com", "u", "p");
    manager.save();

    manager.lock();
    EXPECT_FALSE(manager.isUnlocked());
    EXPECT_THROW(manager.allCredentials(), std::logic_error);

    manager.unlock(kPassword);
    EXPECT_EQ(manager.allCredentials().size(), 1u);
}

TEST_F(PasswordManagerTest, LockDiscardsUnsavedChanges) {
    PasswordManager manager(vaultPath_);
    manager.createVault(kPassword);
    manager.addCredential("unsaved.com", "u", "p");

    manager.lock();
    manager.unlock(kPassword);

    EXPECT_TRUE(manager.allCredentials().empty());
}

TEST_F(PasswordManagerTest, UpdateAndDeleteThroughManagerPersist) {
    PasswordManager manager(vaultPath_);
    manager.createVault(kPassword);
    manager.addCredential("a.com", "u", "old");
    manager.addCredential("b.com", "u", "p");
    manager.getCredential(1).setPassword("new");
    manager.removeCredential(2);
    manager.save();

    PasswordManager reopened(vaultPath_);
    reopened.unlock(kPassword);
    ASSERT_EQ(reopened.allCredentials().size(), 1u);
    EXPECT_EQ(reopened.getCredential(1).password(), "new");
}

TEST_F(PasswordManagerTest, ChangeMasterPasswordReplacesTheOldOne) {
    {
        PasswordManager manager(vaultPath_);
        manager.createVault(kPassword);
        manager.addCredential("a.com", "u", "p");
        manager.save();
        manager.changeMasterPassword(kPassword, "brand new password");
    }

    PasswordManager reopened(vaultPath_);
    EXPECT_THROW(reopened.unlock(kPassword), std::runtime_error);
    EXPECT_NO_THROW(reopened.unlock("brand new password"));
    EXPECT_EQ(reopened.allCredentials().size(), 1u);
}

TEST_F(PasswordManagerTest, ChangeMasterPasswordRejectsWrongCurrentPassword) {
    PasswordManager manager(vaultPath_);
    manager.createVault(kPassword);

    EXPECT_THROW(manager.changeMasterPassword("not the current one", "new"), std::invalid_argument);

    manager.lock();
    EXPECT_NO_THROW(manager.unlock(kPassword));  // original password still works
}

TEST_F(PasswordManagerTest, GeneratePasswordWorksWhileLocked) {
    PasswordManager manager(vaultPath_);
    PasswordGenerator::Options options;
    options.length = 12;
    EXPECT_EQ(PasswordManager::generatePassword(options).size(), 12u);
}

// --- Auto-lock ---
// These pass a future time point to lockIfIdle() instead of sleeping.

TEST_F(PasswordManagerTest, LockIfIdleDoesNothingBeforeTimeout) {
    PasswordManager manager(vaultPath_);
    manager.setAutoLockTimeout(60s);
    manager.createVault(kPassword);

    const auto soon = std::chrono::steady_clock::now() + 30s;
    EXPECT_FALSE(manager.lockIfIdle(soon));
    EXPECT_TRUE(manager.isUnlocked());
}

TEST_F(PasswordManagerTest, LockIfIdleLocksAfterTimeout) {
    PasswordManager manager(vaultPath_);
    manager.setAutoLockTimeout(60s);
    manager.createVault(kPassword);

    const auto later = std::chrono::steady_clock::now() + 61s;
    EXPECT_TRUE(manager.lockIfIdle(later));
    EXPECT_FALSE(manager.isUnlocked());
    EXPECT_THROW(manager.allCredentials(), std::logic_error);
}

TEST_F(PasswordManagerTest, AutoLockSavesPendingChangesFirst) {
    PasswordManager manager(vaultPath_);
    manager.setAutoLockTimeout(60s);
    manager.createVault(kPassword);
    manager.addCredential("pending.com", "u", "p");  // never explicitly saved

    EXPECT_TRUE(manager.lockIfIdle(std::chrono::steady_clock::now() + 61s));

    manager.unlock(kPassword);
    ASSERT_EQ(manager.allCredentials().size(), 1u);
    EXPECT_EQ(manager.getCredential(1).site(), "pending.com");
}

TEST_F(PasswordManagerTest, ZeroTimeoutDisablesAutoLock) {
    PasswordManager manager(vaultPath_);
    manager.setAutoLockTimeout(0s);
    manager.createVault(kPassword);

    EXPECT_FALSE(manager.lockIfIdle(std::chrono::steady_clock::now() + 24h));
    EXPECT_TRUE(manager.isUnlocked());
}

TEST_F(PasswordManagerTest, LockIfIdleOnLockedVaultReturnsFalse) {
    PasswordManager manager(vaultPath_);
    EXPECT_FALSE(manager.lockIfIdle(std::chrono::steady_clock::now() + 24h));
}
