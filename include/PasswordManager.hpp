#pragma once

#include "PasswordGenerator.hpp"
#include "Vault.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

// Ties Vault, Storage, and Crypto together into the operations a user
// actually performs: create a vault, unlock it, add/view/search/
// update/delete credentials, generate passwords, and save changes back
// to disk. The command-line interface (main.cpp) is a thin layer on
// top of this class - it only handles reading input and printing
// output; all the actual logic lives here.
class PasswordManager {
public:
    explicit PasswordManager(std::filesystem::path vaultPath);

    // True if a vault file already exists at the configured path.
    bool vaultExists() const;

    // Creates a new, empty vault at the configured path, encrypted
    // with masterPassword, and unlocks it. Throws std::runtime_error
    // if a vault file already exists there (use unlock() instead).
    void createVault(const std::string& masterPassword);

    // Loads and decrypts the vault file at the configured path.
    // Throws std::runtime_error if the file is missing, corrupted, or
    // masterPassword is wrong (indistinguishable - see Crypto.hpp).
    void unlock(const std::string& masterPassword);

    // Re-encrypts and writes the current vault state back to disk.
    // Throws std::logic_error if the vault is locked.
    void save();

    // Clears the in-memory vault and master password. Does not save -
    // call save() first if you have unsaved changes.
    void lock();

    bool isUnlocked() const noexcept { return unlocked_; }

    // Inactivity timeout used by lockIfIdle(). A timeout of zero (or
    // less) disables auto-locking. Defaults to two minutes.
    void setAutoLockTimeout(std::chrono::seconds timeout) noexcept { autoLockTimeout_ = timeout; }
    std::chrono::seconds autoLockTimeout() const noexcept { return autoLockTimeout_; }

    // If the vault is unlocked and no operation has touched it for at
    // least the auto-lock timeout, saves it and locks it, and returns
    // true. Returns false (and does nothing) otherwise.
    //
    // This is a check, not a background timer: the caller has to ask.
    // The CLI asks every time the user submits a command. If saving
    // fails the vault is still locked before the exception propagates,
    // because locking is the security-relevant half of the job.
    //
    // 'now' defaults to the real clock; tests pass a later time point
    // instead of sleeping.
    bool lockIfIdle(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    // All of the below throw std::logic_error if the vault is locked.
    Credential& addCredential(std::string site, std::string username, std::string password, std::string notes = "");
    Credential& getCredential(int id);
    void removeCredential(int id);
    std::vector<Credential> searchCredentials(const std::string& query) const;
    const std::vector<Credential>& allCredentials() const;

    // Changes the master password and immediately re-saves the vault
    // under the new password. Throws std::invalid_argument if
    // currentPassword doesn't match the vault's actual master password.
    void changeMasterPassword(const std::string& currentPassword, const std::string& newPassword);

    // Stateless - does not require the vault to be unlocked.
    static std::string generatePassword(const PasswordGenerator::Options& options);

private:
    void requireUnlocked() const;
    void recordActivity() const noexcept;

    std::filesystem::path vaultPath_;
    Vault vault_;
    std::string masterPassword_;
    bool unlocked_ = false;

    std::chrono::seconds autoLockTimeout_{120};
    // mutable: reading credentials is logically const but still counts
    // as activity for the idle timer.
    mutable std::chrono::steady_clock::time_point lastActivity_ = std::chrono::steady_clock::now();
};
