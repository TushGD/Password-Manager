#include "PasswordManager.hpp"

#include "Storage.hpp"

#include <stdexcept>
#include <utility>

PasswordManager::PasswordManager(std::filesystem::path vaultPath) : vaultPath_(std::move(vaultPath)) {}

bool PasswordManager::vaultExists() const {
    return std::filesystem::exists(vaultPath_);
}

void PasswordManager::createVault(const std::string& masterPassword) {
    if (vaultExists()) {
        throw std::runtime_error("A vault already exists at " + vaultPath_.string());
    }
    vault_ = Vault{};
    masterPassword_ = masterPassword;
    unlocked_ = true;
    recordActivity();
    save();
}

void PasswordManager::unlock(const std::string& masterPassword) {
    Vault loaded = Storage::load(vaultPath_, masterPassword);  // throws on wrong password / corruption
    vault_ = std::move(loaded);
    masterPassword_ = masterPassword;
    unlocked_ = true;
    recordActivity();
}

void PasswordManager::save() {
    requireUnlocked();
    Storage::save(vault_, vaultPath_, masterPassword_);
}

void PasswordManager::lock() {
    vault_ = Vault{};
    // Best-effort scrub before releasing the buffer. std::string gives
    // no hard guarantee this leaves no trace in memory (a prior
    // reallocation could've left a copy elsewhere), but overwriting
    // before clearing is strictly better than doing nothing.
    masterPassword_.assign(masterPassword_.size(), '\0');
    masterPassword_.clear();
    unlocked_ = false;
}

void PasswordManager::requireUnlocked() const {
    if (!unlocked_) {
        throw std::logic_error("Vault is locked");
    }
    recordActivity();
}

void PasswordManager::recordActivity() const noexcept {
    lastActivity_ = std::chrono::steady_clock::now();
}

bool PasswordManager::lockIfIdle(std::chrono::steady_clock::time_point now) {
    if (!unlocked_ || autoLockTimeout_ <= std::chrono::seconds::zero()) {
        return false;
    }
    if (now - lastActivity_ < autoLockTimeout_) {
        return false;
    }

    try {
        save();
    } catch (...) {
        lock();
        throw;
    }
    lock();
    return true;
}

Credential& PasswordManager::addCredential(std::string site, std::string username, std::string password,
                                            std::string notes) {
    requireUnlocked();
    return vault_.addCredential(std::move(site), std::move(username), std::move(password), std::move(notes));
}

Credential& PasswordManager::getCredential(int id) {
    requireUnlocked();
    return vault_.getCredential(id);
}

void PasswordManager::removeCredential(int id) {
    requireUnlocked();
    vault_.removeCredential(id);
}

std::vector<Credential> PasswordManager::searchCredentials(const std::string& query) const {
    requireUnlocked();
    return vault_.searchCredentials(query);
}

const std::vector<Credential>& PasswordManager::allCredentials() const {
    requireUnlocked();
    return vault_.allCredentials();
}

void PasswordManager::changeMasterPassword(const std::string& currentPassword, const std::string& newPassword) {
    requireUnlocked();
    if (currentPassword != masterPassword_) {
        throw std::invalid_argument("Current master password is incorrect");
    }
    masterPassword_ = newPassword;
    save();
}

std::string PasswordManager::generatePassword(const PasswordGenerator::Options& options) {
    return PasswordGenerator::generate(options);
}
