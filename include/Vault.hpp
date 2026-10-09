#pragma once

#include "Credential.hpp"

#include <string>
#include <vector>

// An in-memory collection of credentials.
//
// Vault is only responsible for holding credentials and letting callers
// add, find, update and remove them by id. It knows nothing about files
// or encryption - Storage and Crypto handle that in later phases, and
// will use Vault as the thing they load into / save from.
//
// References returned by addCredential() and getCredential() point into
// a std::vector, so adding or removing any credential invalidates them.
// Use them immediately; hold on to an id, not a reference.
class Vault {
public:
    // Throws std::invalid_argument if site or password is empty, or if
    // a credential with the same site and username already exists.
    Credential& addCredential(std::string site, std::string username, std::string password, std::string notes = "");

    // Throws std::out_of_range if no credential with this id exists.
    Credential& getCredential(int id);
    const Credential& getCredential(int id) const;

    // Throws std::out_of_range if no credential with this id exists.
    void removeCredential(int id);

    // Case-insensitive substring match against site and username.
    std::vector<Credential> searchCredentials(const std::string& query) const;

    const std::vector<Credential>& allCredentials() const noexcept { return credentials_; }

    std::size_t size() const noexcept { return credentials_.size(); }

    // Returns the id that will be assigned to the next credential added.
    // Storage persists this alongside the credentials so ids stay unique
    // across save/load cycles instead of restarting from 1 every load.
    int nextId() const noexcept { return nextId_; }

    // Replaces all vault contents with the given credentials and id
    // counter. Used by Storage when reconstructing a vault from disk.
    // Unlike addCredential(), this does not run the duplicate check,
    // since the data being loaded already passed that check when it
    // was first saved.
    void loadSnapshot(std::vector<Credential> credentials, int nextId);

private:
    std::vector<Credential> credentials_;
    int nextId_ = 1;
};
