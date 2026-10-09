#pragma once

#include <string>

// A single site/username/password entry stored in the vault.
//
// Credential only knows about its own fields and their basic validity.
// It has no idea how it gets persisted or encrypted - that's Storage's
// and Crypto's job later on.
class Credential {
public:
    Credential(int id, std::string site, std::string username, std::string password, std::string notes = "");

    int id() const noexcept { return id_; }
    const std::string& site() const noexcept { return site_; }
    const std::string& username() const noexcept { return username_; }
    const std::string& password() const noexcept { return password_; }
    const std::string& notes() const noexcept { return notes_; }

    // Throws std::invalid_argument if site is empty.
    void setSite(std::string site);

    void setUsername(std::string username);

    // Throws std::invalid_argument if password is empty.
    void setPassword(std::string password);

    void setNotes(std::string notes);

private:
    int id_;
    std::string site_;
    std::string username_;
    std::string password_;
    std::string notes_;
};
