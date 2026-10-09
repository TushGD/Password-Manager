#include "Credential.hpp"

#include <stdexcept>

Credential::Credential(int id, std::string site, std::string username, std::string password, std::string notes)
    : id_(id), username_(std::move(username)), notes_(std::move(notes)) {
    setSite(std::move(site));
    setPassword(std::move(password));
}

void Credential::setSite(std::string site) {
    if (site.empty()) {
        throw std::invalid_argument("Credential site cannot be empty");
    }
    site_ = std::move(site);
}

void Credential::setUsername(std::string username) {
    username_ = std::move(username);
}

void Credential::setPassword(std::string password) {
    if (password.empty()) {
        throw std::invalid_argument("Credential password cannot be empty");
    }
    password_ = std::move(password);
}

void Credential::setNotes(std::string notes) {
    notes_ = std::move(notes);
}
