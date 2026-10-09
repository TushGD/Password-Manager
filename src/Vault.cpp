#include "Vault.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace {

std::string toLower(const std::string& text) {
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(),
                    [](unsigned char c) { return std::tolower(c); });
    return result;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle) {
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

bool sameEntry(const Credential& credential, const std::string& site, const std::string& username) {
    return toLower(credential.site()) == toLower(site) &&
           toLower(credential.username()) == toLower(username);
}

}  // namespace

Credential& Vault::addCredential(std::string site, std::string username, std::string password, std::string notes) {
    const auto duplicate = std::ranges::find_if(credentials_, [&](const Credential& existing) {
        return sameEntry(existing, site, username);
    });
    if (duplicate != credentials_.end()) {
        throw std::invalid_argument("A credential for '" + site + "' with that username already exists");
    }

    credentials_.emplace_back(nextId_, std::move(site), std::move(username), std::move(password), std::move(notes));
    ++nextId_;
    return credentials_.back();
}

Credential& Vault::getCredential(int id) {
    auto it = std::ranges::find_if(credentials_, [id](const Credential& c) { return c.id() == id; });
    if (it == credentials_.end()) {
        throw std::out_of_range("No credential with id " + std::to_string(id));
    }
    return *it;
}

const Credential& Vault::getCredential(int id) const {
    return const_cast<Vault*>(this)->getCredential(id);
}

void Vault::removeCredential(int id) {
    auto it = std::ranges::find_if(credentials_, [id](const Credential& c) { return c.id() == id; });
    if (it == credentials_.end()) {
        throw std::out_of_range("No credential with id " + std::to_string(id));
    }
    credentials_.erase(it);
}

void Vault::loadSnapshot(std::vector<Credential> credentials, int nextId) {
    credentials_ = std::move(credentials);
    nextId_ = nextId;
}

std::vector<Credential> Vault::searchCredentials(const std::string& query) const {
    std::vector<Credential> matches;
    for (const auto& credential : credentials_) {
        if (containsCaseInsensitive(credential.site(), query) ||
            containsCaseInsensitive(credential.username(), query)) {
            matches.push_back(credential);
        }
    }
    return matches;
}
