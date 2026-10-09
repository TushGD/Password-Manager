#include "PasswordGenerator.hpp"
#include "PasswordManager.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

// Thrown when stdin closes (Ctrl+D / Ctrl+Z, or piped input running
// out). Without this, prompts would loop forever reading empty lines.
struct InputClosed : std::exception {};

std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    if (!std::getline(std::cin, line)) {
        throw InputClosed{};
    }
    return line;
}

int readInt(const std::string& prompt) {
    while (true) {
        const std::string line = readLine(prompt);
        try {
            std::size_t consumed = 0;
            const int value = std::stoi(line, &consumed);
            if (consumed == line.size()) {
                return value;
            }
        } catch (const std::exception&) {
            // falls through to the message below
        }
        std::cout << "Please enter a whole number.\n";
    }
}

void printCredential(const Credential& credential) {
    std::cout << "  [" << credential.id() << "] " << credential.site()
              << " | username: " << (credential.username().empty() ? "(none)" : credential.username())
              << " | password: " << credential.password();
    if (!credential.notes().empty()) {
        std::cout << " | notes: " << credential.notes();
    }
    std::cout << "\n";
}

void runAddCredential(PasswordManager& manager) {
    const std::string site = readLine("Site/service name: ");
    const std::string username = readLine("Username (leave blank if none): ");

    std::string password;
    const std::string generate = readLine("Generate a random password for this entry? (y/n): ");
    if (generate == "y" || generate == "Y") {
        password = PasswordManager::generatePassword(PasswordGenerator::Options{});
        std::cout << "Generated password: " << password << "\n";
    } else {
        password = readLine("Password: ");
    }

    const std::string notes = readLine("Notes (optional): ");

    const Credential& added = manager.addCredential(site, username, password, notes);
    std::cout << "Added credential #" << added.id() << " for " << added.site() << "\n";
}

void runView(PasswordManager& manager) {
    const auto& all = manager.allCredentials();
    if (all.empty()) {
        std::cout << "No credentials stored yet.\n";
        return;
    }
    std::cout << all.size() << " stored credential(s):\n";
    for (const auto& credential : all) {
        printCredential(credential);
    }
}

void runSearch(PasswordManager& manager) {
    const std::string query = readLine("Search for (site or username): ");
    const auto matches = manager.searchCredentials(query);
    if (matches.empty()) {
        std::cout << "No matches.\n";
        return;
    }
    std::cout << matches.size() << " match(es):\n";
    for (const auto& credential : matches) {
        printCredential(credential);
    }
}

void runUpdate(PasswordManager& manager) {
    const int id = readInt("Credential id to update: ");
    Credential& credential = manager.getCredential(id);  // throws std::out_of_range if missing

    std::cout << "Leave a field blank to keep its current value.\n";

    const std::string site = readLine("New site [" + credential.site() + "]: ");
    if (!site.empty()) {
        credential.setSite(site);
    }

    const std::string username = readLine("New username [" + credential.username() + "]: ");
    if (!username.empty()) {
        credential.setUsername(username);
    }

    const std::string password = readLine("New password (leave blank to keep current): ");
    if (!password.empty()) {
        credential.setPassword(password);
    }

    const std::string notes = readLine("New notes [" + credential.notes() + "]: ");
    if (!notes.empty()) {
        credential.setNotes(notes);
    }

    std::cout << "Updated credential #" << credential.id() << ".\n";
}

void runDelete(PasswordManager& manager) {
    const int id = readInt("Credential id to delete: ");
    const Credential& credential = manager.getCredential(id);  // throws std::out_of_range if missing

    const std::string confirm = readLine("Delete '" + credential.site() + "'? This cannot be undone. (y/n): ");
    if (confirm == "y" || confirm == "Y") {
        manager.removeCredential(id);
        std::cout << "Deleted.\n";
    } else {
        std::cout << "Cancelled.\n";
    }
}

void runGeneratePassword() {
    const int length = readInt("Password length (e.g. 16): ");
    PasswordGenerator::Options options;
    options.length = length;
    const std::string password = PasswordManager::generatePassword(options);
    std::cout << "Generated password: " << password << "\n";
}

void runChangeMasterPassword(PasswordManager& manager) {
    const std::string current = readLine("Current master password: ");
    const std::string replacement = readLine("New master password: ");
    const std::string confirmReplacement = readLine("Confirm new master password: ");

    if (replacement != confirmReplacement) {
        std::cout << "New passwords did not match; master password unchanged.\n";
        return;
    }
    if (replacement.empty()) {
        std::cout << "Master password cannot be empty; unchanged.\n";
        return;
    }

    manager.changeMasterPassword(current, replacement);
    std::cout << "Master password changed and vault re-saved.\n";
}

void printMenu() {
    std::cout << "\n--- Menu ---\n"
              << "1) Add credential\n"
              << "2) View all credentials\n"
              << "3) Search credentials\n"
              << "4) Update a credential\n"
              << "5) Delete a credential\n"
              << "6) Generate a password\n"
              << "7) Change master password\n"
              << "8) Save\n"
              << "9) Save and exit\n"
              << "10) Lock vault\n"
              << "Choose an option: ";
}

// Returns false if the user chose to quit instead of unlocking.
bool promptUnlock(PasswordManager& manager) {
    while (!manager.isUnlocked()) {
        const std::string input = readLine("Enter master password to unlock (or 'exit' to quit): ");
        if (input == "exit") {
            return false;
        }
        try {
            manager.unlock(input);
            std::cout << "Vault unlocked.\n";
        } catch (const std::runtime_error& e) {
            std::cout << e.what() << "\n";
        }
    }
    return true;
}

void createNewVault(PasswordManager& manager, const std::filesystem::path& vaultPath) {
    std::cout << "No vault found at " << vaultPath << ".\n";
    std::string password;
    while (password.empty()) {
        password = readLine("Choose a master password for your new vault: ");
        if (password.empty()) {
            std::cout << "Master password cannot be empty.\n";
        }
    }
    manager.createVault(password);
    std::cout << "Vault created and unlocked.\n";
}

// Runs one menu command. Errors are thrown; the caller reports them
// without ending the session.
void runMenuChoice(PasswordManager& manager, const std::string& choice, bool& running) {
    if (choice == "1") {
        runAddCredential(manager);
    } else if (choice == "2") {
        runView(manager);
    } else if (choice == "3") {
        runSearch(manager);
    } else if (choice == "4") {
        runUpdate(manager);
    } else if (choice == "5") {
        runDelete(manager);
    } else if (choice == "6") {
        runGeneratePassword();
    } else if (choice == "7") {
        runChangeMasterPassword(manager);
    } else if (choice == "8") {
        manager.save();
        std::cout << "Saved.\n";
    } else if (choice == "9") {
        manager.save();
        manager.lock();
        std::cout << "Vault saved and locked. Goodbye.\n";
        running = false;
    } else if (choice == "10") {
        manager.save();
        manager.lock();
        std::cout << "Vault saved and locked.\n";
    } else {
        std::cout << "Unrecognized option.\n";
    }
}

int run(PasswordManager& manager, const std::filesystem::path& vaultPath) {
    if (!manager.vaultExists()) {
        createNewVault(manager, vaultPath);
    }

    bool running = true;
    while (running) {
        if (!manager.isUnlocked() && !promptUnlock(manager)) {
            std::cout << "Goodbye.\n";
            return 0;
        }

        printMenu();
        const std::string choice = readLine("");

        try {
            if (manager.lockIfIdle()) {
                std::cout << "\nVault auto-locked after inactivity (changes were saved).\n";
                continue;  // the command typed while locked is discarded on purpose
            }
            runMenuChoice(manager, choice, running);
        } catch (const InputClosed&) {
            throw;
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << "\n";
        }
    }

    return 0;
}

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [--vault <path>] [--timeout <seconds>]\n"
              << "  --vault    vault file to use (default: data/vault.dat)\n"
              << "  --timeout  auto-lock after this many idle seconds; 0 disables (default: 120)\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::filesystem::path vaultPath = "data/vault.dat";
    std::chrono::seconds timeout{120};

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--vault" && i + 1 < argc) {
            vaultPath = argv[++i];
        } else if (arg == "--timeout" && i + 1 < argc) {
            try {
                timeout = std::chrono::seconds(std::stoi(argv[++i]));
            } catch (const std::exception&) {
                std::cerr << "--timeout needs a whole number of seconds\n";
                return 2;
            }
        } else {
            printUsage(argv[0]);
            return arg == "--help" ? 0 : 2;
        }
    }

    PasswordManager manager(vaultPath);
    manager.setAutoLockTimeout(timeout);

    std::cout << "=== Password Manager ===\n";

    try {
        return run(manager, vaultPath);
    } catch (const InputClosed&) {
        std::cout << "\nInput closed. Exiting.\n";
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        if (manager.isUnlocked()) {
            manager.lock();
        }
        return 1;
    }

    if (manager.isUnlocked()) {
        try {
            manager.save();
        } catch (const std::exception& e) {
            std::cerr << "Could not save on exit: " << e.what() << "\n";
        }
        manager.lock();
    }
    return 0;
}
