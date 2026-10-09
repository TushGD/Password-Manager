#pragma once

#include "Vault.hpp"

#include <filesystem>
#include <string>

// Reads and writes a Vault as an encrypted file on disk.
//
// Storage itself still only knows about serializing a Vault to/from
// plain text (same format as Phase 3) - it hands that text to Crypto
// to be encrypted before writing, and decrypts it back before parsing
// on load. Storage and Crypto stay separate modules; this is just the
// glue between them.
namespace Storage {

// Throws std::invalid_argument if any credential field contains a
// reserved character (see Storage.cpp).
// Throws std::runtime_error on file I/O failure.
void save(const Vault& vault, const std::filesystem::path& path, const std::string& masterPassword);

// Throws std::runtime_error if the file is missing/unreadable, has an
// unrecognized header, is structurally malformed, or if masterPassword
// is wrong (these last two are indistinguishable - see Crypto.hpp).
Vault load(const std::filesystem::path& path, const std::string& masterPassword);

}  // namespace Storage
