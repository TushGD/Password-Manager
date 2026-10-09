#include "Storage.hpp"

#include "Crypto.hpp"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

constexpr char kFieldSeparator = '\x1F';  // ASCII unit separator - not typable, unlikely in real data
const std::string kInnerFormatHeader = "PMVAULT1";   // the serialized-text format, now encrypted before storage
const std::string kFileMagic = "PMVENC01";           // on-disk file format: encrypted container, version 1

// Generous but finite caps so a corrupted or malicious file can't make
// the loader try to allocate an absurd amount of memory before any
// cryptographic check even runs.
constexpr std::uint32_t kMaxSaltOrNonceLength = 256;
constexpr std::uint32_t kMaxCiphertextLength = 64u * 1024u * 1024u;  // 64 MB - far beyond any real vault

void checkField(const std::string& field, const std::string& fieldName) {
    if (field.find(kFieldSeparator) != std::string::npos || field.find('\n') != std::string::npos) {
        throw std::invalid_argument(fieldName + " contains a reserved character and cannot be stored");
    }
}

std::string trimTrailingCarriageReturn(std::string line) {
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

// Splits on kFieldSeparator, preserving trailing empty fields (e.g. an
// empty notes field at the end of the line). std::getline-based
// splitting silently drops a trailing empty token, which would corrupt
// the field count, so this walks the string manually instead.
std::vector<std::string> splitFields(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = line.find(kFieldSeparator, start);
        if (pos == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

int parseInt(const std::string& text, const std::string& context) {
    try {
        std::size_t consumed = 0;
        const int value = std::stoi(text, &consumed);
        if (consumed != text.size()) {
            throw std::invalid_argument("trailing characters after number");
        }
        return value;
    } catch (const std::exception&) {
        throw std::runtime_error("Corrupted vault file: " + context);
    }
}

// --- Vault <-> plain-text serialization (same format as Phase 3) ---
// This text is never written to disk directly anymore; it's handed to
// Crypto::encrypt() first. Keeping the inner format unchanged from
// Phase 3 means the serialization logic didn't need to be rewritten,
// only relocated.

std::string serializeVault(const Vault& vault) {
    for (const auto& credential : vault.allCredentials()) {
        checkField(credential.site(), "site");
        checkField(credential.username(), "username");
        checkField(credential.password(), "password");
        checkField(credential.notes(), "notes");
    }

    std::ostringstream out;
    out << kInnerFormatHeader << '\n';
    out << vault.nextId() << '\n';
    for (const auto& credential : vault.allCredentials()) {
        out << credential.id() << kFieldSeparator << credential.site() << kFieldSeparator
            << credential.username() << kFieldSeparator << credential.password() << kFieldSeparator
            << credential.notes() << '\n';
    }
    return out.str();
}

Vault deserializeVault(const std::string& text) {
    std::istringstream in(text);

    std::string header;
    if (!std::getline(in, header)) {
        throw std::runtime_error("Corrupted vault file: missing inner header");
    }
    header = trimTrailingCarriageReturn(header);
    if (header != kInnerFormatHeader) {
        throw std::runtime_error("Corrupted vault file: unrecognized inner format");
    }

    std::string nextIdLine;
    if (!std::getline(in, nextIdLine)) {
        throw std::runtime_error("Corrupted vault file: missing id counter");
    }
    const int nextId = parseInt(trimTrailingCarriageReturn(nextIdLine), "invalid id counter");

    std::vector<Credential> credentials;
    std::string line;
    while (std::getline(in, line)) {
        line = trimTrailingCarriageReturn(line);
        if (line.empty()) {
            continue;
        }

        const auto fields = splitFields(line);
        if (fields.size() != 5) {
            throw std::runtime_error("Corrupted vault file: malformed credential record");
        }

        const int id = parseInt(fields[0], "invalid credential id");
        credentials.emplace_back(id, fields[1], fields[2], fields[3], fields[4]);
    }

    Vault vault;
    vault.loadSnapshot(std::move(credentials), nextId);
    return vault;
}

// --- Binary helpers for the on-disk encrypted container ---
// Lengths are written as big-endian (most significant byte first),
// one byte at a time via explicit shifts rather than memcpy-ing the
// integer's raw bytes. That avoids depending on the host machine's
// endianness or on std::uint32_t having no padding bits - both are
// implementation details memcpy would silently inherit.

void writeUint32(std::ostream& out, std::uint32_t value) {
    const unsigned char bytes[4] = {
        static_cast<unsigned char>((value >> 24) & 0xFF),
        static_cast<unsigned char>((value >> 16) & 0xFF),
        static_cast<unsigned char>((value >> 8) & 0xFF),
        static_cast<unsigned char>(value & 0xFF),
    };
    out.write(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

std::uint32_t readUint32(std::istream& in) {
    unsigned char bytes[4];
    in.read(reinterpret_cast<char*>(bytes), sizeof(bytes));
    if (!in) {
        throw std::runtime_error("Corrupted vault file: unexpected end of file");
    }
    return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
           (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

void writeLengthPrefixed(std::ostream& out, const Crypto::Bytes& data) {
    writeUint32(out, static_cast<std::uint32_t>(data.size()));
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
}

Crypto::Bytes readLengthPrefixed(std::istream& in, std::uint32_t maxLength) {
    const std::uint32_t length = readUint32(in);
    if (length > maxLength) {
        throw std::runtime_error("Corrupted vault file: unreasonable field length");
    }
    Crypto::Bytes data(length);
    if (length > 0) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(length));
        if (!in) {
            throw std::runtime_error("Corrupted vault file: unexpected end of file");
        }
    }
    return data;
}

}  // namespace

void Storage::save(const Vault& vault, const std::filesystem::path& path, const std::string& masterPassword) {
    const std::string serialized = serializeVault(vault);
    const Crypto::EncryptedBlob blob = Crypto::encrypt(serialized, masterPassword);

    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open vault file for writing: " + path.string());
    }

    file.write(kFileMagic.data(), static_cast<std::streamsize>(kFileMagic.size()));
    writeLengthPrefixed(file, blob.salt);
    writeLengthPrefixed(file, blob.nonce);
    writeLengthPrefixed(file, blob.ciphertext);

    if (!file.good()) {
        throw std::runtime_error("Failed while writing vault file: " + path.string());
    }
}

Vault Storage::load(const std::filesystem::path& path, const std::string& masterPassword) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open vault file for reading: " + path.string());
    }

    std::string magic(kFileMagic.size(), '\0');
    file.read(magic.data(), static_cast<std::streamsize>(kFileMagic.size()));
    if (!file || magic != kFileMagic) {
        throw std::runtime_error("Unrecognized vault file format: " + path.string());
    }

    Crypto::EncryptedBlob blob;
    blob.salt = readLengthPrefixed(file, kMaxSaltOrNonceLength);
    blob.nonce = readLengthPrefixed(file, kMaxSaltOrNonceLength);
    blob.ciphertext = readLengthPrefixed(file, kMaxCiphertextLength);

    const std::string serialized = Crypto::decrypt(blob, masterPassword);
    return deserializeVault(serialized);
}
