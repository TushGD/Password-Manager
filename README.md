# Password Manager

A command-line password manager written in C++20. Your credentials are stored in
one encrypted file, protected by a master password.

This is a learning project, not an audited tool. Don't rely on it for anything
important.

## Features

- Create a vault with a master password
- Add, view, search, update and delete credentials
- Generate random passwords
- Change the master password
- Lock the vault manually, or automatically after 2 minutes of inactivity
- Detects a wrong password or a damaged/tampered vault file

## Build

You need a C++20 compiler, CMake, pkg-config and libsodium.

```bash
# Ubuntu / Debian
sudo apt install build-essential cmake pkg-config libsodium-dev

# Windows (MSYS2 UCRT64 shell)
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
          mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-libsodium
```

```bash
cmake -S . -B build
cmake --build build
```

The first build downloads GoogleTest for the tests. Add `-DBUILD_TESTS=OFF` to skip it.

## Run

```bash
./build/password_manager              # Windows: .\build\password_manager.exe
```

On the first run it asks you to choose a master password. After that it asks for
that password to unlock `data/vault.dat`. Use the numbered menu; option 9 saves
and exits.

Options: `--vault <path>` to use a different vault file, and `--timeout <seconds>`
to change the auto-lock time (0 turns it off).

## Tests

```bash
cd build && ctest
```

## How it is secured

- The master password is turned into a key with Argon2id (libsodium).
- The vault is encrypted and authenticated with libsodium's secretbox
  (XSalsa20-Poly1305), using a new random salt and nonce on every save.
- The master password is never written to disk.
- No cryptography is implemented by hand; everything comes from libsodium.

## Limitations

- The master password is visible while you type it.
- Passwords are held in normal memory while the vault is unlocked.
- Auto-lock is checked only when you enter the next command, not by a timer.
- A crash while saving can corrupt the vault file; there is no backup.
- The vault path `data/vault.dat` is relative to the folder you run the program from.
