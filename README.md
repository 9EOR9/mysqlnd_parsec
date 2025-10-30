# mysqlnd_parsec

A **mysqlnd authentication plugin** providing **parsec-based authentication** for PHP when connecting to MariaDB servers.

## Why?

PARSEC is MariaDB’s modern, secure authentication plugin based on elliptic-curve signatures and PBKDF2 key derivation.
When your PHP connector supports it, it replaces older SHA-1–based password methods with stronger, public-key–style authentication.

## Features

- Drop-in authentication plugin for **mysqlnd**.
- Supports MariaDB servers configured with the `parsec` authentication plugin.

## Requirements

- PHP 8.1 or newer with `mysqlnd`.
- `libsodium` development libraries.
- MariaDB server configured with `parsec` authentication plugin. (version 11.8 or newer)

## Installation

### Normal installation

`mysqlnd_parsec` is usually built and installed automatically when installed through your system’s PHP extension packaging system.

Note: When installed into PHP’s extension directory, `mysqlnd_parsec` is loaded automatically by `mysqlnd`.
You do not need to add `extension=mysqlnd_parsec to your php.ini.

### Building from source

If you cloned the repository or want to build manually:

```bash
phpize
./configure
make
sudo make install
