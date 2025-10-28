# mysqlnd_ed25519

A **mysqlnd authentication plugin** providing **parsec-based authentication** for PHP when connecting to MariaDB servers.

## Why?

PHP currently connects to MariaDB servers using `mysql_native_password`, which relies on **SHA1**, a deprecated and insecure algorithm.

**parsec** provides modern, secure, and fast public-key authentication, helping to eliminate SHA1 usage in your PHP–MariaDB connections.

## Features

- Drop-in authentication plugin for **mysqlnd**.
- Supports MariaDB servers configured with the `parsec` authentication plugin.

## Requirements

- PHP 8.1 or newer with `mysqlnd`.
- MariaDB server configured with `parsec` authentication plugin. (version 11.8 or newer)

## Installation

```bash
phpize
./configure
make
sudo make install

