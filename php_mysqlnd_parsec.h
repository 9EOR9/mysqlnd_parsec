/*
  +----------------------------------------------------------------------+
  | PHP Version 8                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2025 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Georg Richter <georg@mariadb.com>                            |
  +----------------------------------------------------------------------+
*/
#ifndef PHP_MARIADB_PARSEC_PLUGIN_H
#define PHP_MARIADB_PARSEC_PLUGIN_H

#define SHA512_LENGTH 64
#define NONCE_LENGTH 32

#define CHALLENGE_SCRAMBLE_LENGTH 32
#define CHALLENGE_SALT_LENGTH     18
#define ED25519_SIG_LENGTH        64
#define ED25519_KEY_LENGTH        32
#define PBKDF2_HASH_LENGTH        ED25519_KEY_LENGTH
#define CLIENT_RESPONSE_LENGTH    (CHALLENGE_SCRAMBLE_LENGTH + ED25519_SIG_LENGTH)

#define NET_HEADER_SIZE  4


#define PHP_MARIADB_AUTH_PLUGIN_VERSION "0.0.1"

extern zend_module_entry mariadb_auth_plugin_module_entry;
#define phpext_mariadb_auth_plugin_ptr &mariadb_auth_plugin_module_entry

#endif
