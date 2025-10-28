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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_auth.h"
#include "ext/mysqlnd/mysqlnd_plugin.h"
#include "ext/mysqlnd/mysqlnd_wireprotocol.h"
#include "php_ini.h"
#include "php_mysqlnd_parsec.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

struct Passwd_in_memory
{
  char algorithm;
  zend_uchar iterations;
  zend_uchar salt[CHALLENGE_SALT_LENGTH];
  zend_uchar pub_key[ED25519_KEY_LENGTH];
};

_Static_assert(sizeof(struct Passwd_in_memory) == 2 + CHALLENGE_SALT_LENGTH
                                                   + ED25519_KEY_LENGTH,
              "Passwd_in_memory should be packed.");

struct Client_signed_response
{
  union {
    struct {
      zend_uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      zend_uchar signature[ED25519_SIG_LENGTH];
    };
    zend_uchar start[1];
  };
};

_Static_assert(sizeof(struct Client_signed_response) == CLIENT_RESPONSE_LENGTH,
              "Client_signed_response should be packed.");


static int compute_derived_key(const char* password, size_t pass_len,
                               const struct Passwd_in_memory *params,
                               zend_uchar *derived_key)
{
  return !PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                            CHALLENGE_SALT_LENGTH,
                            1 << (params->iterations + 10),
                            EVP_sha512(), PBKDF2_HASH_LENGTH, derived_key);
}


static zend_uchar* mariadb_parsec_auth(struct st_mysqlnd_authentication_plugin* self, size_t* auth_data_len,
	MYSQLND_CONN_DATA* conn, const char* const user, const char* const passwd, const size_t passwd_len,
	zend_uchar* auth_plugin_data, const size_t auth_plugin_data_len,
	const MYSQLND_SESSION_OPTIONS* const session_options, const MYSQLND_PFC_DATA* const pfc_data,
	const zend_ulong mysql_flags) {

	union
	{
		struct
		{
			zend_uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
			struct Client_signed_response response;
		};
		zend_uchar start[1];
	} signed_msg;
	_Static_assert(sizeof signed_msg == CHALLENGE_SCRAMBLE_LENGTH
                                     + sizeof(struct Client_signed_response),
                "signed_msg should be packed.");

	zend_uchar *ret;
	zend_uchar buffer[100];
	size_t pkt_len;
	struct Passwd_in_memory params;
	MYSQLND_PFC * pfc = conn->protocol_frame_codec;
	zend_uchar priv_key[ED25519_KEY_LENGTH];
    zend_uchar *packet_no= &pfc->data->packet_no;

    *auth_data_len= 0;
	if (auth_plugin_data_len != CHALLENGE_SCRAMBLE_LENGTH)
    {
	    php_error_docref(NULL, E_WARNING, "received scramble with invalid length");
		return NULL;
    }

    if (!(pfc->data->m.send(pfc, conn->vio, buffer, 0, conn->stats, conn->error_info)))
      return NULL;

    if (FAIL == pfc->data->m.receive(pfc, conn->vio, buffer, NET_HEADER_SIZE + CHALLENGE_SALT_LENGTH + 2, conn->stats, conn->error_info))
      return NULL;

    pkt_len= uint3korr(buffer);
    if (pkt_len != CHALLENGE_SALT_LENGTH + 2)
    {
	    php_error_docref(NULL, E_WARNING, "received scramble with invalid length");
		return NULL;
    }

	memcpy(signed_msg.server_scramble, auth_plugin_data, auth_plugin_data_len);
    memcpy(&params, buffer + NET_HEADER_SIZE, pkt_len);

	if (params.algorithm != 'P')
		return NULL;
	if (params.iterations > 3)
    	return NULL;

	RAND_bytes(signed_msg.response.client_scramble, CHALLENGE_SCRAMBLE_LENGTH);

	if (compute_derived_key(passwd, passwd_len, &params, priv_key))
		return NULL;

	if ((ret= malloc(sizeof signed_msg.response)))
	{
		unsigned long long sig_len;

		/* Construct 64-byte secret key from 32-byte priv_key seed */
		zend_uchar sk[crypto_sign_SECRETKEYBYTES];
		zend_uchar pk[crypto_sign_PUBLICKEYBYTES];

		crypto_sign_seed_keypair(pk, sk, priv_key);

		/* Sign using crypto_sign_detached */
		if (crypto_sign_detached(signed_msg.response.signature, &sig_len,
                         signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH * 2,
                         sk) != 0) {
			free(ret);
			return NULL;
		}
        *packet_no= *packet_no + 1;
		memcpy(ret, signed_msg.response.start, sizeof signed_msg.response);
	    *auth_data_len = sizeof signed_msg.response;
        return ret;
	}

	return NULL;
}

static struct st_mysqlnd_authentication_plugin mariadb_parsec_auth_plugin =
{
	.plugin_header = {
		MYSQLND_PLUGIN_API_VERSION,
		"auth_plugin_parsec",
		PHP_VERSION_ID,
		PHP_MARIADB_AUTH_PLUGIN_VERSION,
		"PHP License 3.01",
		"Georg Richter <georg@mariadb.com>",
		{ NULL, NULL },
		{ NULL },
	},
	.methods = {
		mariadb_parsec_auth,
		NULL
	},
};

PHP_MINIT_FUNCTION(mysqlnd_parsec)
{
	if (mysqlnd_plugin_register_ex((struct st_mysqlnd_plugin_header*)&mariadb_parsec_auth_plugin) == FAIL) {
	  php_error_docref(NULL, E_WARNING, "mysqlnd_plugin_register_ex failed");
	  return FAILURE;
	}
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(mysqlnd_parsec)
{
	return SUCCESS;
}

zend_module_entry mysqlnd_parsec_module_entry = {
	STANDARD_MODULE_HEADER,
	"mysqlnd_parsec",
	NULL,
	PHP_MINIT(mysqlnd_parsec),
	PHP_MSHUTDOWN(mysqlnd_parsec),
	NULL,
	NULL,
	NULL,
	PHP_MARIADB_AUTH_PLUGIN_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MYSQLND_PARSEC
ZEND_GET_MODULE(mysqlnd_parsec)
#endif

/* vim: set noexpandtab tabstop=4 shiftwidth=4: */
