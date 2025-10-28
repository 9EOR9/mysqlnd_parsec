PHP_ARG_ENABLE(mysqlnd_parsec, whether to enable parsec authentication for mysqlnd, [ --enable-mysqlnd_parsec Enable MariaDB parsec authentication plugin for mysqlnd ])

if test "$PHP_MYSQLND_PARSEC" != "no"; then
  PKG_PROG_PKG_CONFIG

  dnl Check for libsodium
  PKG_CHECK_MODULES([LIBSODIUM], [libsodium], [], [
    AC_MSG_ERROR([libsodium development files not found. Please install libsodium development files.])
  ])

  PKG_CHECK_MODULES([OPENSSL], [openssl], [], [
    PKG_CHECK_MODULES([OPENSSL], [libssl], [], [
      AC_MSG_ERROR([OpenSSL development files not found. Please install libssl-dev or equivalent.])
    ])
  ])

  PHP_EVAL_INCLINE($OPENSSL_CFLAGS)
  PHP_EVAL_LIBLINE($OPENSSL_LIBS, MYSQLND_PARSEC_SHARED_LIBADD)

  PHP_EVAL_INCLINE($LIBSODIUM_CFLAGS)
  PHP_EVAL_LIBLINE($LIBSODIUM_LIBS, MYSQLND_PARSEC_SHARED_LIBADD)

  PHP_ADD_EXTENSION_DEP(mysqlnd_parsec, mysqlnd, true)
  PHP_ADD_EXTENSION_DEP(mysqlnd_parsec, sodium, true)
  PHP_ADD_EXTENSION_DEP(mysqlnd_parsec, openssl, true)
  PHP_REQUIRE_CXX()
  PHP_ADD_INCLUDE($MYSQLND_DIR/include)
  PHP_NEW_EXTENSION(mysqlnd_parsec, php_mysqlnd_parsec.c, $ext_shared)
  PHP_SUBST(MYSQLND_PARSEC_SHARED_LIBADD)
fi
