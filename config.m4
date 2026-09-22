PHP_ARG_ENABLE([gmsm],
  [whether to enable GuoMi SM2/SM3/SM4 support],
  [AS_HELP_STRING([--enable-gmsm], [Enable GuoMi SM2/SM3/SM4 support])],
  [yes])

PHP_ARG_WITH([gmsm-openssl],
  [OpenSSL installation prefix for gmsm],
  [AS_HELP_STRING([--with-gmsm-openssl=DIR], [OpenSSL installation prefix])],
  [no],
  [no])

if test "$PHP_GMSM" != "no"; then
  if test "$PHP_GMSM_OPENSSL" != "no" && test "$PHP_GMSM_OPENSSL" != "yes"; then
    if test ! -r "$PHP_GMSM_OPENSSL/include/openssl/evp.h"; then
      AC_MSG_ERROR([OpenSSL headers not found under $PHP_GMSM_OPENSSL/include])
    fi

    gmsm_openssl_libdir=""
    for gmsm_candidate_libdir in \
      "$PHP_GMSM_OPENSSL/lib64" \
      "$PHP_GMSM_OPENSSL/lib" \
      "$PHP_GMSM_OPENSSL/lib/x86_64-linux-gnu" \
      "$PHP_GMSM_OPENSSL/lib/aarch64-linux-gnu"; do
      if test -r "$gmsm_candidate_libdir/libcrypto.so" || test -r "$gmsm_candidate_libdir/libcrypto.a" || test -r "$gmsm_candidate_libdir/libcrypto.dylib"; then
        gmsm_openssl_libdir="$gmsm_candidate_libdir"
        break
      fi
    done
    if test -z "$gmsm_openssl_libdir"; then
      AC_MSG_ERROR([OpenSSL libcrypto not found under $PHP_GMSM_OPENSSL/lib or lib64])
    fi

    OPENSSL_CFLAGS="-I$PHP_GMSM_OPENSSL/include"
    OPENSSL_LIBS="-L$gmsm_openssl_libdir -lcrypto"
  fi

  dnl Same discovery as ext/openssl. The explicit prefix above and the standard
  dnl PKG_CONFIG_PATH / OPENSSL_CFLAGS / OPENSSL_LIBS overrides all feed this path.
  PHP_SETUP_OPENSSL([GMSM_SHARED_LIBADD],
    [AC_DEFINE([HAVE_GMSM], [1], [Whether GuoMi SM2/SM3/SM4 support is present])],
    [AC_MSG_ERROR([ext/gmsm requires OpenSSL 1.1.1+ (libcrypto) discoverable via pkg-config])])

  PHP_NEW_EXTENSION([gmsm], [gmsm.c], [$ext_shared],, [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])
  PHP_ADD_EXTENSION_DEP([gmsm], [openssl], [true])
  PHP_SUBST([GMSM_SHARED_LIBADD])
fi
