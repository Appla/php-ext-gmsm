#ifndef PHP_GMSM_H
#define PHP_GMSM_H

#define PHP_GMSM_NAME    "gmsm"
#define PHP_GMSM_VERSION "1.0.0"

/* Userland constants (registered from gmsm_arginfo.h via @cvalue) */
#define SM2_FMT_ASN1   0
#define SM2_FMT_C1C3C2 1
#define SM2_FMT_C1C2C3 2
#define SM2_SIG_ASN1   0
#define SM2_SIG_RAW_RS 1

extern zend_module_entry gmsm_module_entry;
#define phpext_gmsm_ptr &gmsm_module_entry

#if defined(ZTS) && defined(COMPILE_DL_GMSM)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif /* PHP_GMSM_H */
