/*
 * ext/gmsm: SM2 / SM3 / SM4 for PHP 8.3+, on OpenSSL 1.1.1 or 3.x.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/md5.h" /* make_digest_ex() */
#include "zend_attributes.h"
#include "php_gmsm.h"
#include "gmsm_arginfo.h"

#include <limits.h>
#include <stddef.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
# error "ext/gmsm requires OpenSSL 1.1.1 or later"
#endif
#if defined(OPENSSL_NO_SM2) || defined(OPENSSL_NO_SM3) || defined(OPENSSL_NO_SM4)
# error "ext/gmsm requires an OpenSSL built with SM2, SM3 and SM4 (this one was configured with no-sm2/no-sm3/no-sm4)"
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# define GMSM_OSSL3 1
#else
# define GMSM_OSSL3 0
#endif

#define GMSM_DEFAULT_ID   "1234567812345678" /* GM/T 0009-2012 default user ID */
#define GMSM_MAX_ID_LEN   8190               /* OpenSSL rejects id_len >= UINT16_MAX / 8 */
#define GMSM_MAX_PASS_LEN 1024               /* PEM_BUFSIZE, the password callback's buffer */

/* Raw SM2 ciphertext: C1 = 04 || x || y, C3 = SM3 digest, C2 = masked payload. */
#define GMSM_C1_LEN  65
#define GMSM_C3_LEN  32
#define GMSM_RAW_MIN (GMSM_C1_LEN + GMSM_C3_LEN)

#define GMSM_CT_FMT_ERROR  "must be one of SM2_FMT_ASN1, SM2_FMT_C1C3C2, or SM2_FMT_C1C2C3"
#define GMSM_SIG_FMT_ERROR "must be SM2_SIG_ASN1 or SM2_SIG_RAW_RS"

static const struct {
	const char *name; /* userland name, matched case-insensitively */
	const char *ossl; /* OpenSSL algorithm name */
	size_t iv_len;
} gmsm_sm4_modes[] = {
	{"sm4-cbc", "SM4-CBC", 16},
	{"sm4-ecb", "SM4-ECB", 0},
	{"sm4-ctr", "SM4-CTR", 16},
	{"sm4-cfb", "SM4-CFB", 16},
	{"sm4-ofb", "SM4-OFB", 16},
	{"sm4-gcm", "SM4-GCM", 12},
};
#define GMSM_SM4_MODES (sizeof(gmsm_sm4_modes) / sizeof(gmsm_sm4_modes[0]))
#define GMSM_SM4_GCM   5

/* Set once in MINIT and read-only afterwards, so safe to share between ZTS threads.
 * On OpenSSL 3 these are explicitly fetched: passing legacy EVP_sm3()/EVP_sm4_*() constants
 * makes every Init call repeat the provider fetch. */
static zend_class_entry *gmsm_pkey_ce; /* ext/openssl's OpenSSLAsymmetricKey, or NULL */
static const EVP_MD *gmsm_sm3;
static const EVP_CIPHER *gmsm_sm4[GMSM_SM4_MODES];

/* Layout of ext/openssl's php_openssl_pkey_object (PHP 8.0+). ext/openssl exports no accessor,
 * so we mirror it; gmsm_get_key() checks the class identity and handlers->offset before use. */
typedef struct {
	EVP_PKEY *pkey;
	bool is_private;
	zend_object std;
} gmsm_openssl_pkey;

/* SEQUENCE { x INTEGER, y INTEGER, hash OCTET STRING, cipher OCTET STRING } (GM/T 0009) */
typedef struct {
	ASN1_INTEGER *x;
	ASN1_INTEGER *y;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *cipher;
} GMSM_CIPHERTEXT;

ASN1_SEQUENCE(GMSM_CIPHERTEXT) = {
	ASN1_SIMPLE(GMSM_CIPHERTEXT, x, ASN1_INTEGER),
	ASN1_SIMPLE(GMSM_CIPHERTEXT, y, ASN1_INTEGER),
	ASN1_SIMPLE(GMSM_CIPHERTEXT, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(GMSM_CIPHERTEXT, cipher, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(GMSM_CIPHERTEXT)

IMPLEMENT_ASN1_FUNCTIONS(GMSM_CIPHERTEXT)

/* ========================================================================= */
/* Keys                                                                      */
/* ========================================================================= */

/* Non-interactive: a missing passphrase fails instead of prompting on the terminal. */
static int gmsm_pem_pass_cb(char *buf, int size, int rwflag, void *u)
{
	const zend_string *pass = u;
	(void)rwflag;
	if (!pass || ZSTR_LEN(pass) > (size_t)size) {
		return pass ? -1 : 0;
	}
	memcpy(buf, ZSTR_VAL(pass), ZSTR_LEN(pass));
	return (int)ZSTR_LEN(pass);
}

/* Take the contents of a memory BIO and empty it for reuse. */
static zend_string *gmsm_bio_str(BIO *bio)
{
	char *data;
	long len = BIO_get_mem_data(bio, &data);
	zend_string *s = zend_string_init(data, len, 0);
	(void)BIO_reset(bio);
	return s;
}

/* Consumes pkey. Returns a key usable for SM2 operations, or NULL if it is not on the SM2 curve. */
static EVP_PKEY *gmsm_to_sm2(EVP_PKEY *pkey)
{
	EVP_PKEY *sm2 = NULL;
#if GMSM_OSSL3
	char group[16];

	if (EVP_PKEY_is_a(pkey, "SM2")) {
		return pkey;
	}
	/* An "EC"-typed key on the SM2 curve (e.g. from openssl_pkey_new()) has no SM2 operations:
	 * re-import it into the SM2 key manager. */
	if (EVP_PKEY_is_a(pkey, "EC")
			&& EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), NULL)
			&& strcasecmp(group, "SM2") == 0) {
		OSSL_PARAM *params = NULL;
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
		if (ctx && EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params) > 0 && EVP_PKEY_fromdata_init(ctx) > 0) {
			EVP_PKEY_fromdata(ctx, &sm2, EVP_PKEY_KEYPAIR, params);
		}
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
	}
#else
	if (EVP_PKEY_id(pkey) == EVP_PKEY_SM2) {
		return pkey;
	}
	const EC_KEY *ec = EVP_PKEY_base_id(pkey) == EVP_PKEY_EC ? EVP_PKEY_get0_EC_KEY(pkey) : NULL;
	if (ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) == NID_sm2) {
		/* Alias a fresh wrapper, never the caller's EVP_PKEY: it may belong to an OpenSSLAsymmetricKey. */
		sm2 = EVP_PKEY_new();
		if (sm2 && (!EVP_PKEY_set1_EC_KEY(sm2, (EC_KEY *)ec) || !EVP_PKEY_set_alias_type(sm2, EVP_PKEY_SM2))) {
			EVP_PKEY_free(sm2);
			sm2 = NULL;
		}
	}
#endif
	EVP_PKEY_free(pkey);
	return sm2;
}

/* Decode a PEM or DER key with narrow format-specific paths. On OpenSSL 3.0 every decoder attempt
 * costs ~300us whether it succeeds or not, so broad trial-and-error ladders are expensive. */
static EVP_PKEY *gmsm_load_key(const char *data, size_t len, bool need_private, zend_string *pass)
{
	const char *end = data + len;
	EVP_PKEY *pkey = NULL;

	ERR_set_mark();
	if (zend_memnstr(data, "-----BEGIN ", sizeof("-----BEGIN ") - 1, end)) {
		BIO *bio = BIO_new_mem_buf(data, (int)len);
		if (bio && !need_private && zend_memnstr(data, "-----BEGIN PUBLIC KEY-----", sizeof("-----BEGIN PUBLIC KEY-----") - 1, end)) {
			/* Base64-decode the block ourselves: ~3x faster than PEM_read_bio_PUBKEY() on OpenSSL 3. */
			char *name = NULL, *header = NULL;
			unsigned char *der = NULL;
			long der_len = 0;
			while (!pkey && PEM_read_bio(bio, &name, &header, &der, &der_len)) {
				if (strcmp(name, PEM_STRING_PUBLIC) == 0) {
					const unsigned char *p = der;
					pkey = d2i_PUBKEY(NULL, &p, der_len);
				}
				OPENSSL_free(name);
				OPENSSL_free(header);
				OPENSSL_free(der);
			}
		} else if (bio) {
			/* PKCS#8 (plain or encrypted) and SEC1 "EC PRIVATE KEY" */
			pkey = PEM_read_bio_PrivateKey(bio, NULL, gmsm_pem_pass_cb, pass);
		}
		BIO_free(bio);
	} else {
		const unsigned char *p = (const unsigned char *)data;
		if (!need_private) {
			pkey = d2i_PUBKEY(NULL, &p, (long)len); /* fails in <1us on non-SPKI input */
		}
		if (!pkey && pass) {
			/* d2i_PrivateKey() cannot decrypt PKCS#8. Decode the encrypted wrapper explicitly
			 * so a successful parse must consume the complete input. */
			const unsigned char *q = (const unsigned char *)data;
			X509_SIG *p8 = d2i_X509_SIG(NULL, &q, (long)len);
			if (p8) {
				if (q == (const unsigned char *)end) {
					PKCS8_PRIV_KEY_INFO *plain = PKCS8_decrypt(p8, ZSTR_VAL(pass), (int)ZSTR_LEN(pass));
					if (plain) {
						pkey = EVP_PKCS82PKEY(plain);
						PKCS8_PRIV_KEY_INFO_free(plain);
						if (pkey) {
							p = q;
						}
					}
				}
				X509_SIG_free(p8);
			}
		}
		if (!pkey) {
			/* PKCS#8 or SEC1. d2i_AutoPrivateKey() tries every decoder and is ~4x slower on 3.0. */
			p = (const unsigned char *)data;
			pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)len);
		}
		if (pkey && p != (const unsigned char *)end) { /* trailing bytes */
			EVP_PKEY_free(pkey);
			pkey = NULL;
		}
	}
	/* Decoder fallbacks can report errors even when a later format succeeds.
	 * Keep diagnostics if no format worked. */
	if (pkey) {
		ERR_pop_to_mark();
	} else {
		ERR_clear_last_mark();
	}
	return pkey;
}

/*
 * Accepts a PEM/DER string, an OpenSSLAsymmetricKey, or (allow_array) [$key, $passphrase] /
 * ['key' => ..., 'passphrase' => ...]. Returns an owned SM2 key, or NULL after raising a
 * warning or an exception.
 */
static EVP_PKEY *gmsm_get_key(zval *zv, bool need_private, bool allow_array, uint32_t arg)
{
	zend_string *pass = NULL;
	EVP_PKEY *pkey = NULL;

	if (Z_TYPE_P(zv) == IS_ARRAY && allow_array) {
		HashTable *ht = Z_ARRVAL_P(zv);
		zval *pz = zend_hash_index_find(ht, 1);
		if (!pz) {
			pz = zend_hash_str_find(ht, ZEND_STRL("passphrase"));
		}
		zv = zend_hash_index_find(ht, 0);
		if (!zv) {
			zv = zend_hash_str_find(ht, ZEND_STRL("key"));
		}
		if (!zv) {
			zend_argument_value_error(arg, "must contain the key at index 0 or \"key\"");
			return NULL;
		}
		ZVAL_DEREF(zv);
		if (pz) {
			ZVAL_DEREF(pz);
			if (Z_TYPE_P(pz) != IS_STRING) {
				zend_argument_type_error(arg, "passphrase must be of type string, %s given", zend_zval_value_name(pz));
				return NULL;
			}
			if (Z_STRLEN_P(pz) > GMSM_MAX_PASS_LEN) {
				zend_argument_value_error(arg, "passphrase must be at most %d bytes", GMSM_MAX_PASS_LEN);
				return NULL;
			}
			pass = Z_STR_P(pz);
		}
	}

	if (Z_TYPE_P(zv) == IS_STRING) {
		if (Z_STRLEN_P(zv) > INT_MAX) {
			zend_argument_value_error(arg, "is too long");
			return NULL;
		}
		pkey = gmsm_load_key(Z_STRVAL_P(zv), Z_STRLEN_P(zv), need_private, pass);
		if (!pkey) {
			php_error_docref(NULL, E_WARNING, "Argument #%u could not be decoded as %s key",
				arg, need_private ? "a private" : "a public or private");
			return NULL;
		}
	} else if (Z_TYPE_P(zv) == IS_OBJECT && gmsm_pkey_ce && Z_OBJCE_P(zv) == gmsm_pkey_ce) {
		zend_object *obj = Z_OBJ_P(zv);
		if (obj->handlers->offset != offsetof(gmsm_openssl_pkey, std)) {
			zend_throw_error(NULL, "This build of ext/gmsm does not match the loaded ext/openssl");
			return NULL;
		}
		gmsm_openssl_pkey *k = (gmsm_openssl_pkey *)((char *)obj - offsetof(gmsm_openssl_pkey, std));
		if (need_private && !k->is_private) {
			zend_argument_value_error(arg, "must be a private key");
			return NULL;
		}
		pkey = k->pkey;
		EVP_PKEY_up_ref(pkey);
	} else {
		zend_argument_type_error(arg, allow_array
				? "must be of type OpenSSLAsymmetricKey|array|string, %s given"
				: "must be of type OpenSSLAsymmetricKey|string, %s given",
			zend_zval_value_name(zv));
		return NULL;
	}

	pkey = gmsm_to_sm2(pkey);
	if (!pkey) {
		zend_argument_value_error(arg, "must be an SM2 key");
	}
	return pkey;
}

/* ========================================================================= */
/* Codecs. These are purely syntactic; point and scalar validity are checked */
/* by OpenSSL's SM2 decrypt/verify (SM2's cofactor is 1, so on-curve suffices) */
/* ========================================================================= */

static zend_string *gmsm_der_to_raw(const unsigned char *der, size_t len, bool c1c2c3)
{
	const unsigned char *p = der;
	GMSM_CIPHERTEXT *c = d2i_GMSM_CIPHERTEXT(NULL, &p, (long)len);
	BIGNUM *x = NULL, *y = NULL;
	zend_string *out = NULL;

	/* p != end also rejects inputs whose length did not survive the cast to long */
	if (c && p == der + len
			&& (x = ASN1_INTEGER_to_BN(c->x, NULL)) && (y = ASN1_INTEGER_to_BN(c->y, NULL))
			&& !BN_is_negative(x) && !BN_is_negative(y) && c->hash->length == GMSM_C3_LEN) {
		size_t c2_len = (size_t)c->cipher->length;
		out = zend_string_alloc(GMSM_RAW_MIN + c2_len, 0);
		unsigned char *o = (unsigned char *)ZSTR_VAL(out);
		o[0] = 0x04;
		if (BN_bn2binpad(x, o + 1, 32) != 32 || BN_bn2binpad(y, o + 33, 32) != 32) {
			zend_string_efree(out);
			out = NULL;
		} else {
			memcpy(o + (c1c2c3 ? GMSM_C1_LEN + c2_len : GMSM_C1_LEN), c->hash->data, GMSM_C3_LEN);
			if (c2_len) {
				memcpy(o + (c1c2c3 ? GMSM_C1_LEN : GMSM_RAW_MIN), c->cipher->data, c2_len);
			}
			o[GMSM_RAW_MIN + c2_len] = '\0';
		}
	}
	BN_free(x);
	BN_free(y);
	GMSM_CIPHERTEXT_free(c);
	return out;
}

static zend_string *gmsm_raw_to_der(const unsigned char *raw, size_t len, bool c1c2c3)
{
	if (len < GMSM_RAW_MIN || raw[0] != 0x04 || len - GMSM_RAW_MIN > INT_MAX) {
		return NULL;
	}
	size_t c2_len = len - GMSM_RAW_MIN;
	const unsigned char *c3 = raw + (c1c2c3 ? GMSM_C1_LEN + c2_len : GMSM_C1_LEN);
	const unsigned char *c2 = raw + (c1c2c3 ? GMSM_C1_LEN : GMSM_RAW_MIN);
	GMSM_CIPHERTEXT *c = GMSM_CIPHERTEXT_new();
	BIGNUM *x = BN_bin2bn(raw + 1, 32, NULL);
	BIGNUM *y = BN_bin2bn(raw + 33, 32, NULL);
	zend_string *out = NULL;
	int der_len;

	if (c && x && y
			&& BN_to_ASN1_INTEGER(x, c->x) && BN_to_ASN1_INTEGER(y, c->y)
			&& ASN1_OCTET_STRING_set(c->hash, c3, GMSM_C3_LEN)
			&& ASN1_OCTET_STRING_set(c->cipher, c2, (int)c2_len)
			&& (der_len = i2d_GMSM_CIPHERTEXT(c, NULL)) > 0) {
		out = zend_string_alloc(der_len, 0);
		unsigned char *p = (unsigned char *)ZSTR_VAL(out);
		i2d_GMSM_CIPHERTEXT(c, &p);
		ZSTR_VAL(out)[der_len] = '\0';
	}
	BN_free(x);
	BN_free(y);
	GMSM_CIPHERTEXT_free(c);
	return out;
}

/* C1C3C2 <-> C1C2C3: move the 32-byte C3 block to the other side of C2. */
static zend_string *gmsm_raw_swap(const unsigned char *raw, size_t len, bool from_c1c2c3)
{
	if (len < GMSM_RAW_MIN || raw[0] != 0x04) {
		return NULL;
	}
	size_t c2_len = len - GMSM_RAW_MIN;
	zend_string *out = zend_string_alloc(len, 0);
	unsigned char *o = (unsigned char *)ZSTR_VAL(out);

	memcpy(o, raw, GMSM_C1_LEN);
	if (from_c1c2c3) {
		memcpy(o + GMSM_C1_LEN, raw + GMSM_C1_LEN + c2_len, GMSM_C3_LEN);
		memcpy(o + GMSM_RAW_MIN, raw + GMSM_C1_LEN, c2_len);
	} else {
		memcpy(o + GMSM_C1_LEN, raw + GMSM_RAW_MIN, c2_len);
		memcpy(o + GMSM_C1_LEN + c2_len, raw + GMSM_C1_LEN, GMSM_C3_LEN);
	}
	o[len] = '\0';
	return out;
}

static zend_string *gmsm_sig_der_to_raw(const unsigned char *der, size_t len)
{
	const unsigned char *p = der;
	ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)len);
	zend_string *out = NULL;

	if (sig && p == der + len) {
		const BIGNUM *r, *s;
		ECDSA_SIG_get0(sig, &r, &s);
		out = zend_string_alloc(64, 0);
		unsigned char *o = (unsigned char *)ZSTR_VAL(out);
		if (BN_is_negative(r) || BN_is_negative(s) || BN_bn2binpad(r, o, 32) != 32 || BN_bn2binpad(s, o + 32, 32) != 32) {
			zend_string_efree(out);
			out = NULL;
		} else {
			o[64] = '\0';
		}
	}
	ECDSA_SIG_free(sig);
	return out;
}

static zend_string *gmsm_sig_raw_to_der(const unsigned char *raw, size_t len)
{
	if (len != 64) {
		return NULL;
	}
	ECDSA_SIG *sig = ECDSA_SIG_new();
	BIGNUM *r = BN_bin2bn(raw, 32, NULL);
	BIGNUM *s = BN_bin2bn(raw + 32, 32, NULL);
	zend_string *out = NULL;
	int der_len;

	if (sig && r && s && ECDSA_SIG_set0(sig, r, s)) {
		r = s = NULL; /* now owned by sig */
		if ((der_len = i2d_ECDSA_SIG(sig, NULL)) > 0) {
			out = zend_string_alloc(der_len, 0);
			unsigned char *p = (unsigned char *)ZSTR_VAL(out);
			i2d_ECDSA_SIG(sig, &p);
			ZSTR_VAL(out)[der_len] = '\0';
		}
	}
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(sig);
	return out;
}

/* ========================================================================= */
/* SM2                                                                       */
/* ========================================================================= */

/*
 * Digest context for SM2 sign/verify with the user ID applied (NULL id = GM/T 0009 default;
 * OpenSSL 3 would otherwise use an empty ID). The ID is set on a caller-owned EVP_PKEY_CTX
 * before init, which both 1.1.1 and 3.x honour. Free the MD ctx first, then *pctx.
 */
static EVP_MD_CTX *gmsm_sm2_md_ctx(EVP_PKEY *pkey, const zend_string *id, bool verify, EVP_PKEY_CTX **pctx)
{
	const char *id_val = id ? ZSTR_VAL(id) : GMSM_DEFAULT_ID;
	int id_len = id ? (int)ZSTR_LEN(id) : (int)sizeof(GMSM_DEFAULT_ID) - 1;
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	*pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (md && *pctx && EVP_PKEY_CTX_set1_id(*pctx, id_val, id_len) > 0) {
		EVP_MD_CTX_set_pkey_ctx(md, *pctx);
		if ((verify
				? EVP_DigestVerifyInit(md, NULL, gmsm_sm3, NULL, pkey)
				: EVP_DigestSignInit(md, NULL, gmsm_sm3, NULL, pkey)) > 0) {
			return md;
		}
	}
	EVP_MD_CTX_free(md);
	EVP_PKEY_CTX_free(*pctx);
	*pctx = NULL;
	return NULL;
}

PHP_FUNCTION(sm2_keygen)
{
	zend_string *pass = NULL;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR_OR_NULL(pass)
	ZEND_PARSE_PARAMETERS_END();

	/* "" would silently produce an unencrypted key */
	if (pass && (ZSTR_LEN(pass) == 0 || ZSTR_LEN(pass) > GMSM_MAX_PASS_LEN)) {
		zend_argument_value_error(1, "must be between 1 and %d bytes, or null", GMSM_MAX_PASS_LEN);
		RETURN_THROWS();
	}

	/* An EC key on the SM2 curve serialises exactly like an "SM2"-typed one (id-ecPublicKey +
	 * curve OID 1.2.156.10197.1.301), so this single path serves both OpenSSL lines. */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	bool ok = ctx && EVP_PKEY_keygen_init(ctx) > 0
		&& EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) > 0
		&& EVP_PKEY_keygen(ctx, &pkey) > 0;
	EVP_PKEY_CTX_free(ctx);

	zend_string *priv = NULL, *pub = NULL;
	BIO *bio = ok ? BIO_new(BIO_s_mem()) : NULL;
	if (bio && PEM_write_bio_PKCS8PrivateKey(bio, pkey, pass ? EVP_aes_256_cbc() : NULL,
			pass ? ZSTR_VAL(pass) : NULL, pass ? (int)ZSTR_LEN(pass) : 0, NULL, NULL)) {
		priv = gmsm_bio_str(bio);
		if (PEM_write_bio_PUBKEY(bio, pkey)) {
			pub = gmsm_bio_str(bio);
		}
	}
	BIO_free(bio);
	EVP_PKEY_free(pkey);

	if (!pub) {
		if (priv) {
			zend_string_efree(priv);
		}
		RETURN_FALSE;
	}
	array_init_size(return_value, 2);
	add_assoc_str(return_value, "private_key", priv);
	add_assoc_str(return_value, "public_key", pub);
}

PHP_FUNCTION(sm2_encrypt)
{
	zend_string *data;
	zval *key;
	zend_long format = SM2_FMT_C1C3C2;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STR(data)
		Z_PARAM_ZVAL(key)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(format)
	ZEND_PARSE_PARAMETERS_END();

	if (format < SM2_FMT_ASN1 || format > SM2_FMT_C1C2C3) {
		zend_argument_value_error(3, GMSM_CT_FMT_ERROR);
		RETURN_THROWS();
	}
	if (ZSTR_LEN(data) == 0) { /* OpenSSL cannot encrypt an empty message */
		zend_argument_value_error(1, "must not be empty");
		RETURN_THROWS();
	}

	EVP_PKEY *pkey = gmsm_get_key(key, false, false, 2);
	if (!pkey) {
		RETURN_FALSE;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	zend_string *der = NULL;
	size_t len = 0;
	if (ctx && EVP_PKEY_encrypt_init(ctx) > 0
			&& EVP_PKEY_encrypt(ctx, NULL, &len, (const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data)) > 0) {
		der = zend_string_alloc(len, 0);
		if (EVP_PKEY_encrypt(ctx, (unsigned char *)ZSTR_VAL(der), &len, (const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data)) > 0) {
			ZSTR_LEN(der) = len;
			ZSTR_VAL(der)[len] = '\0';
		} else {
			zend_string_efree(der);
			der = NULL;
		}
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (!der) {
		RETURN_FALSE;
	}
	if (format == SM2_FMT_ASN1) {
		RETURN_NEW_STR(der);
	}
	zend_string *raw = gmsm_der_to_raw((const unsigned char *)ZSTR_VAL(der), ZSTR_LEN(der), format == SM2_FMT_C1C2C3);
	zend_string_efree(der);
	if (!raw) {
		RETURN_FALSE;
	}
	RETURN_NEW_STR(raw);
}

PHP_FUNCTION(sm2_decrypt)
{
	zend_string *data, *der = NULL;
	zval *key;
	zend_long format = SM2_FMT_C1C3C2;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STR(data)
		Z_PARAM_ZVAL(key)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(format)
	ZEND_PARSE_PARAMETERS_END();

	if (format < SM2_FMT_ASN1 || format > SM2_FMT_C1C2C3) {
		zend_argument_value_error(3, GMSM_CT_FMT_ERROR);
		RETURN_THROWS();
	}
	if (format != SM2_FMT_ASN1) {
		der = gmsm_raw_to_der((const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data), format == SM2_FMT_C1C2C3);
		if (!der) {
			RETURN_FALSE;
		}
		data = der;
	}

	EVP_PKEY *pkey = gmsm_get_key(key, true, true, 2);
	EVP_PKEY_CTX *ctx = pkey ? EVP_PKEY_CTX_new(pkey, NULL) : NULL;
	zend_string *out = NULL;
	/* The plaintext is always shorter than its ciphertext, so the input length is a safe bound.
	 * This skips OpenSSL's size query, which parses the DER a second time and under-reports
	 * before 1.1.1l (CVE-2021-3711). */
	size_t len = ZSTR_LEN(data);
	if (ctx && EVP_PKEY_decrypt_init(ctx) > 0) {
		out = zend_string_alloc(len, 0);
		if (EVP_PKEY_decrypt(ctx, (unsigned char *)ZSTR_VAL(out), &len, (const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data)) > 0) {
			ZSTR_LEN(out) = len;
			ZSTR_VAL(out)[len] = '\0';
		} else {
			zend_string_efree(out);
			out = NULL;
		}
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	if (der) {
		zend_string_efree(der);
	}
	if (!out) {
		RETURN_FALSE;
	}
	RETURN_NEW_STR(out);
}

PHP_FUNCTION(sm2_sign)
{
	zend_string *data, *id = NULL;
	zval *key;
	zend_long format = SM2_SIG_ASN1;

	ZEND_PARSE_PARAMETERS_START(2, 4)
		Z_PARAM_STR(data)
		Z_PARAM_ZVAL(key)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR_OR_NULL(id)
		Z_PARAM_LONG(format)
	ZEND_PARSE_PARAMETERS_END();

	if (id && ZSTR_LEN(id) > GMSM_MAX_ID_LEN) {
		zend_argument_value_error(3, "must be at most %d bytes", GMSM_MAX_ID_LEN);
		RETURN_THROWS();
	}
	if (format != SM2_SIG_ASN1 && format != SM2_SIG_RAW_RS) {
		zend_argument_value_error(4, GMSM_SIG_FMT_ERROR);
		RETURN_THROWS();
	}

	EVP_PKEY *pkey = gmsm_get_key(key, true, true, 2);
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *md = pkey ? gmsm_sm2_md_ctx(pkey, id, false, &pctx) : NULL;
	zend_string *sig = NULL;
	if (md) {
		size_t len = (size_t)EVP_PKEY_size(pkey);
		sig = zend_string_alloc(len, 0);
		if (EVP_DigestSign(md, (unsigned char *)ZSTR_VAL(sig), &len, (const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data)) > 0) {
			ZSTR_LEN(sig) = len;
			ZSTR_VAL(sig)[len] = '\0';
		} else {
			zend_string_efree(sig);
			sig = NULL;
		}
	}
	EVP_MD_CTX_free(md);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);

	if (!sig) {
		RETURN_FALSE;
	}
	if (format == SM2_SIG_ASN1) {
		RETURN_NEW_STR(sig);
	}
	zend_string *raw = gmsm_sig_der_to_raw((const unsigned char *)ZSTR_VAL(sig), ZSTR_LEN(sig));
	zend_string_efree(sig);
	if (!raw) {
		RETURN_FALSE;
	}
	RETURN_NEW_STR(raw);
}

PHP_FUNCTION(sm2_verify)
{
	zend_string *data, *sig, *id = NULL, *der = NULL;
	zval *key;
	zend_long format = SM2_SIG_ASN1;

	ZEND_PARSE_PARAMETERS_START(3, 5)
		Z_PARAM_STR(data)
		Z_PARAM_STR(sig)
		Z_PARAM_ZVAL(key)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR_OR_NULL(id)
		Z_PARAM_LONG(format)
	ZEND_PARSE_PARAMETERS_END();

	if (id && ZSTR_LEN(id) > GMSM_MAX_ID_LEN) {
		zend_argument_value_error(4, "must be at most %d bytes", GMSM_MAX_ID_LEN);
		RETURN_THROWS();
	}
	if (format != SM2_SIG_ASN1 && format != SM2_SIG_RAW_RS) {
		zend_argument_value_error(5, GMSM_SIG_FMT_ERROR);
		RETURN_THROWS();
	}
	if (format == SM2_SIG_RAW_RS) {
		der = gmsm_sig_raw_to_der((const unsigned char *)ZSTR_VAL(sig), ZSTR_LEN(sig));
		if (!der) {
			RETURN_FALSE;
		}
		sig = der;
	}

	EVP_PKEY *pkey = gmsm_get_key(key, false, false, 3);
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *md = pkey ? gmsm_sm2_md_ctx(pkey, id, true, &pctx) : NULL;
	bool ok = md && EVP_DigestVerify(md, (const unsigned char *)ZSTR_VAL(sig), ZSTR_LEN(sig),
		(const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data)) == 1;

	EVP_MD_CTX_free(md);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);
	if (der) {
		zend_string_efree(der);
	}
	RETURN_BOOL(ok);
}

PHP_FUNCTION(sm2_pkey_get_details)
{
	zval *key;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_ZVAL(key)
	ZEND_PARSE_PARAMETERS_END();

	EVP_PKEY *pkey = gmsm_get_key(key, false, true, 1);
	if (!pkey) {
		RETURN_FALSE;
	}

	unsigned char xy[64], d[32];
	bool ok, has_d;
#if GMSM_OSSL3
	/* Not OSSL_PKEY_PARAM_EC_PUB_X/Y: OpenSSL 3.0 fails those for decoded SM2 private keys.
	 * The encoded public key is always the uncompressed 04 || x || y. */
	unsigned char *pub = NULL;
	BIGNUM *bd = NULL;
	ok = EVP_PKEY_get1_encoded_public_key(pkey, &pub) == 65 && pub[0] == 0x04;
	if (ok) {
		memcpy(xy, pub + 1, 64);
	}
	OPENSSL_free(pub);
	ERR_set_mark(); /* a public key has no PRIV_KEY; that is not an error */
	has_d = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bd) && BN_bn2binpad(bd, d, 32) == 32;
	ERR_pop_to_mark();
	BN_clear_free(bd);
#else
	/* EVP_PKEY_get0_EC_KEY() refuses SM2-aliased keys; EVP_PKEY_get0() does not. */
	const EC_KEY *ec = EVP_PKEY_get0(pkey);
	const EC_POINT *pub = ec ? EC_KEY_get0_public_key(ec) : NULL;
	const BIGNUM *bd = ec ? EC_KEY_get0_private_key(ec) : NULL;
	unsigned char oct[65];
	ok = pub && EC_POINT_point2oct(EC_KEY_get0_group(ec), pub, POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), NULL) == sizeof(oct);
	if (ok) {
		memcpy(xy, oct + 1, 64);
	}
	has_d = bd && BN_bn2binpad(bd, d, 32) == 32;
#endif

	zend_string *pem = NULL;
	BIO *bio = ok ? BIO_new(BIO_s_mem()) : NULL;
	if (bio && PEM_write_bio_PUBKEY(bio, pkey)) {
		pem = gmsm_bio_str(bio);
	}
	BIO_free(bio);
	EVP_PKEY_free(pkey);

	if (pem) {
		zval sm2;
		array_init_size(&sm2, 3);
		add_assoc_stringl(&sm2, "x", (char *)xy, 32);
		add_assoc_stringl(&sm2, "y", (char *)xy + 32, 32);
		if (has_d) {
			add_assoc_stringl(&sm2, "d", (char *)d, 32);
		}
		array_init_size(return_value, 4);
		add_assoc_long(return_value, "bits", 256);
		add_assoc_str(return_value, "key", pem);
		add_assoc_string(return_value, "type", "sm2");
		add_assoc_zval(return_value, "sm2", &sm2);
	} else {
		RETVAL_FALSE;
	}
	OPENSSL_cleanse(d, sizeof(d));
}

PHP_FUNCTION(sm2_cipher_convert)
{
	zend_string *data;
	zend_long from, to;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(data)
		Z_PARAM_LONG(from)
		Z_PARAM_LONG(to)
	ZEND_PARSE_PARAMETERS_END();

	if (from < SM2_FMT_ASN1 || from > SM2_FMT_C1C2C3) {
		zend_argument_value_error(2, GMSM_CT_FMT_ERROR);
		RETURN_THROWS();
	}
	if (to < SM2_FMT_ASN1 || to > SM2_FMT_C1C2C3) {
		zend_argument_value_error(3, GMSM_CT_FMT_ERROR);
		RETURN_THROWS();
	}
	if (from == to) {
		RETURN_STR_COPY(data);
	}

	const unsigned char *in = (const unsigned char *)ZSTR_VAL(data);
	size_t len = ZSTR_LEN(data);
	zend_string *out = from == SM2_FMT_ASN1 ? gmsm_der_to_raw(in, len, to == SM2_FMT_C1C2C3)
		: to == SM2_FMT_ASN1 ? gmsm_raw_to_der(in, len, from == SM2_FMT_C1C2C3)
		: gmsm_raw_swap(in, len, from == SM2_FMT_C1C2C3);
	if (!out) {
		RETURN_FALSE;
	}
	RETURN_NEW_STR(out);
}

PHP_FUNCTION(sm2_sig_convert)
{
	zend_string *sig;
	zend_long from, to;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STR(sig)
		Z_PARAM_LONG(from)
		Z_PARAM_LONG(to)
	ZEND_PARSE_PARAMETERS_END();

	if (from != SM2_SIG_ASN1 && from != SM2_SIG_RAW_RS) {
		zend_argument_value_error(2, GMSM_SIG_FMT_ERROR);
		RETURN_THROWS();
	}
	if (to != SM2_SIG_ASN1 && to != SM2_SIG_RAW_RS) {
		zend_argument_value_error(3, GMSM_SIG_FMT_ERROR);
		RETURN_THROWS();
	}
	if (from == to) {
		RETURN_STR_COPY(sig);
	}

	zend_string *out = from == SM2_SIG_ASN1
		? gmsm_sig_der_to_raw((const unsigned char *)ZSTR_VAL(sig), ZSTR_LEN(sig))
		: gmsm_sig_raw_to_der((const unsigned char *)ZSTR_VAL(sig), ZSTR_LEN(sig));
	if (!out) {
		RETURN_FALSE;
	}
	RETURN_NEW_STR(out);
}

/* ========================================================================= */
/* SM3                                                                       */
/* ========================================================================= */

static void gmsm_return_digest(zval *return_value, const unsigned char *md, bool binary)
{
	if (binary) {
		RETVAL_STRINGL((const char *)md, 32);
		return;
	}
	zend_string *hex = zend_string_alloc(64, 0);
	make_digest_ex(ZSTR_VAL(hex), md, 32);
	RETVAL_NEW_STR(hex);
}

PHP_FUNCTION(sm3)
{
	zend_string *data;
	bool binary = false;
	unsigned char md[32];

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(data)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(binary)
	ZEND_PARSE_PARAMETERS_END();
	if (!gmsm_sm3) {
		zend_throw_error(NULL, "SM3 is not available in the linked OpenSSL");
		RETURN_THROWS();
	}

	if (!EVP_Digest(ZSTR_VAL(data), ZSTR_LEN(data), md, NULL, gmsm_sm3, NULL)) {
		zend_throw_error(NULL, "SM3 digest failed");
		RETURN_THROWS();
	}
	gmsm_return_digest(return_value, md, binary);
}

PHP_FUNCTION(sm3_hmac)
{
	zend_string *data, *key;
	bool binary = false;
	unsigned char md[32];

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STR(data)
		Z_PARAM_STR(key)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(binary)
	ZEND_PARSE_PARAMETERS_END();
	if (!gmsm_sm3) {
		zend_throw_error(NULL, "SM3 is not available in the linked OpenSSL");
		RETURN_THROWS();
	}

	if (ZSTR_LEN(key) > INT_MAX) {
		zend_argument_value_error(2, "is too long");
		RETURN_THROWS();
	}
	if (!HMAC(gmsm_sm3, ZSTR_VAL(key), (int)ZSTR_LEN(key), (const unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data), md, NULL)) {
		zend_throw_error(NULL, "SM3 HMAC failed");
		RETURN_THROWS();
	}
	gmsm_return_digest(return_value, md, binary);
}

/* ========================================================================= */
/* SM4                                                                       */
/* ========================================================================= */

/* Shared body of sm4_encrypt()/sm4_decrypt(); they differ only in how $tag is passed. */
static void gmsm_sm4_crypt(zval *return_value, int enc, zend_string *data, zend_string *key, zend_string *iv,
		zend_string *mode, zend_string *aad, zval *tag_out, zend_string *tag_in)
{
	size_t m = 0; /* default: sm4-cbc */
	if (mode) {
		while (m < GMSM_SM4_MODES && zend_binary_strcasecmp(ZSTR_VAL(mode), ZSTR_LEN(mode),
				gmsm_sm4_modes[m].name, strlen(gmsm_sm4_modes[m].name)) != 0) {
			m++;
		}
		if (m == GMSM_SM4_MODES) {
			zend_argument_value_error(4, "must be one of sm4-cbc, sm4-ecb, sm4-ctr, sm4-cfb, sm4-ofb, or sm4-gcm");
			return;
		}
	}
	const char *name = gmsm_sm4_modes[m].ossl;
	size_t iv_len = gmsm_sm4_modes[m].iv_len;
	bool gcm = m == GMSM_SM4_GCM;
	bool has_aad = aad && ZSTR_LEN(aad);

	if (ZSTR_LEN(key) != 16) {
		zend_argument_value_error(2, "SM4 key must be exactly 16 bytes");
		return;
	}
	if (ZSTR_LEN(iv) != iv_len) {
		if (iv_len) {
			zend_argument_value_error(3, "must be exactly %d bytes for %s", (int)iv_len, name);
		} else {
			zend_argument_value_error(3, "must be empty for %s", name);
		}
		return;
	}
	/* A later named argument makes PHP synthesize a one-owner reference for a skipped
	 * by-reference $tag. Reject it because the authentication tag would be discarded. */
	if (gcm && enc && (!tag_out || (Z_ISREF_P(tag_out) && Z_REFCOUNT_P(tag_out) == 1))) {
		zend_argument_value_error(5, "must be passed to receive the %s authentication tag", name);
		return;
	}
	if (gcm && !enc && (!tag_in || ZSTR_LEN(tag_in) != 16)) {
		zend_argument_value_error(5, "must be exactly 16 bytes for %s", name);
		return;
	}
	/* Like openssl_encrypt(): clear $tag rather than reject it. A skipped by-ref $tag
	 * (named $aad) arrives as a fresh reference too, so "passed" cannot be detected here. */
	if (!gcm && enc && tag_out) {
		ZEND_TRY_ASSIGN_REF_NULL(tag_out);
	}
	/* Silently ignoring these would let callers believe their data is authenticated. */
	if (!gcm && !enc && tag_in && ZSTR_LEN(tag_in)) {
		zend_argument_value_error(5, "must be empty for %s", name);
		return;
	}
	if (!gcm && has_aad) {
		zend_argument_value_error(6, "must be empty for %s", name);
		return;
	}
	if (ZSTR_LEN(data) > INT_MAX || (aad && ZSTR_LEN(aad) > INT_MAX)) {
		zend_argument_value_error(ZSTR_LEN(data) > INT_MAX ? 1 : 6, "is too long");
		return;
	}
	if (!gmsm_sm4[m]) {
		php_error_docref(NULL, E_WARNING, "%s is not available in the linked OpenSSL", name);
		RETURN_FALSE;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	zend_string *out = zend_string_alloc(ZSTR_LEN(data) + 16, 0); /* + one block of padding */
	unsigned char *o = (unsigned char *)ZSTR_VAL(out);
	int len = 0, fin = 0, aad_len;
	unsigned char tag[16];

	/* The default GCM IV length is 12, so no EVP_CTRL_GCM_SET_IVLEN is needed. */
	bool ok = ctx
		&& EVP_CipherInit_ex(ctx, gmsm_sm4[m], NULL, (const unsigned char *)ZSTR_VAL(key),
			iv_len ? (const unsigned char *)ZSTR_VAL(iv) : NULL, enc)
		&& (!has_aad || EVP_CipherUpdate(ctx, NULL, &aad_len, (const unsigned char *)ZSTR_VAL(aad), (int)ZSTR_LEN(aad)))
		&& (!ZSTR_LEN(data) || EVP_CipherUpdate(ctx, o, &len, (const unsigned char *)ZSTR_VAL(data), (int)ZSTR_LEN(data)))
		&& (!gcm || enc || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ZSTR_VAL(tag_in)))
		&& EVP_CipherFinal_ex(ctx, o + len, &fin)
		&& (!gcm || !enc || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag));
	EVP_CIPHER_CTX_free(ctx);

	if (!ok) {
		/* may hold unauthenticated or unpadded plaintext */
		OPENSSL_cleanse(ZSTR_VAL(out), ZSTR_LEN(out));
		zend_string_efree(out);
		RETURN_FALSE;
	}
	if (gcm && enc) {
		ZEND_TRY_ASSIGN_REF_STRINGL(tag_out, (char *)tag, 16);
	}
	ZSTR_LEN(out) = len + fin;
	ZSTR_VAL(out)[len + fin] = '\0';
	RETURN_NEW_STR(out);
}

PHP_FUNCTION(sm4_encrypt)
{
	zend_string *data, *key, *iv, *mode = NULL, *aad = NULL;
	zval *tag = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 6)
		Z_PARAM_STR(data)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(mode)
		Z_PARAM_ZVAL(tag)
		Z_PARAM_STR(aad)
	ZEND_PARSE_PARAMETERS_END();

	gmsm_sm4_crypt(return_value, 1, data, key, iv, mode, aad, tag, NULL);
}

PHP_FUNCTION(sm4_decrypt)
{
	zend_string *data, *key, *iv, *mode = NULL, *tag = NULL, *aad = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 6)
		Z_PARAM_STR(data)
		Z_PARAM_STR(key)
		Z_PARAM_STR(iv)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(mode)
		Z_PARAM_STR(tag)
		Z_PARAM_STR(aad)
	ZEND_PARSE_PARAMETERS_END();

	gmsm_sm4_crypt(return_value, 0, data, key, iv, mode, aad, NULL, tag);
}

/* ========================================================================= */
/* Module                                                                    */
/* ========================================================================= */

PHP_MINIT_FUNCTION(gmsm)
{
	register_gmsm_symbols(module_number);

	/* Only internal classes exist during MINIT, so a userland class named OpenSSLAsymmetricKey
	 * can never be mistaken for ext/openssl's. The module dependency below orders us after it. */
	gmsm_pkey_ce = zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("opensslasymmetrickey"));
	if (gmsm_pkey_ce) {
		/* An ext/openssl built against a different OpenSSL major hands us foreign EVP_PKEYs. */
		zval *v = zend_get_constant_str(ZEND_STRL("OPENSSL_VERSION_NUMBER"));
		if (!v || Z_TYPE_P(v) != IS_LONG || ((zend_ulong)Z_LVAL_P(v) >> 28) != ((zend_ulong)OPENSSL_VERSION_NUMBER >> 28)) {
			gmsm_pkey_ce = NULL;
		}
	}

#if GMSM_OSSL3
	gmsm_sm3 = EVP_MD_fetch(NULL, "SM3", NULL);
	for (size_t i = 0; i < GMSM_SM4_MODES; i++) {
		gmsm_sm4[i] = EVP_CIPHER_fetch(NULL, gmsm_sm4_modes[i].ossl, NULL);
	}
	ERR_clear_error(); /* modes this OpenSSL lacks (e.g. SM4-GCM on 3.0) stay NULL */
#else
	gmsm_sm3 = EVP_sm3();
	for (size_t i = 0; i < GMSM_SM4_MODES; i++) {
		gmsm_sm4[i] = EVP_get_cipherbyname(gmsm_sm4_modes[i].ossl);
	}
#endif
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(gmsm)
{
#if GMSM_OSSL3
	EVP_MD_free((EVP_MD *)gmsm_sm3);
	for (size_t i = 0; i < GMSM_SM4_MODES; i++) {
		EVP_CIPHER_free((EVP_CIPHER *)gmsm_sm4[i]);
	}
#endif
	return SUCCESS;
}

PHP_MINFO_FUNCTION(gmsm)
{
	bool sm4_basic = true, sm4_any = false;
	for (size_t i = 0; i < GMSM_SM4_MODES; i++) {
		sm4_any |= gmsm_sm4[i] != NULL;
		if (i != GMSM_SM4_GCM && !gmsm_sm4[i]) {
			sm4_basic = false;
		}
	}

	php_info_print_table_start();
	php_info_print_table_header(2, "gmsm support", "enabled");
	php_info_print_table_row(2, "gmsm extension version", PHP_GMSM_VERSION);
	php_info_print_table_row(2, "OpenSSL header version", OPENSSL_VERSION_TEXT);
	php_info_print_table_row(2, "OpenSSL library version", OpenSSL_version(OPENSSL_VERSION));
	php_info_print_table_row(2, "SM2 asymmetric cryptography", "compiled (GB/T 32918)");
	php_info_print_table_row(2, "SM3 cryptographic hash", gmsm_sm3
		? "enabled (GB/T 32905)" : "unavailable in the linked OpenSSL");
	php_info_print_table_row(2, "SM4 block cipher", !sm4_any ? "unavailable in the linked OpenSSL"
		: !sm4_basic ? "partially available in the linked OpenSSL"
		: gmsm_sm4[GMSM_SM4_GCM] ? "enabled (GB/T 32907, CBC/ECB/CTR/CFB/OFB/GCM)"
		: "enabled (GB/T 32907, CBC/ECB/CTR/CFB/OFB)");
	php_info_print_table_row(2, "OpenSSLAsymmetricKey interop", gmsm_pkey_ce ? "enabled" : "disabled");
	php_info_print_table_end();
}

static const zend_module_dep gmsm_deps[] = {
	ZEND_MOD_OPTIONAL("openssl")
	ZEND_MOD_END
};

zend_module_entry gmsm_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	gmsm_deps,
	PHP_GMSM_NAME,
	ext_functions,
	PHP_MINIT(gmsm),
	PHP_MSHUTDOWN(gmsm),
	NULL,
	NULL,
	PHP_MINFO(gmsm),
	PHP_GMSM_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_GMSM
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(gmsm)
#endif
