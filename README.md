# php-ext-gmsm

[English](README.md) | [简体中文](README-zh.md)

SM2 / SM3 / SM4 (GB/T 32918, 32905, 32907) for PHP 8.3+, built on OpenSSL 1.1.1 or 3.x.

## Installation

### Via PIE (Recommended)

```bash
pie install appla/php-ext-gmsm
```

### Manual Build

```bash
phpize
./configure --enable-gmsm
make -j"$(nproc)" && make test
sudo make install        # then add extension=gmsm to php.ini
```

OpenSSL is located through pkg-config, the same way PHP's own `ext/openssl` is. Build against
the OpenSSL your PHP uses. For a custom install, pass
`--with-gmsm-openssl=/opt/openssl`; `PKG_CONFIG_PATH` and `OPENSSL_CFLAGS` / `OPENSSL_LIBS`
remain available as lower-level overrides.
OpenSSL must be built with SM2, SM3 and SM4 (the build fails on `no-sm2`/`no-sm3`/`no-sm4`).
On OpenSSL 3.x, the loaded providers must also make the algorithms available at runtime. `phpinfo()` reports SM3 and SM4 availability and lists SM2 as compiled support. SM2 operations fail if the needed provider algorithms are unavailable; `sm3()` and `sm3_hmac()` raise an `Error` if SM3 is unavailable.

## PHP compatibility

PHP 8.3+ is required. Passing an `OpenSSLAsymmetricKey` object depends on PHP's internal
object layout. Object interop was tested on PHP 8.3~8.6 NTS builds

## API

```php
sm2_keygen(?string $passphrase = null): array|false            // ['private_key' => PKCS#8 PEM, 'public_key' => SPKI PEM]
sm2_encrypt(string $data, string|OpenSSLAsymmetricKey $public_key, int $format = SM2_FMT_C1C3C2): string|false
sm2_decrypt(string $data, string|array|OpenSSLAsymmetricKey $private_key, int $format = SM2_FMT_C1C3C2): string|false
sm2_sign(string $data, string|array|OpenSSLAsymmetricKey $private_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): string|false
sm2_verify(string $data, string $signature, string|OpenSSLAsymmetricKey $public_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): bool
sm2_pkey_get_details(string|array|OpenSSLAsymmetricKey $key): array|false   // ['bits', 'key', 'type' => 'sm2', 'sm2' => ['x', 'y', 'd'?]]
sm2_cipher_convert(string $data, int $from_format, int $to_format): string|false
sm2_sig_convert(string $signature, int $from_format, int $to_format): string|false
sm3(string $data, bool $binary = false): string
sm3_hmac(string $data, string $key, bool $binary = false): string
sm4_encrypt(string $data, string $key, string $iv, string $mode = "sm4-cbc", ?string &$tag = null, string $aad = ""): string|false
sm4_decrypt(string $data, string $key, string $iv, string $mode = "sm4-cbc", string $tag = "", string $aad = ""): string|false
```

Constants: `SM2_FMT_ASN1`, `SM2_FMT_C1C3C2` (GB/T 32918.4), `SM2_FMT_C1C2C3` (old draft), `SM2_SIG_ASN1`, `SM2_SIG_RAW_RS` (64-byte r‖s).

When a call fails, use PHP's `openssl_error_string()` immediately afterward to read any OpenSSL diagnostics (if ext/openssl is loaded). Call it repeatedly until it returns `false`. Some failures are detected by gmsm before OpenSSL runs and have no OpenSSL message. Successful key-decoder fallbacks and public-key detail probes discard their expected OpenSSL errors.

### Keys

A key is a PEM or DER string (SPKI, PKCS#8, encrypted PKCS#8, or SEC1 `EC PRIVATE KEY`), or an
`OpenSSLAsymmetricKey`. Private-key parameters also accept `[$key, $passphrase]` or
`['key' => ..., 'passphrase' => ...]`. Public-key functions do not accept arrays, so passphrases
never end up in their stack traces. A key string that cannot be decoded emits `E_WARNING` and the
function returns `false`. A missing passphrase fails without prompting.

Every call with a key string decodes it again. On OpenSSL 3.0 that costs roughly 100–350 µs, so for
repeated operations decode once with `openssl_pkey_get_public()` / `openssl_pkey_get_private()` and
pass the object. This saves about 140 µs per `sm2_verify()` on 3.0 and about 30 µs on 3.5.

### Notes

- `$user_id = null` uses the GM/T 0009 default `"1234567812345678"`; `""` is a distinct, empty ID. Maximum 8190 bytes.
- `sm2_keygen()` passphrases must be 1–1024 bytes; `""` throws instead of producing an unencrypted key.
- `sm2_encrypt()` throws `ValueError` for an empty message (SM2 cannot encrypt one).
- `sm2_cipher_convert()` / `sm2_sig_convert()` check structure only. Curve-point and scalar validity
  are checked by `sm2_decrypt()` / `sm2_verify()`, so a converted but invalid value fails there.
- SM4 keys are 16 bytes. CBC/CTR/CFB/OFB need a 16-byte IV; ECB takes `""`. CBC and ECB apply PKCS#7 padding.
- ECB reveals repeated plaintext blocks and is provided for interoperability; avoid it for general data.
- SM4-GCM needs a 12-byte IV and a 16-byte tag. In other modes `$aad` and a non-empty decrypt `$tag` throw,
  and `sm4_encrypt()` sets `$tag` to `null`, as `openssl_encrypt()` does.
  Never reuse a GCM IV with the same key. Generate a fresh IV with `random_bytes(12)` for each encryption and store it alongside the ciphertext and tag.
  When using named arguments for GCM, pass `tag:` explicitly; skipping it while naming `aad:` throws.
  SM4-GCM is not in OpenSSL 1.1.1 or 3.0 (it is in newer 3.x; tested on 3.5.5). Where it is missing,
  `sm4-gcm` emits a warning and returns `false`, and `phpinfo()` reports SM4 support status.
- When checking an HMAC from an untrusted source, use `hash_equals(sm3_hmac($data, $key, true), $receivedMac)` instead of `===`.

## License

MIT
