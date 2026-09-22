<?php

/** @generate-class-entries */

/**
 * @var int
 * @cvalue SM2_FMT_ASN1
 */
const SM2_FMT_ASN1 = UNKNOWN;

/**
 * @var int
 * @cvalue SM2_FMT_C1C3C2
 */
const SM2_FMT_C1C3C2 = UNKNOWN;

/**
 * @var int
 * @cvalue SM2_FMT_C1C2C3
 */
const SM2_FMT_C1C2C3 = UNKNOWN;

/**
 * @var int
 * @cvalue SM2_SIG_ASN1
 */
const SM2_SIG_ASN1 = UNKNOWN;

/**
 * @var int
 * @cvalue SM2_SIG_RAW_RS
 */
const SM2_SIG_RAW_RS = UNKNOWN;

/**
 * Generate an SM2 keypair.
 *
 * @param string|null $passphrase Optional passphrase to encrypt the private key
 * @return array{private_key: string, public_key: string}|false
 */
function sm2_keygen(#[\SensitiveParameter] ?string $passphrase = null): array|false {}

/**
 * Encrypt data using an SM2 public key.
 *
 * @param string $data Plaintext
 * @param string|object $public_key SPKI/PKCS8 PEM/DER string or OpenSSLAsymmetricKey
 * @param int $format Output format: SM2_FMT_C1C3C2 (default), SM2_FMT_ASN1, or SM2_FMT_C1C2C3
 */
function sm2_encrypt(string $data, string|object $public_key, int $format = SM2_FMT_C1C3C2): string|false {}

/**
 * Decrypt data using an SM2 private key.
 *
 * @param string $data Ciphertext
 * @param string|array|object $private_key PKCS8 PEM/DER string, array [$key, $passphrase], or OpenSSLAsymmetricKey
 * @param int $format Input format: SM2_FMT_C1C3C2 (default), SM2_FMT_ASN1, or SM2_FMT_C1C2C3
 */
function sm2_decrypt(string $data, #[\SensitiveParameter] string|array|object $private_key, int $format = SM2_FMT_C1C3C2): string|false {}

/**
 * Sign data using an SM2 private key with SM3.
 *
 * @param string $data Message data to sign
 * @param string|array|object $private_key PKCS8 PEM/DER string, array [$key, $passphrase], or OpenSSLAsymmetricKey
 * @param string|null $user_id User ID (null = GM/T 0009 default "1234567812345678", "" = empty ID)
 * @param int $format Output format: SM2_SIG_ASN1 (default) or SM2_SIG_RAW_RS
 */
function sm2_sign(string $data, #[\SensitiveParameter] string|array|object $private_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): string|false {}

/**
 * Verify an SM2 signature with SM3.
 *
 * @param string $data Message data that was signed
 * @param string $signature Signature (ASN.1 DER or 64-byte raw R||S depending on $format)
 * @param string|object $public_key SPKI/PKCS8 PEM/DER string or OpenSSLAsymmetricKey
 * @param string|null $user_id User ID (null = GM/T 0009 default "1234567812345678", "" = empty ID)
 * @param int $format Signature format: SM2_SIG_ASN1 (default) or SM2_SIG_RAW_RS
 */
function sm2_verify(string $data, string $signature, string|object $public_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): bool {}

/**
 * Extract public/private key details for an SM2 key.
 *
 * @param string|array|object $key PEM/DER string, array [$key, $passphrase], or OpenSSLAsymmetricKey
 * @return array{bits: int, key: string, type: string, sm2: array{x: string, y: string, d?: string}}|false
 */
function sm2_pkey_get_details(#[\SensitiveParameter] string|array|object $key): array|false {}

/**
 * Convert SM2 ciphertext between ASN.1 DER, C1C3C2, and C1C2C3 formats.
 *
 * @param string $data Ciphertext to convert
 * @param int $from_format Source format (SM2_FMT_*)
 * @param int $to_format Target format (SM2_FMT_*)
 */
function sm2_cipher_convert(string $data, int $from_format, int $to_format): string|false {}

/**
 * Convert SM2 signature between ASN.1 DER and raw 64-byte R||S.
 *
 * @param string $signature Signature to convert
 * @param int $from_format Source format (SM2_SIG_*)
 * @param int $to_format Target format (SM2_SIG_*)
 */
function sm2_sig_convert(string $signature, int $from_format, int $to_format): string|false {}

/**
 * Compute SM3 cryptographic hash.
 *
 * @param string $data Input message
 * @param bool $binary If true, returns 32-byte raw binary; otherwise 64-char lowercase hex
 */
function sm3(string $data, bool $binary = false): string {}

/**
 * Compute HMAC using SM3.
 *
 * @param string $data Input message
 * @param string $key Secret key
 * @param bool $binary If true, returns 32-byte raw binary; otherwise 64-char lowercase hex
 */
function sm3_hmac(string $data, #[\SensitiveParameter] string $key, bool $binary = false): string {}

/**
 * Encrypt data using SM4 block cipher.
 *
 * @param string $data Plaintext
 * @param string $key 16-byte SM4 key
 * @param string $iv Initialization vector (16 bytes for CBC/CTR/OFB/CFB, exactly 12 bytes for GCM)
 * @param string $mode Cipher mode: "sm4-cbc", "sm4-ecb", "sm4-ctr", "sm4-cfb", "sm4-ofb", "sm4-gcm"
 * @param string|null $tag Reference to receive authentication tag (for GCM mode)
 * @param string $aad Additional authenticated data (for GCM mode)
 */
function sm4_encrypt(string $data, #[\SensitiveParameter] string $key, string $iv, string $mode = "sm4-cbc", ?string &$tag = null, string $aad = ""): string|false {}

/**
 * Decrypt data using SM4 block cipher.
 *
 * @param string $data Ciphertext
 * @param string $key 16-byte SM4 key
 * @param string $iv Initialization vector
 * @param string $mode Cipher mode: "sm4-cbc", "sm4-ecb", "sm4-ctr", "sm4-cfb", "sm4-ofb", "sm4-gcm"
 * @param string $tag Authentication tag (required for GCM mode)
 * @param string $aad Additional authenticated data (for GCM mode)
 */
function sm4_decrypt(string $data, #[\SensitiveParameter] string $key, string $iv, string $mode = "sm4-cbc", string $tag = "", string $aad = ""): string|false {}
