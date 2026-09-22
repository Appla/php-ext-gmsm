--TEST--
Failed gmsm operations expose OpenSSL diagnostics; decoder fallbacks clear incidental errors
--EXTENSIONS--
gmsm
--SKIPIF--
<?php if (!function_exists('openssl_error_string')) echo 'skip ext/openssl required'; ?>
--FILE--
<?php
$pair = sm2_keygen();
$private = $pair['private_key'];
$public = $pair['public_key'];
function hasOpenSSLErrors(): bool {
    $found = false;
    while (openssl_error_string() !== false) $found = true;
    return $found;
}
var_dump(hasOpenSSLErrors() === false);
var_dump(is_array(sm2_pkey_get_details($public)));
var_dump(hasOpenSSLErrors() === false);

// ASN.1 decoding and signature verification both fail inside OpenSSL.
var_dump(sm2_verify('message', "\x00", $public) === false);
var_dump(hasOpenSSLErrors() === true);

$signature = sm2_sign('message', $private);
var_dump(hasOpenSSLErrors() === false);
var_dump(sm2_verify('other message', $signature, $public) === false);
hasOpenSSLErrors(); // A mismatch may or may not enqueue an OpenSSL error.

// Corrupt C3 so the decrypted plaintext fails authentication.
$ciphertext = sm2_encrypt('message', $public);
var_dump(hasOpenSSLErrors() === false);
$ciphertext[65] = chr(ord($ciphertext[65]) ^ 1);
var_dump(sm2_decrypt($ciphertext, $private) === false);
var_dump(hasOpenSSLErrors() === true);

// A rejected key and invalid CBC ciphertext retain their OpenSSL diagnostics.
var_dump(@sm2_sign('message', 'not a key') === false);
var_dump(hasOpenSSLErrors() === true);
var_dump(sm4_decrypt("\x00", str_repeat("\x00", 16), str_repeat("\x00", 16)) === false);
var_dump(hasOpenSSLErrors() === true);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
