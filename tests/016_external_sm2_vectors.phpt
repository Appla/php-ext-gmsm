--TEST--
SM2 verifies and decrypts fixed ciphertext from OpenSSL independently of gmsm keygen
--EXTENSIONS--
gmsm
--FILE--
<?php
// Key and ciphertext: OpenSSL test/recipes/30-test_evp_data/evppkey_sm2.txt,
// SM2_key1 and the first Decrypt case (OpenSSL 3.5.5).
// https://github.com/openssl/openssl/blob/openssl-3.5.5/test/recipes/30-test_evp_data/evppkey_sm2.txt
$private = <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----
PEM;
$public = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX
F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==
-----END PUBLIC KEY-----
PEM;
$ciphertext = hex2bin('30818A0220466BE2EF5C11782EC77864A0055417F407A5AFC11D653C6BCE69E417BB1D05B6022062B572E21FF0DDF5C726BD3F9FF2EAE56E6294713A607E9B9525628965F62CC804203C1B5713B5DB2728EB7BF775E44F4689FC32668BDC564F52EA45B09E8DF2A5F40422084A9D0CC2997092B7D3C404FCE95956EB604D732B2307A8E5B8900ED6608CA5B197');
var_dump(sm2_decrypt($ciphertext, $private, SM2_FMT_ASN1) === 'The floofy bunnies hop at midnight');

// Fixed signature generated separately with OpenSSL 3.5.5:
// openssl pkeyutl -sign -inkey sm2-key.pem -rawin -digest sm3
//   -pkeyopt distid:1234567812345678 -in message.bin -out signature.der
$message = hex2bin('D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8');
$signature = hex2bin('304402203312972adf0191c31a27d3da1e1138defbd1ecf2d8088bd8018987dbb4bcd8c802200b64748a0135c9e24c8eed396617f197a6b87bfa63d8155a8f4b43e23b8b6235');
var_dump(sm2_verify($message, $signature, $public) === true);
var_dump(sm2_verify($message, $signature, $public, 'wrong') === false);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
