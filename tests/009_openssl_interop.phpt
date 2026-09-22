--TEST--
Interoperability with ext/openssl OpenSSLAsymmetricKey objects
--SKIPIF--
<?php
if (!extension_loaded("gmsm")) print "skip gmsm not loaded";
if (!extension_loaded("openssl")) print "skip openssl not loaded";
?>
--FILE--
<?php
// Generate an SM2 key using built-in ext/openssl
$keyOpts = defined('OPENSSL_KEYTYPE_SM2')
    ? ['private_key_type' => OPENSSL_KEYTYPE_SM2]
    : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'SM2'];

$opensslPriv = openssl_pkey_new($keyOpts);
var_dump($opensslPriv instanceof OpenSSLAsymmetricKey);

$details = openssl_pkey_get_details($opensslPriv);
$opensslPub = openssl_pkey_get_public($details['key']);
var_dump($opensslPub instanceof OpenSSLAsymmetricKey);

$msg = "Interoperability test between ext/openssl and ext/gmsm.";

// 1. Pass OpenSSLAsymmetricKey object to sm2_encrypt()
$ct = sm2_encrypt($msg, $opensslPub);
var_dump($ct !== false);

// 2. Pass OpenSSLAsymmetricKey object to sm2_decrypt()
$dec = sm2_decrypt($ct, $opensslPriv);
var_dump($dec === $msg);

// 3. Pass OpenSSLAsymmetricKey object to sm2_sign()
$sig = sm2_sign($msg, $opensslPriv);
var_dump($sig !== false);

// 4. Pass OpenSSLAsymmetricKey object to sm2_verify()
var_dump(sm2_verify($msg, $sig, $opensslPub) === true);

// 5. Pass OpenSSLAsymmetricKey object to sm2_pkey_get_details()
$gmsmDetails = sm2_pkey_get_details($opensslPriv);
var_dump($gmsmDetails['bits'] === 256);
var_dump($gmsmDetails['type'] === 'sm2');
var_dump(strlen($gmsmDetails['sm2']['x']) === 32);
var_dump(strlen($gmsmDetails['sm2']['y']) === 32);
var_dump(strlen($gmsmDetails['sm2']['d']) === 32);
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
