--TEST--
SM2 public key encryption and private key decryption across formats
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
$kp = sm2_keygen();
$pub = $kp['public_key'];
$priv = $kp['private_key'];

$plaintext = "Hello World! SM2 encryption test with Chinese national crypto GB/T 32918.";

// 1. Default format: SM2_FMT_C1C3C2
$ctC1C3C2 = sm2_encrypt($plaintext, $pub);
var_dump($ctC1C3C2 !== false);
var_dump(ord($ctC1C3C2[0]) === 0x04); // Starts with 0x04 uncompressed
var_dump(strlen($ctC1C3C2) === 1 + 64 + 32 + strlen($plaintext)); // 97 + len

$dec1 = sm2_decrypt($ctC1C3C2, $priv);
var_dump($dec1 === $plaintext);

// 2. ASN.1 DER format: SM2_FMT_ASN1
$ctAsn1 = sm2_encrypt($plaintext, $pub, SM2_FMT_ASN1);
var_dump($ctAsn1 !== false);
var_dump(ord($ctAsn1[0]) === 0x30); // SEQUENCE tag

$decAsn1 = sm2_decrypt($ctAsn1, $priv, SM2_FMT_ASN1);
var_dump($decAsn1 === $plaintext);

// 3. Legacy draft format: SM2_FMT_C1C2C3
$ctC1C2C3 = sm2_encrypt($plaintext, $pub, SM2_FMT_C1C2C3);
var_dump($ctC1C2C3 !== false);
var_dump(ord($ctC1C2C3[0]) === 0x04);
var_dump(strlen($ctC1C2C3) === 1 + 64 + 32 + strlen($plaintext));

$decC1C2C3 = sm2_decrypt($ctC1C2C3, $priv, SM2_FMT_C1C2C3);
var_dump($decC1C2C3 === $plaintext);

// 4. Cross-format decryption failure check (e.g. C1C3C2 decrypted as C1C2C3 must fail)
$crossDec = sm2_decrypt($ctC1C3C2, $priv, SM2_FMT_C1C2C3);
var_dump($crossDec !== $plaintext);

// 5. Decryption with wrong private key fails
$otherKp = sm2_keygen();
$wrongDec = sm2_decrypt($ctC1C3C2, $otherKp['private_key']);
var_dump($wrongDec === false);
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
