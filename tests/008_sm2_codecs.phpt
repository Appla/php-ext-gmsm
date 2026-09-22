--TEST--
SM2 hardware codecs: sm2_cipher_convert and sm2_sig_convert
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
$kp = sm2_keygen();
$pub = $kp['public_key'];
$priv = $kp['private_key'];

$plaintext = "Codec roundtrip test message.";

// Generate ciphertext in ASN.1 DER format
$derCt = sm2_encrypt($plaintext, $pub, SM2_FMT_ASN1);
var_dump($derCt !== false);

// 1. DER -> C1C3C2
$c1c3c2 = sm2_cipher_convert($derCt, SM2_FMT_ASN1, SM2_FMT_C1C3C2);
var_dump($c1c3c2 !== false);
var_dump(ord($c1c3c2[0]) === 0x04);
// Decrypt converted C1C3C2 using sm2_decrypt
var_dump(sm2_decrypt($c1c3c2, $priv, SM2_FMT_C1C3C2) === $plaintext);

// 2. C1C3C2 -> ASN.1 DER
$derReconstructed = sm2_cipher_convert($c1c3c2, SM2_FMT_C1C3C2, SM2_FMT_ASN1);
var_dump($derReconstructed !== false);
var_dump(sm2_decrypt($derReconstructed, $priv, SM2_FMT_ASN1) === $plaintext);

// 3. C1C3C2 -> C1C2C3
$c1c2c3 = sm2_cipher_convert($c1c3c2, SM2_FMT_C1C3C2, SM2_FMT_C1C2C3);
var_dump($c1c2c3 !== false);
var_dump(sm2_decrypt($c1c2c3, $priv, SM2_FMT_C1C2C3) === $plaintext);

// 4. C1C2C3 -> C1C3C2
$c1c3c2Roundtrip = sm2_cipher_convert($c1c2c3, SM2_FMT_C1C2C3, SM2_FMT_C1C3C2);
var_dump($c1c3c2Roundtrip === $c1c3c2);

// 5. Signature codec: DER -> Raw RS (64B) -> DER
$derSig = sm2_sign($plaintext, $priv, null, SM2_SIG_ASN1);
var_dump($derSig !== false);

$rawSig = sm2_sig_convert($derSig, SM2_SIG_ASN1, SM2_SIG_RAW_RS);
var_dump(is_string($rawSig) && strlen($rawSig) === 64);
var_dump(sm2_verify($plaintext, $rawSig, $pub, null, SM2_SIG_RAW_RS) === true);

$derSigReconstructed = sm2_sig_convert($rawSig, SM2_SIG_RAW_RS, SM2_SIG_ASN1);
var_dump($derSigReconstructed !== false);
var_dump(sm2_verify($plaintext, $derSigReconstructed, $pub, null, SM2_SIG_ASN1) === true);
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
