--TEST--
SM2 keypair generation and details extraction
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
// 1. Generate unencrypted keypair
$kp = sm2_keygen();
var_dump(is_array($kp));
var_dump(isset($kp['private_key'], $kp['public_key']));
var_dump(str_contains($kp['private_key'], 'BEGIN PRIVATE KEY'));
var_dump(str_contains($kp['public_key'], 'BEGIN PUBLIC KEY'));

// 2. Extract details from public key PEM
$pubDetails = sm2_pkey_get_details($kp['public_key']);
var_dump($pubDetails['bits'] === 256);
var_dump($pubDetails['type'] === 'sm2');
var_dump(isset($pubDetails['sm2']['x'], $pubDetails['sm2']['y']));
var_dump(strlen($pubDetails['sm2']['x']) === 32);
var_dump(strlen($pubDetails['sm2']['y']) === 32);
var_dump(!isset($pubDetails['sm2']['d'])); // Public key has no private D

// 3. Extract details from private key PEM
$privDetails = sm2_pkey_get_details($kp['private_key']);
var_dump($privDetails['bits'] === 256);
var_dump($privDetails['type'] === 'sm2');
var_dump($privDetails['sm2']['x'] === $pubDetails['sm2']['x']);
var_dump($privDetails['sm2']['y'] === $pubDetails['sm2']['y']);
var_dump(isset($privDetails['sm2']['d']));
var_dump(strlen($privDetails['sm2']['d']) === 32);

// 4. Generate encrypted private key with passphrase
$kpEnc = sm2_keygen("MyStrongPassphrase123!");
var_dump(str_contains($kpEnc['private_key'], 'ENCRYPTED PRIVATE KEY'));
$encDetails = sm2_pkey_get_details($kpEnc['public_key']);
var_dump($encDetails['bits'] === 256);
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
bool(true)
bool(true)
bool(true)
bool(true)
