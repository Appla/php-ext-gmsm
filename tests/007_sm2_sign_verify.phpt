--TEST--
SM2 digital signature and verification with default, custom, and empty User IDs
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
$kp = sm2_keygen();
$pub = $kp['public_key'];
$priv = $kp['private_key'];

$message = "Test transaction data for SM2 digital signature verification.";

// 1. Default User ID (GM/T 0009-2012 "1234567812345678") and default ASN.1 DER format
$sigDer = sm2_sign($message, $priv);
var_dump($sigDer !== false);
var_dump(ord($sigDer[0]) === 0x30); // SEQUENCE

// Verify with default ID
var_dump(sm2_verify($message, $sigDer, $pub) === true);
// Explicit null selects default ID
var_dump(sm2_verify($message, $sigDer, $pub, null) === true);

// 2. Raw 64-byte R||S format
$sigRaw = sm2_sign($message, $priv, null, SM2_SIG_RAW_RS);
var_dump(is_string($sigRaw) && strlen($sigRaw) === 64);
var_dump(sm2_verify($message, $sigRaw, $pub, null, SM2_SIG_RAW_RS) === true);

// 3. Custom User ID
$customId = "ALICE123@COMPANY.COM";
$sigCustom = sm2_sign($message, $priv, $customId);
var_dump($sigCustom !== false);

// Verification with matching ID succeeds
var_dump(sm2_verify($message, $sigCustom, $pub, $customId) === true);

// Verification with different ID fails
var_dump(sm2_verify($message, $sigCustom, $pub, "BOB456@COMPANY.COM") === false);
var_dump(sm2_verify($message, $sigCustom, $pub, null) === false);

// 4. Empty User ID ("")
$sigEmpty = sm2_sign($message, $priv, "");
var_dump($sigEmpty !== false);
var_dump(sm2_verify($message, $sigEmpty, $pub, "") === true);
var_dump(sm2_verify($message, $sigEmpty, $pub, null) === false);

// 5. Tampered message fails verification
var_dump(sm2_verify("Tampered message", $sigDer, $pub) === false);

// 6. Wrong public key fails verification
$otherKp = sm2_keygen();
var_dump(sm2_verify($message, $sigDer, $otherKp['public_key']) === false);
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
