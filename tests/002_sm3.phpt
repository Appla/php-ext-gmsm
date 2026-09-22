--TEST--
SM3 cryptographic hash and HMAC against standard test vectors
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
// Test Vector 1: GB/T 32905-2016 "abc"
$hash1 = sm3("abc");
echo "SM3('abc'): $hash1\n";
var_dump($hash1 === "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

// Test Vector 2: GB/T 32905-2016 64-byte message "abcd...abcd"
$msg2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
$hash2 = sm3($msg2);
echo "SM3(64B): $hash2\n";
var_dump($hash2 === "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");

// Binary output test
$bin = sm3("abc", true);
var_dump(strlen($bin) === 32);
var_dump(bin2hex($bin) === $hash1);

// SM3 HMAC test
$key = "SecretKey12345";
$hmacHex = sm3_hmac("Hello GuoMi SM3 HMAC", $key);
$hmacBin = sm3_hmac("Hello GuoMi SM3 HMAC", $key, true);
var_dump(strlen($hmacHex) === 64);
var_dump(strlen($hmacBin) === 32);
var_dump(bin2hex($hmacBin) === $hmacHex);

// Consistency check: different key or data produces different HMAC
var_dump(sm3_hmac("Hello GuoMi SM3 HMAC", "OtherKey") !== $hmacHex);
var_dump(sm3_hmac("Altered Message", $key) !== $hmacHex);
?>
--EXPECT--
SM3('abc'): 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
bool(true)
SM3(64B): debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
