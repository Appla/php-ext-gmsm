--TEST--
SM4 symmetric block cipher modes (CBC, ECB, CTR)
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
// SM4 Standard Test Vector (GB/T 32907-2016)
$keyHex = "0123456789abcdeffedcba9876543210";
$ptHex  = "0123456789abcdeffedcba9876543210";
$key = hex2bin($keyHex);
$plaintext = hex2bin($ptHex);

// 1. SM4 ECB Mode (Note: sm4_encrypt adds PKCS#7 padding by default)
$ctEcb = sm4_encrypt($plaintext, $key, "", "sm4-ecb");
var_dump($ctEcb !== false);
// First 16 bytes of ciphertext in ECB matches standard single block: 681edf34d206965e86b3e94f536e4246
var_dump(bin2hex(substr($ctEcb, 0, 16)) === "681edf34d206965e86b3e94f536e4246");

$dtEcb = sm4_decrypt($ctEcb, $key, "", "sm4-ecb");
var_dump($dtEcb === $plaintext);

// 2. SM4 CBC Mode
$iv = random_bytes(16);
$message = "SM4-CBC test message with arbitrary length to check PKCS#7 padding.";
$ctCbc = sm4_encrypt($message, $key, $iv, "sm4-cbc");
var_dump($ctCbc !== false);
$dtCbc = sm4_decrypt($ctCbc, $key, $iv, "sm4-cbc");
var_dump($dtCbc === $message);

// Decryption with bad key or iv fails
$badDec = sm4_decrypt($ctCbc, str_repeat("\x00", 16), $iv, "sm4-cbc");
var_dump($badDec !== $message);

// 3. SM4 CTR Mode
$ivCtr = random_bytes(16);
$ctCtr = sm4_encrypt($message, $key, $ivCtr, "sm4-ctr");
var_dump($ctCtr !== false);
$dtCtr = sm4_decrypt($ctCtr, $key, $ivCtr, "sm4-ctr");
var_dump($dtCtr === $message);

// 4. Invalid key length throws ValueError
try {
    sm4_encrypt("test", "short_key", $iv, "sm4-cbc");
} catch (ValueError $e) {
    echo "Caught: " . $e->getMessage() . "\n";
}
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
Caught: sm4_encrypt(): Argument #2 ($key) SM4 key must be exactly 16 bytes
