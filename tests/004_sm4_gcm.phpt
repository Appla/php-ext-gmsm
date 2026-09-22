--TEST--
SM4-GCM AEAD encryption and tamper detection
--SKIPIF--
<?php
if (!extension_loaded("gmsm")) print "skip";
$suppressed = false;
set_error_handler(function() use (&$suppressed) { $suppressed = true; return true; });
$tag = null;
$res = sm4_encrypt("test", str_repeat("\x01", 16), str_repeat("\x02", 12), "sm4-gcm", $tag);
restore_error_handler();
if ($res === false) print "skip SM4-GCM not supported in this OpenSSL build";
?>
--FILE--
<?php
$key = random_bytes(16);
$iv  = random_bytes(12);
$aad = "authenticated-header-data";
$plaintext = "Confidential message protected by SM4-GCM AEAD.";

// 1. Encrypt and obtain tag
$tag = null;
$ciphertext = sm4_encrypt($plaintext, $key, $iv, "sm4-gcm", $tag, $aad);
var_dump($ciphertext !== false);
var_dump(is_string($tag) && strlen($tag) === 16);

// 2. Decrypt with matching tag and AAD
$decrypted = sm4_decrypt($ciphertext, $key, $iv, "sm4-gcm", $tag, $aad);
var_dump($decrypted === $plaintext);

// 3. Tamper detection: altered ciphertext returns false
$tamperedCt = $ciphertext;
$tamperedCt[0] = chr(ord($tamperedCt[0]) ^ 0x01);
var_dump(sm4_decrypt($tamperedCt, $key, $iv, "sm4-gcm", $tag, $aad) === false);

// 4. Tamper detection: altered tag returns false
$tamperedTag = $tag;
$tamperedTag[0] = chr(ord($tamperedTag[0]) ^ 0x01);
var_dump(sm4_decrypt($ciphertext, $key, $iv, "sm4-gcm", $tamperedTag, $aad) === false);

// 5. Tamper detection: altered AAD returns false
var_dump(sm4_decrypt($ciphertext, $key, $iv, "sm4-gcm", $tag, "corrupted-aad") === false);

// 6. Empty plaintext
$emptyTag = null;
$emptyCt = sm4_encrypt("", $key, $iv, "sm4-gcm", $emptyTag, $aad);
var_dump($emptyCt === "");
var_dump(is_string($emptyTag) && strlen($emptyTag) === 16);
var_dump(sm4_decrypt("", $key, $iv, "sm4-gcm", $emptyTag, $aad) === "");

// 7. Non-12-byte IV rejection
try {
    sm4_encrypt($plaintext, $key, str_repeat("\x00", 16), "sm4-gcm", $tag);
    echo "FAIL: accepted 16-byte IV for GCM\n";
} catch (ValueError $e) {
    echo "OK: GCM requires 12-byte IV\n";
}

// 8. Truncated tag rejection
try {
    sm4_decrypt($ciphertext, $key, $iv, "sm4-gcm", substr($tag, 0, 1), $aad);
    echo "FAIL: accepted truncated tag\n";
} catch (ValueError $e) {
    echo "OK: GCM rejected truncated tag\n";
}

// 9. Omitting tag parameter in GCM mode throws ValueError
try {
    sm4_encrypt($plaintext, $key, $iv, "sm4-gcm");
    echo "FAIL: accepted omitted tag in GCM mode\n";
} catch (ValueError $e) {
    echo "OK: GCM requires tag output argument\n";
}

// 10. Naming a later argument must not silently discard the skipped tag output
try {
    sm4_encrypt($plaintext, $key, $iv, "sm4-gcm", aad: $aad);
    echo "FAIL: accepted throwaway GCM tag output\n";
} catch (ValueError $e) {
    echo "OK: GCM rejects throwaway tag output\n";
}

// 11. An explicitly named tag remains a caller-owned output
$namedTag = null;
$namedCt = sm4_encrypt($plaintext, $key, $iv, "sm4-gcm", tag: $namedTag, aad: $aad);
var_dump(is_string($namedCt) && strlen($namedTag) === 16);
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
OK: GCM requires 12-byte IV
OK: GCM rejected truncated tag
OK: GCM requires tag output argument
OK: GCM rejects throwaway tag output
bool(true)

