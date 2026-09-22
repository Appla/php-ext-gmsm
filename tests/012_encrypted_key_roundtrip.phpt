--TEST--
SM2 encrypted private key handling with passphrase and non-interactive execution
--EXTENSIONS--
gmsm
--FILE--
<?php
$passphrase = "super-secret-sm2-passphrase-2026";
$pair = sm2_keygen($passphrase);
if (!$pair || empty($pair['private_key']) || empty($pair['public_key'])) {
    die("FAIL: sm2_keygen with passphrase failed\n");
}

$priv_pem = $pair['private_key'];
$pub_pem  = $pair['public_key'];

// Ensure the private key PEM is encrypted (contains ENCRYPTED)
if (strpos($priv_pem, "ENCRYPTED") === false) {
    echo "FAIL: private key is not encrypted\n";
} else {
    echo "OK: private key is encrypted\n";
}

$plaintext = "Classified SM2 Payload under Encryption";
$ciphertext = sm2_encrypt($plaintext, $pub_pem);

// 1. Decrypt without passphrase (must fail immediately without blocking on terminal prompt)
$start = microtime(true);
$dec_no_pass = @sm2_decrypt($ciphertext, $priv_pem);
$elapsed = microtime(true) - $start;

if ($dec_no_pass === false && $elapsed < 2.0) {
    echo "OK: missing passphrase fails non-interactively\n";
} else {
    echo "FAIL: missing passphrase blocked or succeeded ($elapsed s)\n";
}

// 2. Decrypt with incorrect passphrase
$dec_wrong = @sm2_decrypt($ciphertext, [$priv_pem, "wrong-passphrase"]);
echo ($dec_wrong === false) ? "OK: wrong passphrase rejected\n" : "FAIL: wrong passphrase accepted\n";

// 3. Decrypt with indexed array [$pem, $passphrase]
$dec_indexed = sm2_decrypt($ciphertext, [$priv_pem, $passphrase]);
echo ($dec_indexed === $plaintext) ? "OK: indexed array decrypt\n" : "FAIL: indexed array decrypt\n";

// 4. Decrypt with associative array ['key' => $pem, 'passphrase' => $passphrase]
$dec_assoc = sm2_decrypt($ciphertext, ['key' => $priv_pem, 'passphrase' => $passphrase]);
echo ($dec_assoc === $plaintext) ? "OK: assoc array decrypt\n" : "FAIL: assoc array decrypt\n";

// 5. Sign and verify with encrypted key
$msg = "Message to be authenticated by SM2";
$sig = sm2_sign($msg, [$priv_pem, $passphrase]);
$verified = sm2_verify($msg, $sig, $pub_pem);
echo ($verified === true) ? "OK: encrypted key sign & verify\n" : "FAIL: encrypted key sign & verify\n";

// 6. sm2_pkey_get_details with encrypted key
$details = sm2_pkey_get_details([$priv_pem, $passphrase]);
if ($details && isset($details['sm2']['d']) && strlen($details['sm2']['d']) === 32) {
    echo "OK: sm2_pkey_get_details with encrypted key\n";
} else {
    echo "FAIL: sm2_pkey_get_details with encrypted key\n";
}

// 7. sm2_pkey_get_details with wrong passphrase
$details_wrong = @sm2_pkey_get_details([$priv_pem, "bad-pass"]);
echo ($details_wrong === false) ? "OK: sm2_pkey_get_details with wrong pass rejected\n" : "FAIL: sm2_pkey_get_details with wrong pass\n";

// 8. Binary passphrase roundtrip (embedded NUL and binary bytes)
$bin_pass = "binary\0pass\x00\x01\xff\xfe";
$pair_bin = sm2_keygen($bin_pass);
$bin_priv = $pair_bin['private_key'];
$bin_pub  = $pair_bin['public_key'];
$bin_ct   = sm2_encrypt("Binary Passphrase SM2 Data", $bin_pub);
$bin_pt   = sm2_decrypt($bin_ct, [$bin_priv, $bin_pass]);
echo ($bin_pt === "Binary Passphrase SM2 Data") ? "OK: binary passphrase roundtrip\n" : "FAIL: binary passphrase roundtrip\n";

// 9. Encrypted PKCS#8 DER uses the supplied passphrase and remains strict about trailing data
$priv_der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $priv_pem));
$der_sig = sm2_sign($msg, [$priv_der, $passphrase]);
echo sm2_verify($msg, $der_sig, $pub_pem) ? "OK: encrypted DER sign & verify\n" : "FAIL: encrypted DER sign & verify\n";
echo @sm2_sign($msg, [$priv_der, "wrong-passphrase"]) === false ? "OK: encrypted DER wrong pass rejected\n" : "FAIL: encrypted DER wrong pass accepted\n";
echo @sm2_sign($msg, [$priv_der . "junk", $passphrase]) === false ? "OK: encrypted DER trailing data rejected\n" : "FAIL: encrypted DER trailing data accepted\n";

// 10. Oversized passphrase (> 1024 bytes) rejected with ValueError
$oversized_pass = str_repeat("A", 1025);
try {
    sm2_keygen($oversized_pass);
    echo "FAIL: accepted oversized pass in keygen\n";
} catch (ValueError $e) {
    echo "OK: oversized pass rejected in keygen\n";
}

try {
    sm2_decrypt($ciphertext, [$priv_pem, $oversized_pass]);
    echo "FAIL: accepted oversized pass in decrypt\n";
} catch (ValueError $e) {
    echo "OK: oversized pass rejected in decrypt\n";
}

try {
    sm2_sign($msg, [$priv_pem, $oversized_pass]);
    echo "FAIL: accepted oversized pass in sign\n";
} catch (ValueError $e) {
    echo "OK: oversized pass rejected in sign\n";
}

try {
    sm2_pkey_get_details([$priv_pem, $oversized_pass]);
    echo "FAIL: accepted oversized pass in get_details\n";
} catch (ValueError $e) {
    echo "OK: oversized pass rejected in get_details\n";
}
?>
--EXPECT--
OK: private key is encrypted
OK: missing passphrase fails non-interactively
OK: wrong passphrase rejected
OK: indexed array decrypt
OK: assoc array decrypt
OK: encrypted key sign & verify
OK: sm2_pkey_get_details with encrypted key
OK: sm2_pkey_get_details with wrong pass rejected
OK: binary passphrase roundtrip
OK: encrypted DER sign & verify
OK: encrypted DER wrong pass rejected
OK: encrypted DER trailing data rejected
OK: oversized pass rejected in keygen
OK: oversized pass rejected in decrypt
OK: oversized pass rejected in sign
OK: oversized pass rejected in get_details
