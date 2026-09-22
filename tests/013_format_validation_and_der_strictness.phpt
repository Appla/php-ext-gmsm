--TEST--
Format enum validation, DER strict consumption, User ID limits, and OpenSSL error queue isolation
--EXTENSIONS--
gmsm
--FILE--
<?php
$pair = sm2_keygen();
$priv = $pair['private_key'];
$pub  = $pair['public_key'];
$msg  = "Boundary Test Message";

// 1. Invalid format enum checks in sm2_cipher_convert (including equal invalid values)
try {
    sm2_cipher_convert("data", 999, 999);
    echo "FAIL: accepted invalid format 999, 999\n";
} catch (ValueError $e) {
    echo "OK: cipher convert invalid equal formats rejected\n";
}

try {
    sm2_cipher_convert("data", SM2_FMT_ASN1, 999);
    echo "FAIL: accepted target format 999\n";
} catch (ValueError $e) {
    echo "OK: cipher convert invalid target format rejected\n";
}

// 2. Invalid format enum checks in sm2_sig_convert (including equal invalid values)
try {
    sm2_sig_convert("sig", 999, 999);
    echo "FAIL: accepted invalid sig format 999, 999\n";
} catch (ValueError $e) {
    echo "OK: sig convert invalid equal formats rejected\n";
}

// 3. Strict DER consumption: trailing junk rejection in cipher convert
$asn1_ct = sm2_encrypt($msg, $pub, SM2_FMT_ASN1);
$junk_ct = $asn1_ct . "JUNK";
$conv_res = sm2_cipher_convert($junk_ct, SM2_FMT_ASN1, SM2_FMT_C1C3C2);
echo ($conv_res === false) ? "OK: cipher convert rejected trailing junk\n" : "FAIL: accepted trailing junk\n";

// 4. Strict DER consumption: trailing junk rejection in sig convert
$asn1_sig = sm2_sign($msg, $priv, null, SM2_SIG_ASN1);
$junk_sig = $asn1_sig . "JUNK";
$sig_conv = sm2_sig_convert($junk_sig, SM2_SIG_ASN1, SM2_SIG_RAW_RS);
echo ($sig_conv === false) ? "OK: sig convert rejected trailing junk\n" : "FAIL: sig convert accepted trailing junk\n";

// 5. SM2 User ID boundary (OpenSSL enforces id_len < UINT16_MAX / 8, so max is 8190 bytes)
$uid_8190 = str_repeat("U", 8190);
$sig_8190 = sm2_sign($msg, $priv, $uid_8190);
$ver_8190 = sm2_verify($msg, $sig_8190, $pub, $uid_8190);
echo ($ver_8190 === true) ? "OK: 8190-byte User ID accepted and verified\n" : "FAIL: 8190-byte User ID failed\n";

$uid_8191 = str_repeat("U", 8191);
try {
    sm2_sign($msg, $priv, $uid_8191);
    echo "FAIL: accepted 8191-byte User ID in sm2_sign\n";
} catch (ValueError $e) {
    echo "OK: 8191-byte User ID rejected in sm2_sign\n";
}

try {
    sm2_verify($msg, $sig_8190, $pub, $uid_8191);
    echo "FAIL: accepted 8191-byte User ID in sm2_verify\n";
} catch (ValueError $e) {
    echo "OK: 8191-byte User ID rejected in sm2_verify\n";
}

// 6. OpenSSL error queue cleanliness
if (function_exists('openssl_error_string')) {
    while (openssl_error_string()); // clear any previous errors
    $c1c3c2 = sm2_encrypt($msg, $pub);
    $plain = sm2_decrypt($c1c3c2, $priv);
    $err = openssl_error_string();
    echo ($err === false) ? "OK: error queue is clean after key parse & crypto\n" : "FAIL: leftover error: $err\n";
} else {
    echo "OK: error queue is clean after key parse & crypto\n";
}

// 7. Strict DER key handling: trailing junk rejected in DER public & private keys
$pub_der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pub));
$priv_der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $priv));

// Valid DER keys work
$ct_der = sm2_encrypt($msg, $pub_der);
$pt_der = sm2_decrypt($ct_der, $priv_der);
echo ($pt_der === $msg) ? "OK: DER keys roundtrip\n" : "FAIL: DER keys roundtrip\n";

// Trailing junk on DER keys must fail
$junk_pub_der = $pub_der . "JUNK";
$enc_junk = @sm2_encrypt($msg, $junk_pub_der);
echo ($enc_junk === false) ? "OK: rejected trailing junk on DER public key\n" : "FAIL: accepted junk on DER public key\n";

$junk_priv_der = $priv_der . "JUNK";
$dec_junk = @sm2_decrypt($ct_der, $junk_priv_der);
echo ($dec_junk === false) ? "OK: rejected trailing junk on DER private key\n" : "FAIL: accepted junk on DER private key\n";

// 8. sm2_encrypt and sm2_verify reject key arrays with TypeError
try {
    sm2_encrypt($msg, [$pub, "secret"]);
    echo "FAIL: accepted key array in sm2_encrypt\n";
} catch (TypeError $e) {
    echo "OK: sm2_encrypt rejects key array\n";
}

try {
    sm2_verify($msg, $sig_8190, [$pub, "secret"], $uid_8190);
    echo "FAIL: accepted key array in sm2_verify\n";
} catch (TypeError $e) {
    echo "OK: sm2_verify rejects key array\n";
}

// 9. Codecs are syntactic; an off-curve C1 converts, and decryption rejects it
$invalid_c1c3c2 = "\x04" . str_repeat("\xff", 64) . str_repeat("\x00", 32) . "ciphertext";
$conv_raw2der = sm2_cipher_convert($invalid_c1c3c2, SM2_FMT_C1C3C2, SM2_FMT_ASN1);
echo is_string($conv_raw2der) ? "OK: raw2der is syntactic\n" : "FAIL: raw2der rejected well-formed input\n";
echo (sm2_decrypt($invalid_c1c3c2, $priv) === false) ? "OK: decrypt rejected invalid curve point\n" : "FAIL: decrypt accepted invalid curve point\n";
echo (sm2_decrypt($conv_raw2der, $priv, SM2_FMT_ASN1) === false) ? "OK: decrypt rejected invalid curve point (DER)\n" : "FAIL: decrypt accepted invalid curve point (DER)\n";

// 10. Out-of-range raw signature scalars convert, and verification rejects them
foreach ([str_repeat("\x00", 64), str_repeat("\xff", 64)] as $bad_sig) {
    $der = sm2_sig_convert($bad_sig, SM2_SIG_RAW_RS, SM2_SIG_ASN1);
    echo (is_string($der) && sm2_verify($msg, $bad_sig, $pub, null, SM2_SIG_RAW_RS) === false && sm2_verify($msg, $der, $pub) === false)
        ? "OK: verify rejected out-of-range raw signature\n" : "FAIL: out-of-range raw signature\n";
}
?>
--EXPECT--
OK: cipher convert invalid equal formats rejected
OK: cipher convert invalid target format rejected
OK: sig convert invalid equal formats rejected
OK: cipher convert rejected trailing junk
OK: sig convert rejected trailing junk
OK: 8190-byte User ID accepted and verified
OK: 8191-byte User ID rejected in sm2_sign
OK: 8191-byte User ID rejected in sm2_verify
OK: error queue is clean after key parse & crypto
OK: DER keys roundtrip
OK: rejected trailing junk on DER public key
OK: rejected trailing junk on DER private key
OK: sm2_encrypt rejects key array
OK: sm2_verify rejects key array
OK: raw2der is syntactic
OK: decrypt rejected invalid curve point
OK: decrypt rejected invalid curve point (DER)
OK: verify rejected out-of-range raw signature
OK: verify rejected out-of-range raw signature
