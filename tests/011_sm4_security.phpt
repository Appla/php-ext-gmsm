--TEST--
SM4 security validation: non-SM4 ciphers, IV lengths, GCM tag length, CFB/OFB
--EXTENSIONS--
gmsm
--FILE--
<?php
$key16 = "0123456789abcdef";
$iv16  = "fedcba9876543210";
$iv12  = "123456789012";
$data  = "Sensitive Financial Payload 1234";

// 1. Invalid key length rejection
try {
    sm4_encrypt($data, "short_key", $iv16, "sm4-cbc");
    echo "FAIL: accepted short key\n";
} catch (ValueError $e) {
    echo "OK: key length rejected\n";
}

// 2. Non-SM4 cipher rejection
$non_sm4 = ["aes-128-cbc", "aes-256-cbc", "des-ede3-cbc", "chacha20", "foobar"];
foreach ($non_sm4 as $mode) {
    try {
        sm4_encrypt($data, $key16, $iv16, $mode);
        echo "FAIL: accepted mode $mode\n";
    } catch (ValueError $e) {
        // OK
    }
}
echo "OK: non-SM4 ciphers rejected\n";

// 3. Embedded NUL byte in mode rejection
try {
    sm4_encrypt($data, $key16, $iv16, "sm4-cbc\0extra");
    echo "FAIL: accepted mode with embedded NUL\n";
} catch (ValueError $e) {
    echo "OK: embedded NUL mode rejected\n";
}

// 4. Invalid IV length for CBC/CTR/CFB/OFB
foreach (["sm4-cbc", "sm4-ctr", "sm4-cfb", "sm4-ofb"] as $m) {
    try {
        sm4_encrypt($data, $key16, "short_iv", $m);
        echo "FAIL: accepted short IV in $m\n";
    } catch (ValueError $e) {
        // OK
    }
    try {
        sm4_encrypt($data, $key16, "", $m);
        echo "FAIL: accepted empty IV in $m\n";
    } catch (ValueError $e) {
        // OK
    }
}
echo "OK: invalid IV rejected for CBC/CTR/CFB/OFB\n";

// 5. ECB mode: must NOT accept an IV
try {
    sm4_encrypt($data, $key16, $iv16, "sm4-ecb");
    echo "FAIL: accepted IV in ECB mode\n";
} catch (ValueError $e) {
    echo "OK: ECB with IV rejected\n";
}
// ECB with empty IV succeeds
$ecb_ct = sm4_encrypt($data, $key16, "", "sm4-ecb");
$ecb_pt = sm4_decrypt($ecb_ct, $key16, "", "sm4-ecb");
echo ($ecb_pt === $data) ? "OK: ECB roundtrip\n" : "FAIL: ECB roundtrip\n";

// 6. CFB and OFB roundtrips
$cfb_ct = sm4_encrypt($data, $key16, $iv16, "sm4-cfb");
$cfb_pt = sm4_decrypt($cfb_ct, $key16, $iv16, "sm4-cfb");
echo ($cfb_pt === $data) ? "OK: CFB roundtrip\n" : "FAIL: CFB roundtrip\n";

$ofb_ct = sm4_encrypt($data, $key16, $iv16, "sm4-ofb");
$ofb_pt = sm4_decrypt($ofb_ct, $key16, $iv16, "sm4-ofb");
echo ($ofb_pt === $data) ? "OK: OFB roundtrip\n" : "FAIL: OFB roundtrip\n";

// 7. Default mode is sm4-cbc and IV is required
$def_ct = sm4_encrypt($data, $key16, $iv16);
$def_pt = sm4_decrypt($def_ct, $key16, $iv16);
echo ($def_pt === $data) ? "OK: default mode sm4-cbc roundtrip\n" : "FAIL: default mode roundtrip\n";

try {
    sm4_encrypt($data, $key16);
    echo "FAIL: accepted missing IV in sm4_encrypt\n";
} catch (ArgumentCountError $e) {
    echo "OK: IV required in sm4_encrypt\n";
}

try {
    sm4_decrypt($def_ct, $key16);
    echo "FAIL: accepted missing IV in sm4_decrypt\n";
} catch (ArgumentCountError $e) {
    echo "OK: IV required in sm4_decrypt\n";
}
?>
--EXPECT--
OK: key length rejected
OK: non-SM4 ciphers rejected
OK: embedded NUL mode rejected
OK: invalid IV rejected for CBC/CTR/CFB/OFB
OK: ECB with IV rejected
OK: ECB roundtrip
OK: CFB roundtrip
OK: OFB roundtrip
OK: default mode sm4-cbc roundtrip
OK: IV required in sm4_encrypt
OK: IV required in sm4_decrypt

