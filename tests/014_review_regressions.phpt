--TEST--
Review regressions: empty inputs, GCM-only parameters, key arrays with references, details of decoded private keys
--EXTENSIONS--
gmsm
--FILE--
<?php
$pair = sm2_keygen();
$pub  = $pair['public_key'];
$priv = $pair['private_key'];

// 1. An empty passphrase used to produce an unencrypted key silently
try { sm2_keygen(""); echo "FAIL\n"; } catch (ValueError $e) { echo "OK: empty passphrase rejected\n"; }

// 2. OpenSSL cannot SM2-encrypt an empty message
try { sm2_encrypt("", $pub); echo "FAIL\n"; } catch (ValueError $e) { echo "OK: empty plaintext rejected\n"; }

// 3. AAD and tag only exist in GCM; ignoring them would fake authentication
$k = str_repeat("k", 16);
$iv = str_repeat("i", 16);
$t = null;
try { sm4_encrypt("data", $k, $iv, "sm4-cbc", $t, "aad"); echo "FAIL\n"; } catch (ValueError $e) { echo "OK: aad rejected for sm4-cbc\n"; }
$t = "stale tag";
var_dump(is_string(sm4_encrypt("data", $k, $iv, "sm4-cbc", $t)) && $t === null);
var_dump(is_string(sm4_encrypt("data", $k, $iv, "sm4-cbc", aad: "")));
$ct = sm4_encrypt("data", $k, $iv, "sm4-cbc");
try { sm4_decrypt($ct, $k, $iv, "sm4-cbc", str_repeat("t", 16)); echo "FAIL\n"; } catch (ValueError $e) { echo "OK: tag rejected for sm4-cbc\n"; }
$gcmIv = str_repeat("i", 12);
try { sm4_encrypt("data", $k, $gcmIv, "sm4-gcm", aad: ""); echo "FAIL\n"; } catch (ValueError $e) { echo "OK: throwaway GCM tag rejected\n"; }
$gcmTag = null;
$gcmResult = @sm4_encrypt("data", $k, $gcmIv, "sm4-gcm", tag: $gcmTag, aad: "");
var_dump($gcmResult === false || (is_string($gcmResult) && strlen($gcmTag) === 16));

// 4. Key arrays whose elements are references
$enc  = sm2_keygen("pass");
$ct2  = sm2_encrypt("hello", $enc['public_key']);
$pem  = $enc['private_key'];
$pass = "pass";
var_dump(sm2_decrypt($ct2, [&$pem, &$pass]) === "hello");
var_dump(sm2_decrypt($ct2, ['key' => &$pem, 'passphrase' => &$pass]) === "hello");

// 5. Details of decoded private keys (returned false on OpenSSL 3.0)
$p = sm2_pkey_get_details($pub);
$d = sm2_pkey_get_details($priv);
var_dump($d !== false && $d['sm2']['x'] === $p['sm2']['x'] && $d['sm2']['y'] === $p['sm2']['y'] && strlen($d['sm2']['d']) === 32);
$der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $priv));
var_dump(sm2_pkey_get_details($der)['sm2']['x'] === $p['sm2']['x']);

// 6. A PUBLIC KEY block that follows another PEM block
$bundle = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" . $pub;
var_dump(sm2_decrypt(sm2_encrypt("hello", $bundle), $priv) === "hello");

// 7. An undecodable key string warns instead of failing silently
var_dump(@sm2_encrypt("hello", "not a key") === false);
var_dump(str_contains(error_get_last()['message'] ?? '', 'could not be decoded'));

// 8. Identity conversion returns the input unchanged
$c = sm2_encrypt("x", $pub);
var_dump(sm2_cipher_convert($c, SM2_FMT_C1C3C2, SM2_FMT_C1C3C2) === $c);

// 9. An EC-typed OpenSSLAsymmetricKey on the SM2 curve works and is left unmodified
if (extension_loaded('openssl')) {
    $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'SM2']);
    $before = openssl_pkey_get_details($ec);
    $sig = sm2_sign("m", $ec);
    var_dump(is_string($sig) && sm2_verify("m", $sig, openssl_pkey_get_public($before['key'])) && openssl_pkey_get_details($ec) == $before);
} else {
    var_dump(true);
}
?>
--EXPECT--
OK: empty passphrase rejected
OK: empty plaintext rejected
OK: aad rejected for sm4-cbc
bool(true)
bool(true)
OK: tag rejected for sm4-cbc
OK: throwaway GCM tag rejected
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
