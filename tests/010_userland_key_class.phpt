--TEST--
A userland class named OpenSSLAsymmetricKey is never reinterpreted as ext/openssl's key object
--EXTENSIONS--
gmsm
--SKIPIF--
<?php if (extension_loaded('openssl')) die('skip only reachable when ext/openssl is not loaded'); ?>
--FILE--
<?php
final class OpenSSLAsymmetricKey { public $pkey = 0x41414141; }
try {
    sm2_encrypt("x", new OpenSSLAsymmetricKey());
    echo "FAIL\n";
} catch (TypeError $e) {
    echo "OK: TypeError\n";
}
?>
--EXPECT--
OK: TypeError
