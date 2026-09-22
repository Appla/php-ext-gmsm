--TEST--
Check for gmsm extension presence and module info
--SKIPIF--
<?php if (!extension_loaded("gmsm")) print "skip"; ?>
--FILE--
<?php
echo "gmsm extension is loaded\n";
var_dump(defined('SM2_FMT_ASN1') && SM2_FMT_ASN1 === 0);
var_dump(defined('SM2_FMT_C1C3C2') && SM2_FMT_C1C3C2 === 1);
var_dump(defined('SM2_FMT_C1C2C3') && SM2_FMT_C1C2C3 === 2);
var_dump(defined('SM2_SIG_ASN1') && SM2_SIG_ASN1 === 0);
var_dump(defined('SM2_SIG_RAW_RS') && SM2_SIG_RAW_RS === 1);

ob_start();
phpinfo(INFO_MODULES);
$info = ob_get_clean();
var_dump(str_contains($info, 'gmsm support => enabled'));
var_dump(str_contains($info, 'SM2 asymmetric cryptography => compiled (GB/T 32918)'));
?>
--EXPECT--
gmsm extension is loaded
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
