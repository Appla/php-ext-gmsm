/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 61a95c427b6e6aab33a6ba5768acc2f84c8b3a50 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_keygen, 0, 0, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, passphrase, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_encrypt, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_MASK(0, public_key, MAY_BE_STRING|MAY_BE_OBJECT, NULL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, format, IS_LONG, 0, "SM2_FMT_C1C3C2")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_decrypt, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_MASK(0, private_key, MAY_BE_STRING|MAY_BE_ARRAY|MAY_BE_OBJECT, NULL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, format, IS_LONG, 0, "SM2_FMT_C1C3C2")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_sign, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_MASK(0, private_key, MAY_BE_STRING|MAY_BE_ARRAY|MAY_BE_OBJECT, NULL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, user_id, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, format, IS_LONG, 0, "SM2_SIG_ASN1")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_sm2_verify, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
	ZEND_ARG_TYPE_MASK(0, public_key, MAY_BE_STRING|MAY_BE_OBJECT, NULL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, user_id, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, format, IS_LONG, 0, "SM2_SIG_ASN1")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_pkey_get_details, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_MASK(0, key, MAY_BE_STRING|MAY_BE_ARRAY|MAY_BE_OBJECT, NULL)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_cipher_convert, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, from_format, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, to_format, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm2_sig_convert, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, from_format, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, to_format, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_sm3, 0, 1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, binary, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_sm3_hmac, 0, 2, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, binary, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm4_encrypt, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, iv, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mode, IS_STRING, 0, "\"sm4-cbc\"")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(1, tag, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, aad, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_sm4_decrypt, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, iv, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mode, IS_STRING, 0, "\"sm4-cbc\"")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, tag, IS_STRING, 0, "\"\"")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, aad, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()


ZEND_FUNCTION(sm2_keygen);
ZEND_FUNCTION(sm2_encrypt);
ZEND_FUNCTION(sm2_decrypt);
ZEND_FUNCTION(sm2_sign);
ZEND_FUNCTION(sm2_verify);
ZEND_FUNCTION(sm2_pkey_get_details);
ZEND_FUNCTION(sm2_cipher_convert);
ZEND_FUNCTION(sm2_sig_convert);
ZEND_FUNCTION(sm3);
ZEND_FUNCTION(sm3_hmac);
ZEND_FUNCTION(sm4_encrypt);
ZEND_FUNCTION(sm4_decrypt);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(sm2_keygen, arginfo_sm2_keygen)
	ZEND_FE(sm2_encrypt, arginfo_sm2_encrypt)
	ZEND_FE(sm2_decrypt, arginfo_sm2_decrypt)
	ZEND_FE(sm2_sign, arginfo_sm2_sign)
	ZEND_FE(sm2_verify, arginfo_sm2_verify)
	ZEND_FE(sm2_pkey_get_details, arginfo_sm2_pkey_get_details)
	ZEND_FE(sm2_cipher_convert, arginfo_sm2_cipher_convert)
	ZEND_FE(sm2_sig_convert, arginfo_sm2_sig_convert)
	ZEND_FE(sm3, arginfo_sm3)
	ZEND_FE(sm3_hmac, arginfo_sm3_hmac)
	ZEND_FE(sm4_encrypt, arginfo_sm4_encrypt)
	ZEND_FE(sm4_decrypt, arginfo_sm4_decrypt)
	ZEND_FE_END
};

static void register_gmsm_symbols(int module_number)
{
	REGISTER_LONG_CONSTANT("SM2_FMT_ASN1", SM2_FMT_ASN1, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SM2_FMT_C1C3C2", SM2_FMT_C1C3C2, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SM2_FMT_C1C2C3", SM2_FMT_C1C2C3, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SM2_SIG_ASN1", SM2_SIG_ASN1, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SM2_SIG_RAW_RS", SM2_SIG_RAW_RS, CONST_PERSISTENT);


	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm2_keygen", sizeof("sm2_keygen") - 1), 0, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm2_decrypt", sizeof("sm2_decrypt") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm2_sign", sizeof("sm2_sign") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm2_pkey_get_details", sizeof("sm2_pkey_get_details") - 1), 0, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm3_hmac", sizeof("sm3_hmac") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm4_encrypt", sizeof("sm4_encrypt") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "sm4_decrypt", sizeof("sm4_decrypt") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);
}
