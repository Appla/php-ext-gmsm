# php-ext-gmsm

[English](README.md) | [简体中文](README-zh.md)

基于 OpenSSL 1.1.1 或 3.x 的 PHP 8.3+ 国密扩展，提供 SM2、SM3、SM4（GB/T 32918、GB/T 32905、GB/T 32907）算法的高性能纯 C 实现。

## 安装与编译

### 使用 PIE 安装（推荐）

```bash
pie install appla/php-ext-gmsm
```

### 源码编译安装

```bash
phpize
./configure --enable-gmsm
make -j"$(nproc)" && make test
sudo make install        # 然后在 php.ini 中添加 extension=gmsm
```

与 PHP 自带的 `ext/openssl` 机制一致，扩展通过 `pkg-config` 自动定位 OpenSSL。请确保编译所用的 OpenSSL 与运行 PHP 的 OpenSSL 版本一致。若使用自定义安装路径，可添加配置参数：
`--with-gmsm-openssl=/opt/openssl`；底层的 `PKG_CONFIG_PATH`、`OPENSSL_CFLAGS` 与 `OPENSSL_LIBS` 环境变量同样支持覆盖。
所使用的 OpenSSL 必须包含 SM2、SM3 与 SM4 算法支持（若编译时指定了 `no-sm2`、`no-sm3` 或 `no-sm4`，扩展构建将报错中断）。
在 OpenSSL 3.x 中，运行时加载的 Provider 也必须提供相应算法。`phpinfo()` 会显示 SM3 和 SM4 的可用情况，并将 SM2 标为已编译支持。所需 Provider 算法不可用时，SM2 操作会失败；若 SM3 不可用，`sm3()` 和 `sm3_hmac()` 会抛出 `Error`。

## PHP 兼容性

扩展要求 PHP 8.3+。传入 `OpenSSLAsymmetricKey` 对象时，互操作依赖 PHP 的内部对象布局。
已在PHP 8.3~8.6 NTS 上验证对象互操作。

## API 列表

```php
sm2_keygen(?string $passphrase = null): array|false            // ['private_key' => PKCS#8 PEM, 'public_key' => SPKI PEM]
sm2_encrypt(string $data, string|OpenSSLAsymmetricKey $public_key, int $format = SM2_FMT_C1C3C2): string|false
sm2_decrypt(string $data, string|array|OpenSSLAsymmetricKey $private_key, int $format = SM2_FMT_C1C3C2): string|false
sm2_sign(string $data, string|array|OpenSSLAsymmetricKey $private_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): string|false
sm2_verify(string $data, string $signature, string|OpenSSLAsymmetricKey $public_key, ?string $user_id = null, int $format = SM2_SIG_ASN1): bool
sm2_pkey_get_details(string|array|OpenSSLAsymmetricKey $key): array|false   // ['bits', 'key', 'type' => 'sm2', 'sm2' => ['x', 'y', 'd'?]]
sm2_cipher_convert(string $data, int $from_format, int $to_format): string|false
sm2_sig_convert(string $signature, int $from_format, int $to_format): string|false
sm3(string $data, bool $binary = false): string
sm3_hmac(string $data, string $key, bool $binary = false): string
sm4_encrypt(string $data, string $key, string $iv, string $mode = "sm4-cbc", ?string &$tag = null, string $aad = ""): string|false
sm4_decrypt(string $data, string $key, string $iv, string $mode = "sm4-cbc", string $tag = "", string $aad = ""): string|false
```

常量定义：
- `SM2_FMT_ASN1`：ASN.1 DER 格式密文
- `SM2_FMT_C1C3C2`：GB/T 32918.4 国标格式密文（推荐）
- `SM2_FMT_C1C2C3`：旧标准草案格式密文
- `SM2_SIG_ASN1`：ASN.1 DER 格式签名
- `SM2_SIG_RAW_RS`：64 字节拼接签名（$r \parallel s$，常用于硬件及网关）

调用失败后，可立即通过 PHP 的 `openssl_error_string()` 读取 OpenSSL 诊断信息（需加载 ext/openssl），并重复调用直到返回 `false`。部分失败由 gmsm 在调用 OpenSSL 前检出，因此没有 OpenSSL 错误信息。密钥解码回退和公钥详情探测成功后，会清除这些探测过程中的预期错误。

### 密钥参数说明

密钥参数支持 PEM 或 DER 编码的字符串（SPKI、PKCS#8、加密受口令保护的 PKCS#8，或 SEC1 `EC PRIVATE KEY` 格式），或 PHP 原生 `OpenSSLAsymmetricKey` 资源对象。
私钥参数同时支持传递数组形式：`[$key, $passphrase]` 或 `['key' => ..., 'passphrase' => ...]`。公钥函数不接受数组传参，以防止私钥口令意外泄露在公钥调用栈中。若密钥字符串无法解码，函数将触发 `E_WARNING` 并返回 `false`。缺少口令的私钥将直接失败，不会引发终端交互提示。

每次传入字符串形式的密钥时均会执行解析。在 OpenSSL 3.0+ 中，每次解析约耗时 100–350 µs。因此在循环或高频操作中，推荐使用 `openssl_pkey_get_public()` / `openssl_pkey_get_private()` 将密钥预先解析为对象后复用传入。在 OpenSSL 3.0 下每次 `sm2_verify()` 可节省约 140 µs，在 OpenSSL 3.5 下可节省约 30 µs。

### 开发注意事项

- `$user_id = null` 默认使用 GM/T 0009 规定的默认值 `"1234567812345678"`；若传入 `""` 则表示独立的空用户 ID。用户 ID 最大长度支持 8190 字节。
- `sm2_keygen()` 口令长度必须为 1–1024 字节；若传入 `""` 将抛出 `ValueError`，避免误生成无口令保护的私钥。
- `sm2_encrypt()` 传入空消息时会抛出 `ValueError`（SM2 规范不支持加密 0 字节数据）。
- `sm2_cipher_convert()` 与 `sm2_sig_convert()` 仅执行纯语法层面的结构解析与编码转换（耗时 < 1 µs）。椭圆曲线点是否在曲线上及标量合法性由后续的 `sm2_decrypt()` / `sm2_verify()` 负责校验，因此非法点在后续解密/验签时才会报错。
- SM4 密钥长度固定为 16 字节。CBC、CTR、CFB、OFB 模式需要 16 字节 IV；ECB 模式 IV 必须传 `""`。CBC 与 ECB 模式默认采用 PKCS#7 填充。
- ECB 会泄露重复明文块的信息，仅为兼容现有系统而提供；不要用于一般数据加密。
- SM4-GCM 模式需要 12 字节 IV 和 16 字节 tag。在非 GCM 模式下传入 `$aad` 或非空的解密 `$tag` 会抛出异常，加密时 `sm4_encrypt()` 会将 `$tag` 置为 `null`（与 `openssl_encrypt()` 行为一致）。使用具名参数调用 GCM 时，必须显式传递 `tag:`；若跳过 `tag:` 直接命名 `aad:` 会抛出异常。
- 同一个密钥下绝不能重复使用 GCM IV。每次加密都用 `random_bytes(12)` 生成新 IV，并与密文和 tag 一起保存。
- SM4-GCM 未内置于 OpenSSL 1.1.1 或 3.0 中（需要较新的 OpenSSL 3.x，如 3.5.5）。在不支持该模式的环境中，调用 `sm4-gcm` 会触发警告并返回 `false`，可从 `phpinfo()` 中查看 SM4 的支持状态。
- 校验来自不可信来源的 HMAC 时，应使用 `hash_equals(sm3_hmac($data, $key, true), $receivedMac)`，不要使用 `===`。

## 开源协议

MIT
