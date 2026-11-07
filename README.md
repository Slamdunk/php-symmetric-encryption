# Slam / php-symmetric-encryption

[![Latest Stable Version](https://img.shields.io/packagist/v/slam/php-symmetric-encryption.svg)](https://packagist.org/packages/slam/php-symmetric-encryption)
[![Downloads](https://img.shields.io/packagist/dt/slam/php-symmetric-encryption.svg)](https://packagist.org/packages/slam/php-symmetric-encryption)
[![Integrate](https://github.com/Slamdunk/php-symmetric-encryption/workflows/CI/badge.svg?branch=master)](https://github.com/Slamdunk/php-symmetric-encryption/actions)
[![Infection MSI](https://badge.stryker-mutator.io/github.com/Slamdunk/php-symmetric-encryption/master)](https://dashboard.stryker-mutator.io/reports/github.com/Slamdunk/php-symmetric-encryption/master)

V1: encrypt strings with [`sodium_crypto_aead_xchacha20poly1305_ietf_encrypt`](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php) function.

V1 Stream: encrypt streams and files of any size with [`sodium_crypto_secretstream_xchacha20poly1305_*`](https://www.php.net/manual/en/function.sodium-crypto-secretstream-xchacha20poly1305-push.php) functions.

## Installation

To install with composer run the following command:

```console
$ composer require slam/php-symmetric-encryption
```

## Usage

```php
use SlamSymmetricEncryption\V1Encryptor;

// Generate a key and save it somewhere
$key = V1Encryptor::generateKey();
var_dump($key); // string(44) "Hog2u9jtOzyt+mPyAJwp8v3dI6Uvp1T4FUKrAjizVGo="

// Use the key
$encryptor = new V1Encryptor($key);

$ciphertext = $encryptor->encrypt('foo');
var_dump($ciphertext); // string(59) "dznmjbqHnI_26crKpRYvp125K9N6ctqU0kVCmoSRbG7HAKCIrnAz0RBELQ"

$plaintext = $encryptor->decrypt($ciphertext);
var_dump($plaintext); // string(3) "foo"
```

### Streams and files

`V1StreamEncryptor` uses the same key of `V1Encryptor`: the actual encryption key is derived from it with
[`sodium_crypto_kdf_derive_from_key`](https://www.php.net/manual/en/function.sodium-crypto-kdf-derive-from-key.php),
so the two constructions never share the same raw key.

```php
use SlamSymmetricEncryption\V1Encryptor;
use SlamSymmetricEncryption\V1StreamEncryptor;

$encryptor = new V1StreamEncryptor(V1Encryptor::generateKey());

// Files: the destination is written atomically, and left untouched on failure
$encryptor->encryptFile('/path/to/plaintext.csv', '/path/to/ciphertext.bin');
$encryptor->decryptFile('/path/to/ciphertext.bin', '/path/to/plaintext.csv');

// Streams: they are neither rewound nor closed
$encryptor->encryptStream($plaintextInput, $ciphertextOutput);
$encryptor->decryptStream($ciphertextInput, $plaintextOutput);
```

The plaintext is processed in chunks of 1 MiB, so memory usage is constant regardless of the stream size.

Every chunk is authenticated and the last one is marked as final: a truncated, reordered or tampered
ciphertext throws an `EncryptorException`.
Since `decryptStream` writes the plaintext while it reads the ciphertext, on exception the data already
written to the output stream must be discarded; `decryptFile` takes care of that by itself.

Binary format:

| Bytes | Content                                     |
|-------|---------------------------------------------|
| 10    | Magic: `SlamSymEnc`                         |
| 1     | Format version: `0x01`                      |
| 24    | Secretstream header                         |
| ...   | Chunks: up to 1 MiB + 17 bytes of MAC each  |
