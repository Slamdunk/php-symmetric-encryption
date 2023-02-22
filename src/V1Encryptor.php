<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption;

final class V1Encryptor implements EncryptorInterface
{
    private string $key;

    public function __construct(string $key)
    {
        $this->key = sodium_base642bin($key, SODIUM_BASE64_VARIANT_ORIGINAL, '');
    }

    public static function generateKey(): string
    {
        return sodium_bin2base64(
            sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
            SODIUM_BASE64_VARIANT_ORIGINAL
        );
    }

    public function encrypt(string $plaintextMessage): string
    {
        $randnonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $nonce = sodium_crypto_generichash(
            $plaintextMessage,
            $randnonce,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        try {
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintextMessage,
                '',
                $nonce,
                $this->key
            );
        } catch (\SodiumException $sodiumException) {
            throw new EncryptorException('Encryption failed', 0, $sodiumException);
        }

        return sodium_bin2base64($nonce.$ciphertext, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public function decrypt(string $encryptedMessage): string
    {
        $encryptedMessage = sodium_base642bin($encryptedMessage, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '');

        $nonce = substr($encryptedMessage, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = substr($encryptedMessage, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $return = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',
            $nonce,
            $this->key
        );

        if (false === $return) {
            throw new EncryptorException('Decryption failed');
        }

        return $return;
    }
}
