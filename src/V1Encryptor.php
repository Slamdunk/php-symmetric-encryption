<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption;

final readonly class V1Encryptor implements EncryptorInterface
{
    /**
     * @var non-empty-string
     */
    private string $binaryKey;

    /**
     * @param non-empty-string $base64key
     */
    public function __construct(
        #[\SensitiveParameter]
        string $base64key
    ) {
        $binaryKey = sodium_base642bin($base64key, SODIUM_BASE64_VARIANT_ORIGINAL, '');
        \assert('' !== $binaryKey);
        $this->binaryKey = $binaryKey;
    }

    /**
     * @return non-empty-string
     *
     * @throws \SodiumException
     */
    public static function generateKey(): string
    {
        return sodium_bin2base64(
            sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
            SODIUM_BASE64_VARIANT_ORIGINAL
        );
    }

    /**
     * @throws \SodiumException
     */
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
                $this->binaryKey,
            );
        } catch (\SodiumException $sodiumException) {
            throw new EncryptorException('Encryption failed', 0, $sodiumException);
        }

        return sodium_bin2base64($nonce.$ciphertext, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * @throws \SodiumException
     */
    public function decrypt(string $encryptedMessage): string
    {
        $encryptedMessage = sodium_base642bin($encryptedMessage, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '');

        $nonce = substr($encryptedMessage, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = substr($encryptedMessage, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $return = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',
            $nonce,
            $this->binaryKey,
        );

        if (false === $return) {
            throw new EncryptorException('Decryption failed');
        }
        \assert('' !== $return);

        return $return;
    }
}
