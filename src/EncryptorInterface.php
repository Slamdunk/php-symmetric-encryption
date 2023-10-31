<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption;

interface EncryptorInterface
{
    /**
     * @param non-empty-string $plaintextMessage
     *
     * @return non-empty-string
     */
    public function encrypt(string $plaintextMessage): string;

    /**
     * @param non-empty-string $encryptedMessage
     *
     * @return non-empty-string
     */
    public function decrypt(string $encryptedMessage): string;
}
