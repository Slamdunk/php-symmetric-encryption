<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption;

interface StreamEncryptorInterface
{
    /**
     * Reads the plaintext from $input until EOF and writes the ciphertext to $output.
     *
     * Streams are neither rewound nor closed.
     *
     * @param resource $input
     * @param resource $output
     *
     * @throws EncryptorException
     */
    public function encryptStream($input, $output): void;

    /**
     * Reads the ciphertext from $input until EOF and writes the plaintext to $output.
     *
     * The plaintext is written to $output while it gets authenticated, chunk by chunk:
     * if an exception is thrown, what has been written to $output so far MUST be discarded.
     *
     * Streams are neither rewound nor closed.
     *
     * @param resource $input
     * @param resource $output
     *
     * @throws EncryptorException
     */
    public function decryptStream($input, $output): void;

    /**
     * Encrypts $sourcePath into $destinationPath, atomically: on failure $destinationPath is left untouched.
     *
     * @throws EncryptorException
     */
    public function encryptFile(string $sourcePath, string $destinationPath): void;

    /**
     * Decrypts $sourcePath into $destinationPath, atomically: on failure $destinationPath is left untouched.
     *
     * @throws EncryptorException
     */
    public function decryptFile(string $sourcePath, string $destinationPath): void;
}
