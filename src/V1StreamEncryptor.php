<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption;

/**
 * Encrypts streams with sodium_crypto_secretstream_xchacha20poly1305, in chunks of 1 MiB.
 *
 * Binary format: MAGIC . VERSION . secretstream header . encrypted chunks
 *
 * Every chunk is authenticated, with MAGIC . VERSION as additional data, and the last one
 * carries TAG_FINAL: a truncated, reordered or tampered stream fails decryption.
 *
 * The key is the same base64 key of V1Encryptor: the actual encryption key is derived from it
 * with sodium_crypto_kdf_derive_from_key, so the two constructions never share the same raw key.
 */
final readonly class V1StreamEncryptor implements StreamEncryptorInterface
{
    public const string MAGIC = 'SlamSymEnc';
    public const string VERSION = "\x01";

    private const string PREFIX = self::MAGIC.self::VERSION;
    private const int CHUNK_SIZE = 1024 * 1024;
    private const string KDF_CONTEXT = 'SlamStrm';
    private const int KDF_SUBKEY_ID = 1;

    /**
     * @var non-empty-string
     */
    private string $key;

    /**
     * @param non-empty-string $base64key the same kind of key of V1Encryptor, see V1Encryptor::generateKey()
     *
     * @throws EncryptorException
     */
    public function __construct(
        #[\SensitiveParameter]
        string $base64key
    ) {
        try {
            $key = sodium_crypto_kdf_derive_from_key(
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                self::KDF_SUBKEY_ID,
                self::KDF_CONTEXT,
                sodium_base642bin($base64key, SODIUM_BASE64_VARIANT_ORIGINAL, ''),
            );
        } catch (\SodiumException $sodiumException) {
            throw new EncryptorException('Invalid key', 0, $sodiumException);
        }
        \assert('' !== $key);
        $this->key = $key;
    }

    public function encryptStream($input, $output): void
    {
        /** @var array{string, string} $stateAndHeader */
        $stateAndHeader = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        [$state, $header] = $stateAndHeader;
        self::write($output, self::PREFIX.$header);

        $chunk = self::read($input, self::CHUNK_SIZE);
        do {
            $nextChunk = self::read($input, self::CHUNK_SIZE);
            self::write($output, sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $chunk,
                self::PREFIX,
                '' === $nextChunk
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
            ));
            $chunk = $nextChunk;
        } while ('' !== $chunk);
    }

    public function decryptStream($input, $output): void
    {
        $header = self::read($input, \strlen(self::PREFIX) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (
            \strlen($header) !== \strlen(self::PREFIX) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
            || !str_starts_with($header, self::PREFIX)
        ) {
            throw new EncryptorException('Unrecognized format or version');
        }

        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(
            substr($header, \strlen(self::PREFIX)),
            $this->key,
        );

        do {
            $chunk = self::read($input, self::CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            if ('' === $chunk) {
                throw new EncryptorException('Decryption failed: truncated stream');
            }

            /** @var array{string, int}|false $result */
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk, self::PREFIX);
            if (false === $result) {
                throw new EncryptorException('Decryption failed');
            }

            [$plaintext, $tag] = $result;
            self::write($output, $plaintext);
        } while (SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL !== $tag);

        if (false !== fgetc($input)) {
            throw new EncryptorException('Decryption failed: unexpected data after the final chunk');
        }
    }

    public function encryptFile(string $sourcePath, string $destinationPath): void
    {
        self::processFile($sourcePath, $destinationPath, $this->encryptStream(...));
    }

    public function decryptFile(string $sourcePath, string $destinationPath): void
    {
        self::processFile($sourcePath, $destinationPath, $this->decryptStream(...));
    }

    /**
     * @param \Closure(resource, resource): void $process
     */
    private static function processFile(string $sourcePath, string $destinationPath, \Closure $process): void
    {
        $input = self::open($sourcePath, 'rb');

        try {
            // Same directory of the destination, so that the final rename is atomic
            $temporaryPath = \sprintf('%s.%s.tmp', $destinationPath, uniqid());
            $output = self::open($temporaryPath, 'xb');

            try {
                try {
                    $process($input, $output);
                } finally {
                    fclose($output);
                }

                if (!@rename($temporaryPath, $destinationPath)) {
                    throw new EncryptorException(\sprintf('Unable to rename "%s" to "%s"', $temporaryPath, $destinationPath));
                }
            } catch (\Throwable $throwable) {
                unlink($temporaryPath);

                throw $throwable;
            }
        } finally {
            fclose($input);
        }
    }

    /**
     * @return resource
     */
    private static function open(string $path, string $mode)
    {
        $stream = @fopen($path, $mode);
        if (false === $stream) {
            throw new EncryptorException(\sprintf('Unable to open "%s"', $path));
        }

        return $stream;
    }

    /**
     * Reads up to $length bytes, less only on EOF: unlike fread, short reads of
     * network, compression or other filtered streams are not a concern.
     *
     * @param resource     $stream
     * @param positive-int $length
     */
    private static function read($stream, int $length): string
    {
        $data = '';
        while (($missing = $length - \strlen($data)) > 0) {
            $read = fread($stream, $missing);
            if (false === $read) {
                throw new EncryptorException('Unable to read from stream');
            }
            if ('' === $read) {
                break;
            }
            $data .= $read;
        }

        return $data;
    }

    /**
     * @param resource $stream
     */
    private static function write($stream, string $data): void
    {
        if (fwrite($stream, $data) !== \strlen($data)) {
            throw new EncryptorException('Unable to write to stream');
        }
    }
}
