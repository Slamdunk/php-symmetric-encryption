<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption\Test;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SlamSymmetricEncryption\EncryptorException;
use SlamSymmetricEncryption\V1Encryptor;
use SlamSymmetricEncryption\V1StreamEncryptor;

/**
 * @internal
 */
#[CoversClass(V1StreamEncryptor::class)]
final class V1StreamEncryptorTest extends TestCase
{
    private const string KEY = 'Hog2u9jtOzyt+mPyAJwp8v3dI6Uvp1T4FUKrAjizVGo=';
    private const int CHUNK_SIZE = 1024 * 1024;
    private const int HEADER_LENGTH = 11 + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
    private const int ABYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    private V1StreamEncryptor $encryptor;
    private string $directory;

    protected function setUp(): void
    {
        $this->encryptor = new V1StreamEncryptor(self::KEY);

        $this->directory = sys_get_temp_dir().'/'.uniqid('slam_symmetric_encryption_');
        mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        if (\in_array(TestStreamWrapper::PROTOCOL, stream_get_wrappers(), true)) {
            TestStreamWrapper::unregister();
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->directory, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($files as $file) {
            \assert($file instanceof \SplFileInfo);
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->directory);
    }

    public function testFormatConsistency(): void
    {
        $ciphertext = base64_decode('U2xhbVN5bUVuYwEnI+BmTpNaKozqeq7vVqwvGAouo053EX8gyFg9uzDt5rwuJ9+Q9+Yv1n+wvw==', true);

        self::assertSame('foo', self::decrypt($ciphertext));
    }

    public function testFormatHeader(): void
    {
        $ciphertext = self::encrypt('foo');

        self::assertStringStartsWith("SlamSymEnc\x01", $ciphertext);
        self::assertStringStartsWith(V1StreamEncryptor::MAGIC.V1StreamEncryptor::VERSION, $ciphertext);
    }

    public function testCiphertextIsRandomized(): void
    {
        self::assertNotSame(self::encrypt('foo'), self::encrypt('foo'));
    }

    public function testKeyIsCompatibleWithV1EncryptorOne(): void
    {
        $encryptor = new V1StreamEncryptor(V1Encryptor::generateKey());

        $plaintext = random_bytes(100);

        self::assertSame($plaintext, self::decrypt(self::encrypt($plaintext, $encryptor), $encryptor));
    }

    #[DataProvider('provideRoundTripCases')]
    public function testRoundTrip(int $plaintextLength, int $expectedChunks): void
    {
        $plaintext = random_bytes(max(1, $plaintextLength));
        $plaintext = substr($plaintext, 0, $plaintextLength);

        $ciphertext = self::encrypt($plaintext);

        self::assertSame(
            self::HEADER_LENGTH + $plaintextLength + $expectedChunks * self::ABYTES,
            \strlen($ciphertext),
        );
        if ('' !== $plaintext) {
            self::assertStringNotContainsString($plaintext, substr($ciphertext, self::HEADER_LENGTH));
        }
        self::assertSame($plaintext, self::decrypt($ciphertext));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideRoundTripCases(): iterable
    {
        yield 'empty' => [0, 1];

        yield 'one byte' => [1, 1];

        yield 'chunk size - 1' => [self::CHUNK_SIZE - 1, 1];

        yield 'chunk size' => [self::CHUNK_SIZE, 1];

        yield 'chunk size + 1' => [self::CHUNK_SIZE + 1, 2];

        yield 'two chunks' => [2 * self::CHUNK_SIZE, 2];

        yield 'three chunks' => [2 * self::CHUNK_SIZE + 1, 3];
    }

    public function testShortReadsOfInputStreamsAreHandled(): void
    {
        $plaintext = random_bytes(self::CHUNK_SIZE + 12345);

        TestStreamWrapper::register();
        TestStreamWrapper::$data = $plaintext;
        $input = fopen(TestStreamWrapper::PROTOCOL.'://plaintext', 'r');
        \assert(false !== $input);
        $output = self::memoryStream();
        $this->encryptor->encryptStream($input, $output);
        $ciphertext = self::contents($output);

        self::assertSame(self::HEADER_LENGTH + \strlen($plaintext) + 2 * self::ABYTES, \strlen($ciphertext));

        TestStreamWrapper::$data = $ciphertext;
        $input = fopen(TestStreamWrapper::PROTOCOL.'://ciphertext', 'r');
        \assert(false !== $input);
        $output = self::memoryStream();
        $this->encryptor->decryptStream($input, $output);

        self::assertSame($plaintext, self::contents($output));
    }

    public function testCompressedStreamsCanBeUsed(): void
    {
        $plaintext = str_repeat('foo bar baz ', 300_000);
        $compressedPath = $this->directory.'/compressed.gz';
        $encryptedPath = $this->directory.'/encrypted.bin';
        $decryptedPath = $this->directory.'/decrypted.gz';

        file_put_contents('compress.zlib://'.$compressedPath, $plaintext);

        $this->encryptor->encryptFile($compressedPath, $encryptedPath);
        self::assertLessThan(\strlen($plaintext) / 10, filesize($encryptedPath));

        $this->encryptor->decryptFile($encryptedPath, $decryptedPath);
        self::assertSame($plaintext, file_get_contents('compress.zlib://'.$decryptedPath));
    }

    public function testInvalidKey(): void
    {
        try {
            new V1StreamEncryptor(base64_encode('foo'));
            self::fail('Exception expected');
        } catch (EncryptorException $encryptorException) {
            self::assertSame('Invalid key', $encryptorException->getMessage());
            self::assertSame(0, $encryptorException->getCode());
            self::assertInstanceOf(\SodiumException::class, $encryptorException->getPrevious());
        }
    }

    public function testWrongKey(): void
    {
        $ciphertext = self::encrypt('foo');

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Decryption failed');

        self::decrypt($ciphertext, new V1StreamEncryptor(V1Encryptor::generateKey()));
    }

    #[DataProvider('provideUnrecognizedFormatCases')]
    public function testUnrecognizedFormat(string $ciphertext): void
    {
        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Unrecognized format or version');

        self::decrypt($ciphertext);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnrecognizedFormatCases(): iterable
    {
        $ciphertext = self::encrypt('foo');

        yield 'empty' => [''];

        yield 'magic only' => ['SlamSymEnc'];

        yield 'truncated header' => [substr($ciphertext, 0, self::HEADER_LENGTH - 1)];

        yield 'wrong magic' => ['X'.substr($ciphertext, 1)];

        yield 'wrong version' => [substr_replace($ciphertext, "\x02", 10, 1)];

        yield 'V1Encryptor message' => [(new V1Encryptor(self::KEY))->encrypt(str_repeat('foo', 100))];
    }

    public function testTamperedSecretstreamHeader(): void
    {
        $ciphertext = self::encrypt('foo');
        $ciphertext = $this->flipByte($ciphertext, self::HEADER_LENGTH - 1);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Decryption failed');

        self::decrypt($ciphertext);
    }

    public function testTamperedChunk(): void
    {
        $ciphertext = self::encrypt(random_bytes(self::CHUNK_SIZE + 10));
        $ciphertext = $this->flipByte($ciphertext, self::HEADER_LENGTH + 100);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Decryption failed');

        self::decrypt($ciphertext);
    }

    public function testReorderedChunks(): void
    {
        $ciphertext = self::encrypt(random_bytes(2 * self::CHUNK_SIZE + 10));
        $encryptedChunkLength = self::CHUNK_SIZE + self::ABYTES;
        $ciphertext = substr($ciphertext, 0, self::HEADER_LENGTH)
            .substr($ciphertext, self::HEADER_LENGTH + $encryptedChunkLength, $encryptedChunkLength)
            .substr($ciphertext, self::HEADER_LENGTH, $encryptedChunkLength)
            .substr($ciphertext, self::HEADER_LENGTH + 2 * $encryptedChunkLength);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Decryption failed');

        self::decrypt($ciphertext);
    }

    public function testWrongAdditionalData(): void
    {
        /** @var array{string, string} $stateAndHeader */
        $stateAndHeader = sodium_crypto_secretstream_xchacha20poly1305_init_push(
            sodium_crypto_kdf_derive_from_key(
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                1,
                'SlamStrm',
                sodium_base642bin(self::KEY, SODIUM_BASE64_VARIANT_ORIGINAL),
            ),
        );
        [$state, $header] = $stateAndHeader;
        $prefix = V1StreamEncryptor::MAGIC.V1StreamEncryptor::VERSION;
        $ciphertext = $prefix.$header.sodium_crypto_secretstream_xchacha20poly1305_push(
            $state,
            'foo',
            '',
            SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
        );

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Decryption failed');

        self::decrypt($ciphertext);
    }

    /**
     * @param positive-int $plaintextLength
     */
    #[DataProvider('provideTruncatedStreamCases')]
    public function testTruncatedStream(int $plaintextLength, int $removedBytes, string $expectedMessage): void
    {
        $ciphertext = self::encrypt(random_bytes($plaintextLength));
        $ciphertext = substr($ciphertext, 0, -$removedBytes);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage($expectedMessage);

        self::decrypt($ciphertext);
    }

    /**
     * @return iterable<string, array{positive-int, int, string}>
     */
    public static function provideTruncatedStreamCases(): iterable
    {
        yield 'header only' => [10, 10 + self::ABYTES, 'Decryption failed: truncated stream'];

        yield 'last byte missing' => [10, 1, 'Decryption failed'];

        yield 'last chunk missing' => [self::CHUNK_SIZE + 10, 10 + self::ABYTES, 'Decryption failed: truncated stream'];

        yield 'last chunk partially missing' => [self::CHUNK_SIZE + 10, 5, 'Decryption failed'];

        yield 'last full chunk missing' => [2 * self::CHUNK_SIZE, self::CHUNK_SIZE + self::ABYTES, 'Decryption failed: truncated stream'];
    }

    /**
     * @param positive-int $plaintextLength
     */
    #[DataProvider('provideTrailingDataAfterFinalChunkCases')]
    public function testTrailingDataAfterFinalChunk(int $plaintextLength, string $expectedMessage): void
    {
        $ciphertext = self::encrypt(random_bytes($plaintextLength)).'x';

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage($expectedMessage);

        self::decrypt($ciphertext);
    }

    /**
     * @return iterable<string, array{positive-int, string}>
     */
    public static function provideTrailingDataAfterFinalChunkCases(): iterable
    {
        // The trailing data is read together with the last chunk, failing its authentication
        yield 'short last chunk' => [10, 'Decryption failed'];

        yield 'full last chunk' => [self::CHUNK_SIZE, 'Decryption failed: unexpected data after the final chunk'];
    }

    public function testReadFailure(): void
    {
        TestStreamWrapper::register();
        TestStreamWrapper::$data = 'foo';
        TestStreamWrapper::$failRead = true;
        $input = fopen(TestStreamWrapper::PROTOCOL.'://plaintext', 'r');
        \assert(false !== $input);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Unable to read from stream');

        $this->encryptor->encryptStream($input, self::memoryStream());
    }

    public function testWriteFailure(): void
    {
        TestStreamWrapper::register();
        TestStreamWrapper::$failWrite = true;
        $output = fopen(TestStreamWrapper::PROTOCOL.'://ciphertext', 'w');
        \assert(false !== $output);

        $this->expectException(EncryptorException::class);
        $this->expectExceptionMessage('Unable to write to stream');

        $this->encryptor->encryptStream(self::memoryStream('foo'), $output);
    }

    public function testFileRoundTrip(): void
    {
        $plaintext = random_bytes(self::CHUNK_SIZE + 10);
        $plaintextPath = $this->directory.'/plaintext.bin';
        $encryptedPath = $this->directory.'/encrypted.bin';
        $decryptedPath = $this->directory.'/decrypted.bin';
        file_put_contents($plaintextPath, $plaintext);
        $openStreams = \count(get_resources('stream'));

        $this->encryptor->encryptFile($plaintextPath, $encryptedPath);

        $ciphertext = file_get_contents($encryptedPath);
        \assert(\is_string($ciphertext));
        self::assertSame($plaintext, self::decrypt($ciphertext));

        $this->encryptor->decryptFile($encryptedPath, $decryptedPath);

        self::assertSame($plaintext, file_get_contents($decryptedPath));
        self::assertSame(['decrypted.bin', 'encrypted.bin', 'plaintext.bin'], $this->directoryContents());
        self::assertCount($openStreams, get_resources('stream'));
    }

    public function testFileDestinationIsOverwritten(): void
    {
        $plaintextPath = $this->directory.'/plaintext.txt';
        $encryptedPath = $this->directory.'/encrypted.bin';
        file_put_contents($plaintextPath, 'foo');
        file_put_contents($encryptedPath, 'bar');

        $this->encryptor->encryptFile($plaintextPath, $encryptedPath);

        $ciphertext = file_get_contents($encryptedPath);
        \assert(\is_string($ciphertext));
        self::assertSame('foo', self::decrypt($ciphertext));
    }

    public function testFileMissingSource(): void
    {
        $openStreams = \count(get_resources('stream'));

        try {
            $this->encryptor->encryptFile($this->directory.'/missing.txt', $this->directory.'/encrypted.bin');
            self::fail('Exception expected');
        } catch (EncryptorException $encryptorException) {
            self::assertStringContainsString('Unable to open', $encryptorException->getMessage());
            self::assertStringContainsString('missing.txt', $encryptorException->getMessage());
        }

        self::assertSame([], $this->directoryContents());
        self::assertCount($openStreams, get_resources('stream'));
    }

    public function testFileMissingDestinationDirectory(): void
    {
        $plaintextPath = $this->directory.'/plaintext.txt';
        file_put_contents($plaintextPath, 'foo');
        $openStreams = \count(get_resources('stream'));

        try {
            $this->encryptor->encryptFile($plaintextPath, $this->directory.'/missing/encrypted.bin');
            self::fail('Exception expected');
        } catch (EncryptorException $encryptorException) {
            self::assertStringContainsString('Unable to open', $encryptorException->getMessage());
            self::assertStringContainsString('/missing/encrypted.bin', $encryptorException->getMessage());
        }

        self::assertSame(['plaintext.txt'], $this->directoryContents());
        self::assertCount($openStreams, get_resources('stream'));
    }

    public function testFileDecryptionFailureLeavesDestinationUntouched(): void
    {
        $plaintextPath = $this->directory.'/plaintext.bin';
        $encryptedPath = $this->directory.'/encrypted.bin';
        $decryptedPath = $this->directory.'/decrypted.bin';
        file_put_contents($plaintextPath, random_bytes(self::CHUNK_SIZE + 10));
        $this->encryptor->encryptFile($plaintextPath, $encryptedPath);
        file_put_contents($decryptedPath, 'previous content');

        $ciphertext = file_get_contents($encryptedPath);
        \assert(\is_string($ciphertext));
        file_put_contents($encryptedPath, substr($ciphertext, 0, -1));
        $openStreams = \count(get_resources('stream'));

        try {
            $this->encryptor->decryptFile($encryptedPath, $decryptedPath);
            self::fail('Exception expected');
        } catch (EncryptorException $encryptorException) {
            self::assertSame('Decryption failed', $encryptorException->getMessage());
        }

        self::assertSame('previous content', file_get_contents($decryptedPath));
        self::assertSame(['decrypted.bin', 'encrypted.bin', 'plaintext.bin'], $this->directoryContents());
        self::assertCount($openStreams, get_resources('stream'));
    }

    public function testFileRenameFailure(): void
    {
        $plaintextPath = $this->directory.'/plaintext.txt';
        $encryptedPath = $this->directory.'/encrypted';
        file_put_contents($plaintextPath, 'foo');
        mkdir($encryptedPath);
        touch($encryptedPath.'/not-empty');
        $openStreams = \count(get_resources('stream'));

        try {
            $this->encryptor->encryptFile($plaintextPath, $encryptedPath);
            self::fail('Exception expected');
        } catch (EncryptorException $encryptorException) {
            self::assertStringContainsString('Unable to rename', $encryptorException->getMessage());
        }

        self::assertSame(['encrypted', 'plaintext.txt'], $this->directoryContents());
        self::assertCount($openStreams, get_resources('stream'));
    }

    private static function encrypt(string $plaintext, ?V1StreamEncryptor $encryptor = null): string
    {
        $output = self::memoryStream();
        ($encryptor ?? new V1StreamEncryptor(self::KEY))->encryptStream(self::memoryStream($plaintext), $output);

        return self::contents($output);
    }

    private static function decrypt(string $ciphertext, ?V1StreamEncryptor $encryptor = null): string
    {
        $output = self::memoryStream();
        ($encryptor ?? new V1StreamEncryptor(self::KEY))->decryptStream(self::memoryStream($ciphertext), $output);

        return self::contents($output);
    }

    /**
     * @return resource
     */
    private static function memoryStream(string $contents = '')
    {
        $stream = fopen('php://memory', 'w+');
        \assert(false !== $stream);
        fwrite($stream, $contents);
        rewind($stream);

        return $stream;
    }

    /**
     * @param resource $stream
     */
    private static function contents($stream): string
    {
        rewind($stream);
        $contents = stream_get_contents($stream);
        \assert(\is_string($contents));

        return $contents;
    }

    private function flipByte(string $string, int $offset): string
    {
        $string[$offset] = \chr(\ord($string[$offset]) ^ 0x01);

        return $string;
    }

    /**
     * @return list<string>
     */
    private function directoryContents(): array
    {
        $contents = scandir($this->directory);
        \assert(false !== $contents);

        return array_values(array_diff($contents, ['.', '..']));
    }
}
