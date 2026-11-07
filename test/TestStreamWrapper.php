<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption\Test;

/**
 * Stream wrapper simulating short reads and I/O failures.
 *
 * @internal
 */
final class TestStreamWrapper
{
    public const string PROTOCOL = 'slamsymenctest';

    public static string $data = '';
    public static int $maxReadLength = 1000;
    public static bool $failRead = false;
    public static bool $failWrite = false;

    /** @var null|resource */
    public $context;

    private int $position = 0;

    public static function register(): void
    {
        self::$data = '';
        self::$maxReadLength = 1000;
        self::$failRead = false;
        self::$failWrite = false;

        stream_wrapper_register(self::PROTOCOL, self::class);
    }

    public static function unregister(): void
    {
        stream_wrapper_unregister(self::PROTOCOL);
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool
    {
        return true;
    }

    public function stream_read(int $count): false|string
    {
        if (self::$failRead) {
            return false;
        }

        $read = substr(self::$data, $this->position, min($count, self::$maxReadLength));
        $this->position += \strlen($read);

        return $read;
    }

    public function stream_write(string $data): int
    {
        if (self::$failWrite) {
            return 0;
        }

        self::$data .= $data;

        return \strlen($data);
    }

    public function stream_eof(): bool
    {
        return $this->position >= \strlen(self::$data);
    }
}
