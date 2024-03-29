<?php

declare(strict_types=1);

namespace SlamSymmetricEncryption\Test;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SlamSymmetricEncryption\EncryptorException;
use SlamSymmetricEncryption\V1Encryptor;

/**
 * @internal
 */
#[CoversClass(V1Encryptor::class)]
/**
 * @internal
 *
 * @coversNothing
 */
final class V1EncryptorTest extends TestCase
{
    public function testFormatConsistency(): void
    {
        $encryptor = new V1Encryptor('Hog2u9jtOzyt+mPyAJwp8v3dI6Uvp1T4FUKrAjizVGo=');

        self::assertSame('foo', $encryptor->decrypt('dznmjbqHnI_26crKpRYvp125K9N6ctqU0kVCmoSRbG7HAKCIrnAz0RBELQ'));
    }

    public function testWrongKeyBits(): void
    {
        $encryptor = new V1Encryptor(base64_encode('foo'));

        $this->expectException(EncryptorException::class);
        $this->expectExceptionCode(0);

        $encryptor->encrypt('bar');
    }

    public function testWrongEncryptedMessageFormat(): void
    {
        $encryptor = new V1Encryptor(V1Encryptor::generateKey());

        $this->expectException(EncryptorException::class);

        $encryptor->decrypt(sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
    }

    public function testWrongKey(): void
    {
        $encryptor1 = new V1Encryptor(V1Encryptor::generateKey());
        $encryptor2 = new V1Encryptor(V1Encryptor::generateKey());

        $plaintext = uniqid();
        $encryptedWith1 = $encryptor1->encrypt($plaintext);

        self::assertSame($plaintext, $encryptor1->decrypt($encryptedWith1));

        $this->expectException(EncryptorException::class);
        $this->expectExceptionCode(0);

        $encryptor2->decrypt($encryptedWith1);
    }
}
