<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Tests;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Driver\OpenSslDriver;
use PhpSoftBox\Encryptor\Encryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function base64_decode;
use function base64_encode;
use function explode;
use function hash;
use function openssl_encrypt;
use function random_bytes;
use function str_starts_with;
use function substr;

use const OPENSSL_RAW_DATA;

#[CoversClass(OpenSslDriver::class)]
#[CoversClass(Encryptor::class)]
#[CoversMethod(OpenSslDriver::class, 'encrypt')]
#[CoversMethod(OpenSslDriver::class, 'decrypt')]
#[RequiresPhpExtension('openssl')]
final class OpenSslDriverTest extends TestCase
{
    private const string KEY = 'current-key-0123456789abcdef0123456789';

    /**
     * Проверим, что новый шифртекст помечен версией формата и расшифровывается.
     *
     * @see OpenSslDriver::encrypt()
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function encryptsInVersionedFormat(): void
    {
        $driver = new OpenSslDriver();

        $ciphertext = $driver->encrypt('payload', self::KEY);

        self::assertTrue(str_starts_with($ciphertext, 'v1.'));
        self::assertSame('payload', $driver->decrypt($ciphertext, self::KEY));
    }

    /**
     * Проверим, что укороченный тег отклоняется до обращения к OpenSSL: иначе 1-байтовый тег подбирается за ~256
     * попыток.
     *
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function rejectsTruncatedTag(): void
    {
        $driver = new OpenSslDriver();

        [$version, $iv, $tag, $data] = explode('.', $driver->encrypt('payload', self::KEY));
        $truncated                   = base64_encode(substr((string) base64_decode($tag, true), 0, 1));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid OpenSSL authentication tag length.');

        $driver->decrypt($version . '.' . $iv . '.' . $truncated . '.' . $data, self::KEY);
    }

    /**
     * Проверим, что IV неверной длины отклоняется.
     *
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function rejectsWrongIvLength(): void
    {
        $driver = new OpenSslDriver();

        [$version, , $tag, $data] = explode('.', $driver->encrypt('payload', self::KEY));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid OpenSSL initialization vector length.');

        $driver->decrypt($version . '.' . base64_encode(random_bytes(16)) . '.' . $tag . '.' . $data, self::KEY);
    }

    /**
     * Проверим, что шифртекст расшифровывается только с теми же связанными данными.
     *
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function rejectsOtherAssociatedData(): void
    {
        $driver = new OpenSslDriver();

        $ciphertext = $driver->encrypt('session-id', self::KEY, 'cookie:psb_session');

        self::assertSame('session-id', $driver->decrypt($ciphertext, self::KEY, 'cookie:psb_session'));

        $this->expectException(RuntimeException::class);

        $driver->decrypt($ciphertext, self::KEY, 'cookie:remember_web');
    }

    /**
     * Проверим, что шифртекст старого формата (без версии, ключ — SHA-256) по-прежнему расшифровывается.
     *
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function decryptsLegacyFormat(): void
    {
        self::assertSame('payload', new OpenSslDriver()->decrypt($this->legacyCiphertext('payload', 'short-key'), 'short-key'));
    }

    /**
     * Проверим, что старый формат не принимается вместо значения со связанными данными: в нём нет привязки.
     *
     * @see OpenSslDriver::decrypt()
     */
    #[Test]
    public function rejectsLegacyFormatWithAssociatedData(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Legacy OpenSSL ciphertext cannot be bound to associated data.');

        new OpenSslDriver()->decrypt($this->legacyCiphertext('payload', self::KEY), self::KEY, 'cookie:sid');
    }

    /**
     * Проверим, что шифровать коротким ключом нельзя, а расшифровать старые данные коротким ключом — можно.
     *
     * @see Encryptor::encrypt()
     * @see Encryptor::decrypt()
     */
    #[Test]
    public function requiresLongKeyOnlyForEncryption(): void
    {
        $encryptor = new Encryptor();

        self::assertSame('payload', $encryptor->decrypt($this->legacyCiphertext('payload', 'short-key'), 'short-key'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Encryption key must be at least 32 bytes long');

        $encryptor->encrypt('payload', 'short-key');
    }

    private function legacyCiphertext(string $plaintext, string $key): string
    {
        $iv   = random_bytes(12);
        $tag  = '';
        $data = openssl_encrypt($plaintext, 'aes-256-gcm', hash('sha256', $key, true), OPENSSL_RAW_DATA, $iv, $tag);

        return base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode((string) $data);
    }
}
