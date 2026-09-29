<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Tests;

use PhpSoftBox\Encryptor\Driver\DriverRegistry;
use PhpSoftBox\Encryptor\Driver\OpenSslDriver;
use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use function function_exists;

#[CoversClass(Encryptor::class)]
#[CoversClass(OpenSslDriver::class)]
final class EncryptorTest extends TestCase
{
    private const string KEY          = 'current-key-0123456789abcdef0123456789';
    private const string PREVIOUS_KEY = 'previous-key-0123456789abcdef012345678';

    #[Test]
    public function encryptsAndDecryptsWithDefaultDriver(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            defaultKey: self::KEY,
        );

        $ciphertext = $encryptor->encrypt('payload', self::KEY);

        self::assertSame('payload', $encryptor->decrypt($ciphertext, self::KEY));
    }

    #[Test]
    public function resolvesEncryptedValueWithDefaultKey(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            defaultKey: self::KEY,
        );

        $ciphertext = $encryptor->encrypt('payload', self::KEY);

        $value = new EncryptedValue($ciphertext);

        self::assertSame('payload', $encryptor->resolve($value));
    }

    #[Test]
    public function resolvesEncryptedValueWithPreviousKey(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $keyProvider = new ArrayKeyProvider(self::KEY, [self::PREVIOUS_KEY]);

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            keyProvider: $keyProvider,
        );

        $ciphertext = $encryptor->encrypt('payload', self::PREVIOUS_KEY);

        $value = new EncryptedValue($ciphertext);

        self::assertSame('payload', $encryptor->resolve($value));
    }

    #[Test]
    public function encryptsAndDecryptsWithKeyProvider(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            keyProvider: new ArrayKeyProvider(self::KEY, [self::PREVIOUS_KEY]),
        );

        $ciphertext = $encryptor->encryptWithCurrentKey('payload');

        self::assertSame('payload', $encryptor->decryptWithAnyKey($ciphertext));
    }
}
