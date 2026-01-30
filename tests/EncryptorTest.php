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
    #[Test]
    public function encryptsAndDecryptsWithDefaultDriver(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            defaultKey: 'secret-key',
        );

        $ciphertext = $encryptor->encrypt('payload', 'secret-key');

        self::assertSame('payload', $encryptor->decrypt($ciphertext, 'secret-key'));
    }

    #[Test]
    public function resolvesEncryptedValueWithDefaultKey(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            defaultKey: 'secret-key',
        );

        $ciphertext = $encryptor->encrypt('payload', 'secret-key');

        $value = new EncryptedValue($ciphertext);

        self::assertSame('payload', $encryptor->resolve($value));
    }

    #[Test]
    public function resolvesEncryptedValueWithPreviousKey(): void
    {
        if (!function_exists('openssl_encrypt')) {
            $this->markTestSkipped('OpenSSL extension is required for this test.');
        }

        $keyProvider = new ArrayKeyProvider('key-current', ['key-previous']);

        $encryptor = new Encryptor(
            registry: new DriverRegistry([new OpenSslDriver()]),
            keyProvider: $keyProvider,
        );

        $ciphertext = $encryptor->encrypt('payload', 'key-previous');

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
            keyProvider: new ArrayKeyProvider('key-current', ['key-previous']),
        );

        $ciphertext = $encryptor->encryptWithCurrentKey('payload');

        self::assertSame('payload', $encryptor->decryptWithAnyKey($ciphertext));
    }
}
