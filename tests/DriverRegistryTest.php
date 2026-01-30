<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Tests;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Driver\DriverRegistry;
use PhpSoftBox\Encryptor\Driver\OpenSslDriver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DriverRegistry::class)]
final class DriverRegistryTest extends TestCase
{
    #[Test]
    public function registersAndReturnsDriver(): void
    {
        $registry = new DriverRegistry();

        $registry->register(new OpenSslDriver());

        self::assertTrue($registry->has('openssl'));
        self::assertInstanceOf(OpenSslDriver::class, $registry->get('openssl'));
    }

    #[Test]
    public function throwsForUnknownDriver(): void
    {
        $registry = new DriverRegistry();

        $this->expectException(InvalidArgumentException::class);
        $registry->get('unknown');
    }
}
