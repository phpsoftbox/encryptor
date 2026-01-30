<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Tests;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ArrayKeyProvider::class)]
final class ArrayKeyProviderTest extends TestCase
{
    #[Test]
    public function exposesCurrentAndPreviousKeys(): void
    {
        $provider = new ArrayKeyProvider('key-current', ['key-prev-1', 'key-prev-2']);

        self::assertSame('key-current', $provider->currentKey());
        self::assertSame(['key-prev-1', 'key-prev-2'], $provider->previousKeys());
        self::assertSame(['key-current', 'key-prev-1', 'key-prev-2'], $provider->allKeys());
    }

    #[Test]
    public function rejectsEmptyCurrentKey(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ArrayKeyProvider('', []);
    }
}
