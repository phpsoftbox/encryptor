<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor;

final readonly class EncryptedValue
{
    public function __construct(
        private string $value,
        private ?string $key = null,
        private ?string $driver = null,
    ) {
    }

    public function value(): string
    {
        return $this->value;
    }

    public function key(): ?string
    {
        return $this->key;
    }

    public function driver(): ?string
    {
        return $this->driver;
    }
}
