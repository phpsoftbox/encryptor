<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Contracts;

interface DriverInterface
{
    public function name(): string;

    public function encrypt(string $plaintext, string $key): string;

    public function decrypt(string $ciphertext, string $key): string;
}
