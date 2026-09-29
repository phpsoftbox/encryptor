<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Contracts;

interface DriverInterface
{
    public function name(): string;

    /**
     * @param string $associatedData данные, к которым привязывается шифртекст (например, имя cookie); сами не шифруются
     */
    public function encrypt(string $plaintext, string $key, string $associatedData = ''): string;

    /**
     * @param string $associatedData те же данные, что при шифровании; иначе — исключение
     */
    public function decrypt(string $ciphertext, string $key, string $associatedData = ''): string;
}
