<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Contracts;

interface KeyProviderInterface
{
    public function currentKey(): string;

    /**
     * @return list<string>
     */
    public function previousKeys(): array;

    /**
     * @return list<string>
     */
    public function allKeys(): array;
}
