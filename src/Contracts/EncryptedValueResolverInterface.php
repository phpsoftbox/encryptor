<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Contracts;

use PhpSoftBox\Encryptor\EncryptedValue;

interface EncryptedValueResolverInterface
{
    public function resolve(EncryptedValue $value): string;
}
