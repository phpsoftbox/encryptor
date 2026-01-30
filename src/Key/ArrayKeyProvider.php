<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Key;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Contracts\KeyProviderInterface;

use function in_array;
use function is_string;

final readonly class ArrayKeyProvider implements KeyProviderInterface
{
    /**
     * @var list<string>
     */
    private array $previousKeys;

    /**
     * @param list<string> $previousKeys
     */
    public function __construct(
        private string $currentKey,
        array $previousKeys = [],
    ) {
        if ($this->currentKey === '') {
            throw new InvalidArgumentException('Current key must be a non-empty string.');
        }

        $filtered = [];
        foreach ($previousKeys as $key) {
            if (!is_string($key) || $key === '') {
                throw new InvalidArgumentException('Previous keys must be non-empty strings.');
            }
            if ($key === $this->currentKey || in_array($key, $filtered, true)) {
                continue;
            }
            $filtered[] = $key;
        }

        $this->previousKeys = $filtered;
    }

    public function currentKey(): string
    {
        return $this->currentKey;
    }

    public function previousKeys(): array
    {
        return $this->previousKeys;
    }

    public function allKeys(): array
    {
        return [$this->currentKey, ...$this->previousKeys];
    }
}
