<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Contracts\DriverInterface;
use PhpSoftBox\Encryptor\Contracts\EncryptedValueResolverInterface;
use PhpSoftBox\Encryptor\Contracts\EncryptorInterface;
use PhpSoftBox\Encryptor\Contracts\KeyProviderInterface;
use PhpSoftBox\Encryptor\Driver\DriverRegistry;
use PhpSoftBox\Encryptor\Driver\OpenSslDriver;
use Throwable;

final class Encryptor implements EncryptorInterface, EncryptedValueResolverInterface
{
    private DriverRegistry $registry;
    private string $defaultDriver;
    private ?string $defaultKey;
    private ?KeyProviderInterface $keyProvider;

    public function __construct(
        ?DriverRegistry $registry = null,
        string $defaultDriver = OpenSslDriver::NAME,
        ?string $defaultKey = null,
        ?KeyProviderInterface $keyProvider = null,
    ) {
        $this->registry      = $registry ?? new DriverRegistry([new OpenSslDriver()]);
        $this->defaultDriver = $defaultDriver;
        $this->defaultKey    = $defaultKey;
        $this->keyProvider   = $keyProvider;
    }

    public function registerDriver(DriverInterface $driver): void
    {
        $this->registry->register($driver);
    }

    public function encrypt(string $plaintext, string $key): string
    {
        return $this->encryptWithDriver($this->defaultDriver, $plaintext, $key);
    }

    public function decrypt(string $ciphertext, string $key): string
    {
        return $this->decryptWithDriver($this->defaultDriver, $ciphertext, $key);
    }

    public function encryptWithCurrentKey(string $plaintext): string
    {
        return $this->encryptWithDriver($this->defaultDriver, $plaintext, $this->currentKey());
    }

    public function decryptWithAnyKey(string $ciphertext, ?string $driverName = null): string
    {
        $driver = $driverName ?? $this->defaultDriver;

        return $this->decryptWithKeys($driver, $ciphertext, $this->keyCandidates());
    }

    public function encryptWithDriver(string $driverName, string $plaintext, string $key): string
    {
        $key = $this->requireKey($key);

        return $this->registry->get($driverName)->encrypt($plaintext, $key);
    }

    public function decryptWithDriver(string $driverName, string $ciphertext, string $key): string
    {
        $key = $this->requireKey($key);

        return $this->registry->get($driverName)->decrypt($ciphertext, $key);
    }

    public function resolve(EncryptedValue $value): string
    {
        $driver = $value->driver();
        if ($driver === null || $driver === '') {
            $driver = $this->defaultDriver;
        }

        $explicitKey = $value->key();
        if ($explicitKey !== null && $explicitKey !== '') {
            return $this->decryptWithDriver($driver, $value->value(), $explicitKey);
        }

        $keys = $this->keyCandidates();
        if ($keys === []) {
            throw new InvalidArgumentException('Encryption key must be a non-empty string.');
        }

        return $this->decryptWithKeys($driver, $value->value(), $keys);
    }

    private function currentKey(): string
    {
        if ($this->keyProvider !== null) {
            return $this->requireKey($this->keyProvider->currentKey());
        }

        return $this->requireKey($this->defaultKey);
    }

    /**
     * @return list<string>
     */
    private function keyCandidates(): array
    {
        if ($this->keyProvider !== null) {
            return $this->keyProvider->allKeys();
        }

        if ($this->defaultKey !== null && $this->defaultKey !== '') {
            return [$this->defaultKey];
        }

        return [];
    }

    /**
     * @param list<string> $keys
     */
    private function decryptWithKeys(string $driverName, string $ciphertext, array $keys): string
    {
        if ($keys === []) {
            throw new InvalidArgumentException('Encryption key must be a non-empty string.');
        }

        $driver        = $this->registry->get($driverName);
        $lastException = null;

        foreach ($keys as $key) {
            $key = $this->requireKey($key);

            try {
                return $driver->decrypt($ciphertext, $key);
            } catch (Throwable $exception) {
                $lastException = $exception;
            }
        }

        if ($lastException !== null) {
            throw $lastException;
        }

        throw new InvalidArgumentException('Encryption key must be a non-empty string.');
    }

    private function requireKey(?string $key): string
    {
        if ($key === null || $key === '') {
            throw new InvalidArgumentException('Encryption key must be a non-empty string.');
        }

        return $key;
    }
}
