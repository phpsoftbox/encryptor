<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Driver;

use InvalidArgumentException;
use PhpSoftBox\Encryptor\Contracts\DriverInterface;
use RuntimeException;

use function base64_decode;
use function base64_encode;
use function count;
use function explode;
use function function_exists;
use function hash;
use function openssl_cipher_iv_length;
use function openssl_decrypt;
use function openssl_encrypt;
use function random_bytes;

use const OPENSSL_RAW_DATA;

final class OpenSslDriver implements DriverInterface
{
    private const string CIPHER = 'aes-256-gcm';
    public const string NAME    = 'openssl';

    public function name(): string
    {
        return self::NAME;
    }

    public function encrypt(string $plaintext, string $key): string
    {
        $this->assertAvailable();

        $ivLength = openssl_cipher_iv_length(self::CIPHER);
        if ($ivLength === false || $ivLength <= 0) {
            throw new RuntimeException('Unsupported OpenSSL cipher: ' . self::CIPHER);
        }

        $iv  = random_bytes($ivLength);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->normalizeKey($key),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($ciphertext === false) {
            throw new RuntimeException('OpenSSL encryption failed.');
        }

        return base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($ciphertext);
    }

    public function decrypt(string $ciphertext, string $key): string
    {
        $this->assertAvailable();

        $parts = explode('.', $ciphertext, 3);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid OpenSSL ciphertext format.');
        }

        [$ivB64, $tagB64, $dataB64] = $parts;

        $iv   = base64_decode($ivB64, true);
        $tag  = base64_decode($tagB64, true);
        $data = base64_decode($dataB64, true);

        if ($iv === false || $tag === false || $data === false) {
            throw new InvalidArgumentException('Invalid OpenSSL ciphertext encoding.');
        }

        $plaintext = openssl_decrypt(
            $data,
            self::CIPHER,
            $this->normalizeKey($key),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($plaintext === false) {
            throw new RuntimeException('OpenSSL decryption failed.');
        }

        return $plaintext;
    }

    private function normalizeKey(string $key): string
    {
        return hash('sha256', $key, true);
    }

    private function assertAvailable(): void
    {
        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('OpenSSL extension is required for OpenSslDriver.');
        }
    }
}
