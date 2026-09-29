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
use function hash_hkdf;
use function openssl_cipher_iv_length;
use function openssl_decrypt;
use function openssl_encrypt;
use function random_bytes;
use function str_starts_with;
use function strlen;
use function substr;

use const OPENSSL_RAW_DATA;

/**
 * AES-256-GCM через OpenSSL.
 *
 * Формат `v1.<iv>.<tag>.<данные>` (base64): ключ шифрования выводится из переданного ключа через HKDF-SHA256, версия
 * формата и связанные данные (AAD) входят в аутентификацию. Шифртекст с другими связанными данными или другой версией
 * не расшифровывается.
 *
 * Старый формат `<iv>.<tag>.<данные>` (ключ — SHA-256 от переданного, без AAD) только расшифровывается и только без
 * связанных данных: так читаются значения, зашифрованные до появления версии.
 */
final class OpenSslDriver implements DriverInterface
{
    public const string NAME = 'openssl';

    private const string CIPHER     = 'aes-256-gcm';
    private const string VERSION    = 'v1';
    private const int TAG_LENGTH    = 16;
    private const string HKDF_INFO  = 'phpsoftbox/encryptor aes-256-gcm v1';
    private const string AAD_PREFIX = 'phpsoftbox/encryptor v1:';

    public function name(): string
    {
        return self::NAME;
    }

    public function encrypt(string $plaintext, string $key, string $associatedData = ''): string
    {
        $this->assertAvailable();

        $iv  = random_bytes($this->ivLength());
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->deriveKey($key),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::AAD_PREFIX . $associatedData,
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new RuntimeException('OpenSSL encryption failed.');
        }

        return self::VERSION . '.' . base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($ciphertext);
    }

    public function decrypt(string $ciphertext, string $key, string $associatedData = ''): string
    {
        $this->assertAvailable();

        if (str_starts_with($ciphertext, self::VERSION . '.')) {
            [$iv, $tag, $data] = $this->parse(substr($ciphertext, strlen(self::VERSION) + 1));

            return $this->open($data, $this->deriveKey($key), $iv, $tag, self::AAD_PREFIX . $associatedData);
        }

        // Старый формат не содержит связанных данных: принять его вместо значения с AAD — значит обойти привязку.
        if ($associatedData !== '') {
            throw new InvalidArgumentException('Legacy OpenSSL ciphertext cannot be bound to associated data.');
        }

        [$iv, $tag, $data] = $this->parse($ciphertext);

        return $this->open($data, hash('sha256', $key, true), $iv, $tag, '');
    }

    /**
     * @return array{0: string, 1: string, 2: string} IV, тег, данные
     */
    private function parse(string $payload): array
    {
        $parts = explode('.', $payload, 3);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid OpenSSL ciphertext format.');
        }

        $iv   = base64_decode($parts[0], true);
        $tag  = base64_decode($parts[1], true);
        $data = base64_decode($parts[2], true);

        if ($iv === false || $tag === false || $data === false) {
            throw new InvalidArgumentException('Invalid OpenSSL ciphertext encoding.');
        }

        // OpenSSL принимает тег от 1 до 16 байт: короткий тег подбирается перебором.
        if (strlen($tag) !== self::TAG_LENGTH) {
            throw new InvalidArgumentException('Invalid OpenSSL authentication tag length.');
        }

        if (strlen($iv) !== $this->ivLength()) {
            throw new InvalidArgumentException('Invalid OpenSSL initialization vector length.');
        }

        return [$iv, $tag, $data];
    }

    private function open(string $data, string $key, string $iv, string $tag, string $aad): string
    {
        $plaintext = openssl_decrypt($data, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);

        if ($plaintext === false) {
            throw new RuntimeException('OpenSSL decryption failed.');
        }

        return $plaintext;
    }

    private function deriveKey(string $key): string
    {
        return hash_hkdf('sha256', $key, 32, self::HKDF_INFO);
    }

    private function ivLength(): int
    {
        $length = openssl_cipher_iv_length(self::CIPHER);
        if ($length === false || $length <= 0) {
            throw new RuntimeException('Unsupported OpenSSL cipher: ' . self::CIPHER);
        }

        return $length;
    }

    private function assertAvailable(): void
    {
        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('OpenSSL extension is required for OpenSslDriver.');
        }
    }
}
