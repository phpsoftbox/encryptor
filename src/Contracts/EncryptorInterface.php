<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Contracts;

/**
 * Шифрование строк. `$associatedData` привязывает шифртекст к контексту (например, к имени cookie): расшифровать
 * его можно только с теми же данными.
 */
interface EncryptorInterface
{
    public function encrypt(string $plaintext, string $key, string $associatedData = ''): string;

    public function decrypt(string $ciphertext, string $key, string $associatedData = ''): string;

    /**
     * Шифрует текущим ключом (из провайдера ключей или ключом по умолчанию).
     */
    public function encryptWithCurrentKey(string $plaintext, string $associatedData = ''): string;

    /**
     * Расшифровывает текущим или любым из предыдущих ключей.
     */
    public function decryptWithAnyKey(string $ciphertext, string $associatedData = ''): string;
}
