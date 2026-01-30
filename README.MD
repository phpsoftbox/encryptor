# PhpSoftBox Encryptor

Компонент для обратимого шифрования и расшифровки строк с поддержкой расширяемых драйверов.
Подходит для случаев, когда нужен "хеш, который можно расшифровать" (фактически это шифртекст).

## Установка

```bash
composer require phpsoftbox/encryptor
```

## Основные сущности

- `Encryptor` — фасад и точка входа. Реализует `EncryptorInterface` и `EncryptedValueResolverInterface`.
- `DriverInterface` — контракт драйвера шифрования.
- `KeyProviderInterface` — источник текущего и предыдущих ключей.
- `EncryptedValue` — Value Object с шифртекстом, опциональными ключом и именем драйвера.

## Быстрый старт

```php
<?php

declare(strict_types=1);

use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: 'secret-key');

$ciphertext = $encryptor->encrypt('payload', 'secret-key');
$plain = $encryptor->decrypt($ciphertext, 'secret-key');
```

## Ключи

- Ключ обязателен и должен быть непустой строкой.
- Можно передавать ключ явно в `encrypt()`/`decrypt()`, или использовать `KeyProviderInterface`.
- При отсутствии ключа будет выброшен `InvalidArgumentException`.
 - Если `KeyProviderInterface` не задан, можно передать `defaultKey` в `Encryptor`.

Использование ключа из провайдера:

```php
<?php

use PhpSoftBox\Encryptor\Encryptor;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;

$encryptor = new Encryptor(
    keyProvider: new ArrayKeyProvider('secret-key'),
);

$ciphertext = $encryptor->encryptWithCurrentKey('payload');
$plain = $encryptor->decryptWithAnyKey($ciphertext);
```

## Драйверы

По умолчанию используется `OpenSslDriver` (aes-256-gcm). Требуется расширение `ext-openssl`.

Формат шифртекста `OpenSslDriver`:

```
base64(iv).base64(tag).base64(data)
```

### Использование другого драйвера

```php
<?php

use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor();

$ciphertext = $encryptor->encryptWithDriver('openssl', 'payload', 'secret-key');
$plain = $encryptor->decryptWithDriver('openssl', $ciphertext, 'secret-key');
```

### Регистрация кастомного драйвера

```php
<?php

use PhpSoftBox\Encryptor\Contracts\DriverInterface;
use PhpSoftBox\Encryptor\Encryptor;

final class MyDriver implements DriverInterface
{
    public function name(): string
    {
        return 'my-driver';
    }

    public function encrypt(string $plaintext, string $key): string
    {
        // ...
    }

    public function decrypt(string $ciphertext, string $key): string
    {
        // ...
    }
}

$encryptor = new Encryptor();
$encryptor->registerDriver(new MyDriver());

$ciphertext = $encryptor->encryptWithDriver('my-driver', 'payload', 'secret-key');
$plain = $encryptor->decryptWithDriver('my-driver', $ciphertext, 'secret-key');
```

## EncryptedValue

`EncryptedValue` хранит шифртекст и (опционально) ключ/драйвер. Это удобно для хранения в конфиге.

```php
<?php

use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: 'secret-key');
$ciphertext = $encryptor->encrypt('payload', 'secret-key');

$value = new EncryptedValue($ciphertext);
$plain = $encryptor->resolve($value); // payload
```

Если нужен другой ключ или драйвер:

```php
<?php

use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: 'key-v1');
$ciphertext = $encryptor->encrypt('payload', 'key-v2');

$value = new EncryptedValue($ciphertext, key: 'key-v2', driver: 'openssl');
$plain = $encryptor->resolve($value);
```

Если ключ не указан в `EncryptedValue`, используется `KeyProviderInterface` (если задан),
иначе — `defaultKey` у `Encryptor`.

## Ротация ключей

Для постепенной смены ключей используется `KeyProviderInterface`.
Текущий ключ применяется для шифрования, а при расшифровке пробуются сначала текущий,
затем предыдущие ключи по порядку.

```php
<?php

use PhpSoftBox\Encryptor\Encryptor;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;

$provider = new ArrayKeyProvider(
    currentKey: 'key-v2',
    previousKeys: ['key-v1', 'key-v0'],
);

$encryptor = new Encryptor(keyProvider: $provider);

$ciphertext = $encryptor->encryptWithCurrentKey('payload'); // шифруется key-v2
$plain = $encryptor->decryptWithAnyKey($ciphertext);        // пробует key-v2, затем key-v1, key-v0
```

### DI и конфигурация

`KeyProviderInterface` удобно собирать в composition root из значений `APP_KEY`
и списка `previousKeys` (например, `config.app_key` и `config.previous_keys`),
а затем передавать в `Encryptor` через DI-контейнер.

#### Пример для PHP-DI

```php
<?php

use DI\ContainerBuilder;
use PhpSoftBox\Encryptor\Contracts\EncryptedValueResolverInterface;
use PhpSoftBox\Encryptor\Contracts\KeyProviderInterface;
use PhpSoftBox\Encryptor\Encryptor;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;

$builder = new ContainerBuilder();
$builder->addDefinitions([
    KeyProviderInterface::class => static function (): KeyProviderInterface {
        $currentKey = (string) ($_ENV['APP_KEY'] ?? '');
        $previousRaw = (string) ($_ENV['APP_PREVIOUS_KEYS'] ?? '');
        $previousKeys = array_filter(array_map('trim', explode(',', $previousRaw)));

        return new ArrayKeyProvider($currentKey, $previousKeys);
    },
    Encryptor::class => static function (KeyProviderInterface $keys): Encryptor {
        return new Encryptor(keyProvider: $keys);
    },
    EncryptedValueResolverInterface::class => static function (Encryptor $encryptor): EncryptedValueResolverInterface {
        return $encryptor;
    },
]);

$container = $builder->build();
$encryptor = $container->get(Encryptor::class);
```

## Интеграция с Config

`Config` умеет автоматически расшифровывать `EncryptedValue`, если передан
`EncryptedValueResolverInterface` (например, `Encryptor`).

```php
<?php

use PhpSoftBox\Config\Config;
use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: 'secret-key');
$hash = $encryptor->encrypt('payload', 'secret-key');

$config = new Config(
    [
        ['secret' => new EncryptedValue($hash)],
    ],
    encryptedValueResolver: $encryptor,
);

$plain = $config->get('secret'); // payload
```

Для `ConfigFactory`:

```php
<?php

use PhpSoftBox\Config\ConfigFactory;
use PhpSoftBox\Encryptor\Encryptor;

$factory = new ConfigFactory(
    baseDir: __DIR__ . '/..',
    encryptedValueResolver: new Encryptor(defaultKey: 'secret-key')
);

$config = $factory->create();
```
