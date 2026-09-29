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

$encryptor = new Encryptor(defaultKey: $_ENV['APP_KEY']);

$ciphertext = $encryptor->encrypt('payload', $_ENV['APP_KEY']);
$plain = $encryptor->decrypt($ciphertext, $_ENV['APP_KEY']);
```

## Ключи

- Ключ для шифрования — не короче 32 байт (`Encryptor::MIN_KEY_LENGTH`). Генерируйте его командой
  `encryptor:key:generate` (32 случайных байта в base64); строки вида `secret-key` отклоняются
  `InvalidArgumentException`.
- Для расшифровки подходит любой непустой ключ: данные, зашифрованные прежним коротким ключом, читаются, пока он
  указан в `previousKeys`. Новые данные шифруются только текущим длинным ключом.
- Можно передавать ключ явно в `encrypt()`/`decrypt()`, или использовать `KeyProviderInterface`.
- Если `KeyProviderInterface` не задан, можно передать `defaultKey` в `Encryptor`.

Использование ключа из провайдера:

```php
<?php

use PhpSoftBox\Encryptor\Encryptor;
use PhpSoftBox\Encryptor\Key\ArrayKeyProvider;

$encryptor = new Encryptor(
    keyProvider: new ArrayKeyProvider($_ENV['APP_KEY']),
);

$ciphertext = $encryptor->encryptWithCurrentKey('payload');
$plain = $encryptor->decryptWithAnyKey($ciphertext);
```

## Драйверы

По умолчанию используется `OpenSslDriver` (aes-256-gcm). Требуется расширение `ext-openssl`.

Формат шифртекста `OpenSslDriver`:

```
v1.base64(iv).base64(tag).base64(data)
```

- ключ AES выводится из переданного ключа через HKDF-SHA256;
- тег — ровно 16 байт, IV — 12 байт; шифртекст с другой длиной отклоняется (короткий тег GCM подбирается перебором);
- версия формата и связанные данные входят в аутентификацию.

Шифртекст без префикса `v1.` (`base64(iv).base64(tag).base64(data)`, ключ — SHA-256 от переданного) создавался до
версии 1.0. Он по-прежнему расшифровывается, но только без связанных данных; новые значения в нём не шифруются.

## Связанные данные

Последний необязательный аргумент `encrypt()`, `decrypt()`, `encryptWithCurrentKey()` и `decryptWithAnyKey()` — данные,
к которым привязывается шифртекст. Они не шифруются, но без них значение не расшифровать. Так `CookieMiddleware`
привязывает значение к имени cookie: зашифрованное значение одной cookie нельзя подставить в другую.

```php
$ciphertext = $encryptor->encryptWithCurrentKey($sessionId, 'cookie:psb_session');
$encryptor->decryptWithAnyKey($ciphertext, 'cookie:psb_session'); // $sessionId
$encryptor->decryptWithAnyKey($ciphertext, 'cookie:remember_web'); // исключение
```

### Использование другого драйвера

```php
<?php

use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor();

$ciphertext = $encryptor->encryptWithDriver('openssl', 'payload', $_ENV['APP_KEY']);
$plain = $encryptor->decryptWithDriver('openssl', $ciphertext, $_ENV['APP_KEY']);
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

    public function encrypt(string $plaintext, string $key, string $associatedData = ''): string
    {
        // ...
    }

    public function decrypt(string $ciphertext, string $key, string $associatedData = ''): string
    {
        // ...
    }
}

$encryptor = new Encryptor();
$encryptor->registerDriver(new MyDriver());

$ciphertext = $encryptor->encryptWithDriver('my-driver', 'payload', $_ENV['APP_KEY']);
$plain = $encryptor->decryptWithDriver('my-driver', $ciphertext, $_ENV['APP_KEY']);
```

## EncryptedValue

`EncryptedValue` хранит шифртекст и (опционально) ключ/драйвер. Это удобно для хранения в конфиге.

```php
<?php

use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: $_ENV['APP_KEY']);
$ciphertext = $encryptor->encrypt('payload', $_ENV['APP_KEY']);

$value = new EncryptedValue($ciphertext);
$plain = $encryptor->resolve($value); // payload
```

Если нужен другой ключ или драйвер:

```php
<?php

use PhpSoftBox\Encryptor\EncryptedValue;
use PhpSoftBox\Encryptor\Encryptor;

$encryptor = new Encryptor(defaultKey: $keyV1);
$ciphertext = $encryptor->encrypt('payload', $keyV2);

$value = new EncryptedValue($ciphertext, key: $keyV2, driver: 'openssl');
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
    currentKey: $_ENV['APP_KEY'],
    previousKeys: [$_ENV['APP_PREVIOUS_KEY']],
);

$encryptor = new Encryptor(keyProvider: $provider);

$ciphertext = $encryptor->encryptWithCurrentKey('payload'); // шифруется текущим ключом
$plain = $encryptor->decryptWithAnyKey($ciphertext);        // пробует текущий, затем предыдущие
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

$encryptor = new Encryptor(defaultKey: $_ENV['APP_KEY']);
$hash = $encryptor->encrypt('payload', $_ENV['APP_KEY']);

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
    encryptedValueResolver: new Encryptor(defaultKey: $_ENV['APP_KEY'])
);

$config = $factory->create();
```
