<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Cli;

use PhpSoftBox\CliApp\Command\Command;
use PhpSoftBox\CliApp\Command\CommandRegistryInterface;
use PhpSoftBox\CliApp\Command\OptionDefinition;
use PhpSoftBox\CliApp\Loader\CommandProviderInterface;

final class EncryptorCommandProvider implements CommandProviderInterface
{
    public function register(CommandRegistryInterface $registry): void
    {
        $registry->register(Command::define(
            name: 'encryptor:key:generate',
            description: 'Сгенерировать APP_KEY для Encryptor',
            signature: [
                new OptionDefinition(
                    name: 'length',
                    short: 'l',
                    description: 'Длина ключа в байтах (до кодирования)',
                    required: false,
                    default: 32,
                    type: 'int',
                ),
                new OptionDefinition(
                    name: 'format',
                    short: 'f',
                    description: 'Формат ключа: base64 или hex',
                    required: false,
                    default: 'base64',
                    type: 'string',
                ),
            ],
            handler: GenerateKeyHandler::class,
        ));
    }
}
