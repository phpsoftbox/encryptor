<?php

declare(strict_types=1);

namespace PhpSoftBox\Encryptor\Cli;

use PhpSoftBox\CliApp\Command\HandlerInterface;
use PhpSoftBox\CliApp\Response;
use PhpSoftBox\CliApp\Runner\RunnerInterface;

use function base64_encode;
use function bin2hex;
use function is_int;
use function is_string;
use function random_bytes;
use function strtolower;

final class GenerateKeyHandler implements HandlerInterface
{
    public function run(RunnerInterface $runner): int|Response
    {
        $length = $runner->request()->option('length');
        if (!is_int($length) || $length <= 0) {
            $runner->io()->writeln('Некорректная длина ключа.', 'error');

            return Response::FAILURE;
        }

        $format = $runner->request()->option('format');
        if (!is_string($format) || $format === '') {
            $format = 'base64';
        }
        $format = strtolower($format);

        $bytes = random_bytes($length);

        if ($format === 'hex') {
            $key = bin2hex($bytes);
        } elseif ($format === 'base64') {
            $key = base64_encode($bytes);
        } else {
            $runner->io()->writeln('Неизвестный формат ключа. Допустимо: base64, hex.', 'error');

            return Response::FAILURE;
        }

        $runner->io()->writeln('APP_KEY="' . $key . '"', 'success');

        return Response::SUCCESS;
    }
}
