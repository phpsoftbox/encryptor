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
use function rtrim;
use function str_replace;
use function strtolower;

final class GeneratePasswordHandler implements HandlerInterface
{
    public function run(RunnerInterface $runner): int|Response
    {
        $length = $runner->request()->option('length');
        if (!is_int($length) || $length <= 0) {
            $runner->io()->writeln('Некорректная длина пароля.', 'error');

            return Response::FAILURE;
        }

        $format = $runner->request()->option('format');
        if (!is_string($format) || $format === '') {
            $format = 'base64url';
        }
        $format = strtolower($format);

        $bytes = random_bytes($length);

        if ($format === 'hex') {
            $password = bin2hex($bytes);
        } elseif ($format === 'base64') {
            $password = base64_encode($bytes);
        } elseif ($format === 'base64url') {
            $password = rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($bytes)), '=');
        } else {
            $runner->io()->writeln('Неизвестный формат пароля. Допустимо: base64url, hex, base64.', 'error');

            return Response::FAILURE;
        }

        $runner->io()->writeln($password, 'success');

        return Response::SUCCESS;
    }
}
