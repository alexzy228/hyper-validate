<?php

declare(strict_types=1);

namespace Alexzy\HyperfValidate\Exception\Handler;

use Alexzy\HyperfValidate\Exception\ValidateException;
use Alexzy\HyperfValidate\Validate;
use Hyperf\ExceptionHandler\ExceptionHandler;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class ValidateExceptionHandler extends ExceptionHandler
{

    public function handle(Throwable $throwable, ResponseInterface $response)
    {
        $this->stopPropagation();
        /** @var ValidateException $throwable */
        $body = $throwable->getMessage();
        if (!$response->hasHeader('content-type')) {
            $response = $response->withAddedHeader('content-type', 'text/plain; charset=utf-8');
        }
        return $response->withStatus($throwable->getCode())->withBody(new SwooleStream($body));
    }

    public function isValid(Throwable $throwable): bool
    {
        return $throwable instanceof Validate;
    }
}