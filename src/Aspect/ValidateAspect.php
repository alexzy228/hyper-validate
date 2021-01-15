<?php

declare(strict_types=1);

namespace Alexzy\HyperfValidate\Aspect;

use Alexzy\HyperfValidate\Annotation\Validate;
use Alexzy\HyperfValidate\Exception\ValidateException;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Utils\ApplicationContext;
use Psr\Http\Message\ServerRequestInterface;

class ValidateAspect extends AbstractAspect
{
    public $annotations = [
        Validate::class
    ];

    public function process(ProceedingJoinPoint $proceedingJoinPoint)
    {
        $request = ApplicationContext::getContainer()->get(ServerRequestInterface::class);
        $validate = '';

        foreach ($proceedingJoinPoint->getAnnotationMetadata()->method as $validateMethod) {
            if ($validateMethod instanceof Validate) {
                if (!$validateMethod->validate) {
                    throw new ValidateException("validate 不能为空");
                }
                if (class_exists($validateMethod->validate)) {
                    // 实例化验证器
                    $validate = new $validateMethod->validate;
                } else {
                    throw new ValidateException($validateMethod->validate . '不存在');
                }

                if ($validateMethod->scene) {
                    $validate = $validate->scene($validateMethod->scene);
                }

                $data = $request->all();
            }
        }
    }
}