<?php

declare(strict_types=1);

namespace Alexzy\HyperfValidate\Aspect;

use Alexzy\HyperfValidate\Annotation\Validate;
use Alexzy\HyperfValidate\Exception\ValidateException;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Context;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ValidateAspect
 * @package Alexzy\HyperfValidate\Aspect
 * @Aspect
 */
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
                    /** @var \Alexzy\HyperfValidate\Validate $validate */
                    $validate = new $validateMethod->validate;
                } else {
                    throw new ValidateException($validateMethod->validate . '不存在');
                }

                if ($validateMethod->scene) {
                    $validate = $validate->scene($validateMethod->scene);
                }

                $data = $request->all();
                if ($validate->batch($validateMethod->batch)->check($data) === false) {
                    if ($validateMethod->throws) {
                        throw new ValidateException($validate->getError());
                    } else {
                        //错误信息写入请求
                        Context::override(ServerRequestInterface::class, function (ServerRequestInterface $request) use ($validate) {
                            return $request->withAttribute('validate', $validate->getError());
                        });
                    }
                }

                if (empty($validate->getError()) && $validateMethod->filter) {
                    $rules = $validate->getSceneRule($validateMethod->scene);
                    $new_data = [];
                    foreach ($rules as $key) {
                        if (strstr($key, "|")) {
                            $key = explode('|', $key)[0];
                        }
                        if (isset($data[$key])) {
                            $new_data[$key] = $data[$key];
                        }
                    }
                    Context::override(ServerRequestInterface::class, function (ServerRequestInterface $request) use ($new_data) {
                        return $request->withParsedBody($new_data);
                    });
                }
            }
        }
        return $proceedingJoinPoint->process();
    }
}