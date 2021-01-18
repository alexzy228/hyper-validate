<?php
declare(strict_types=1);

namespace Alexzy\HyperfValidate\Annotation;

use Hyperf\Di\Annotation\AbstractAnnotation;

/**
 * Class Validate
 * @package Alexzy\HyperfValidate\Annotation
 * @Annotation
 * @Target({"METHOD"})
 */
class Validate extends AbstractAnnotation
{
    /**
     * 验证器
     * @var string
     */
    public $validate = '';

    /**
     * 场景
     * @var string
     */
    public $scene = '';

    /**
     * 是否过滤多余字段
     * @var bool
     */
    public $filter = true;

    /**
     * 是否批量验证
     * @var bool
     */
    public $batch = false;

    /**
     * 过滤是否抛出异常
     * @var bool
     */
    public $throws = true;

    public function __construct($value = null)
    {
        parent::__construct($value);
        $this->bindMainProperty('validate', $value);
    }

}