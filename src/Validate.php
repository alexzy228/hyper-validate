<?php

namespace Alexzy\HyperfValidate;

use Alexzy\HyperfValidate\Exception\ValidateException;
use Closure;
use Hyperf\HttpMessage\Upload\UploadedFile;
use Hyperf\Utils\Str;

class Validate
{
    /**
     * @var array|string 错误信息
     */
    protected $error = [];

    /**
     * @var array 验证场景
     */
    protected $scene = [];

    /**
     * @var string 当前验证场景
     */
    protected $currentScene;

    /**
     * @var bool 是否批量验证
     */
    protected $batch = false;

    /**
     * @var bool 验证失败是否抛出异常
     */
    protected $failException = false;

    /**
     * @var array 限定验证规则
     */
    protected $only = [];

    /**
     * @var array 追加验证规则
     */
    protected $append = [];

    /**
     * @var array 移除验证规则
     */
    protected $remove = [];

    /**
     * @var array 字段描述
     */
    protected $filed = [];

    /**
     * @var array 当前验证规则
     */
    protected $rule = [];

    /**
     * 验证规则别名
     * @var string[]
     */
    protected $alias = [
        '>' => 'gt',
        '>=' => 'egt',
        '<' => 'lt',
        '<=' => 'elt',
        '=' => 'eq',
        'same' => 'eq',
    ];

    /**
     * @var array 自定义验证方法名
     */
    protected $type = [];

    /**
     * @var array 验证提示信息
     */
    protected $message = [];

    /**
     * 验证字段描述
     * @var array
     */
    protected $field = [];

    /**
     * @var string[] 默认规则提示
     */
    protected $typeMsg = [
        'require' => ':attribute require',
        'must' => ':attribute must',
        'number' => ':attribute must be numeric',
        'integer' => ':attribute must be integer',
        'float' => ':attribute must be float',
        'boolean' => ':attribute must be bool',
        'email' => ':attribute not a valid email address',
        'mobile' => ':attribute not a valid mobile',
        'array' => ':attribute must be a array',
        'accepted' => ':attribute must be yes,on or 1',
        'date' => ':attribute not a valid datetime',
        'file' => ':attribute not a valid file',
        'image' => ':attribute not a valid image',
        'alpha' => ':attribute must be alpha',
        'alphaNum' => ':attribute must be alpha-numeric',
        'alphaDash' => ':attribute must be alpha-numeric, dash, underscore',
        'activeUrl' => ':attribute not a valid domain or ip',
        'chs' => ':attribute must be chinese',
        'chsAlpha' => ':attribute must be chinese or alpha',
        'chsAlphaNum' => ':attribute must be chinese,alpha-numeric',
        'chsDash' => ':attribute must be chinese,alpha-numeric,underscore, dash',
        'url' => ':attribute not a valid url',
        'ip' => ':attribute not a valid ip',
        'dateFormat' => ':attribute must be dateFormat of :rule',
        'in' => ':attribute must be in :rule',
        'notIn' => ':attribute be notin :rule',
        'between' => ':attribute must between :1 - :2',
        'notBetween' => ':attribute not between :1 - :2',
        'length' => 'size of :attribute must be :rule',
        'max' => 'max size of :attribute must be :rule',
        'min' => 'min size of :attribute must be :rule',
        'after' => ':attribute cannot be less than :rule',
        'before' => ':attribute cannot exceed :rule',
        'expire' => ':attribute not within :rule',
        'allowIp' => 'access IP is not allowed',
        'denyIp' => 'access IP denied',
        'confirm' => ':attribute out of accord with :2',
        'different' => ':attribute cannot be same with :2',
        'egt' => ':attribute must greater than or equal :rule',
        'gt' => ':attribute must greater than :rule',
        'elt' => ':attribute must less than or equal :rule',
        'lt' => ':attribute must less than :rule',
        'eq' => ':attribute must equal :rule',
        'unique' => ':attribute has exists',
        'regex' => ':attribute not conform to the rules',
        'method' => 'invalid Request method',
        'token' => 'invalid token',
        'fileSize' => 'filesize not match',
        'fileExt' => 'extensions to upload is not allowed',
        'fileMime' => 'mimetype to upload is not allowed',
        'not_rules' => 'not conform to the rules'
    ];

    /**
     * @var array Filter_var 规则
     */
    protected $filter = [
        'email' => FILTER_VALIDATE_EMAIL,
        'ip' => [FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6],
        'integer' => FILTER_VALIDATE_INT,
        'url' => FILTER_VALIDATE_URL,
        'macAddr' => FILTER_VALIDATE_MAC,
        'float' => FILTER_VALIDATE_FLOAT,
    ];

    /**
     * @var array 验证正则定义
     */
    protected $regex = [];

    /**
     * @var string[] 默认正则规则
     */
    protected $defaultRegex = [
        'alpha' => '/^[A-Za-z]+$/',
        'alphaNum' => '/^[A-Za-z0-9]+$/',
        'alphaDash' => '/^[A-Za-z0-9\-\_]+$/',
        'chs' => '/^[\x{4e00}-\x{9fa5}]+$/u',
        'chsAlpha' => '/^[\x{4e00}-\x{9fa5}a-zA-Z]+$/u',
        'chsAlphaNum' => '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9]+$/u',
        'chsDash' => '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\_\-]+$/u',
        'mobile' => '/^1[3-9]\d{9}$/',
        'idCard' => '/(^[1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$)|(^[1-9]\d{5}\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}$)/',
        'zip' => '/\d{6}/',
    ];

    /**
     * 设置验证场景
     * @param string $name
     * @return $this
     */
    public function scene(string $name)
    {
        $this->currentScene = $name;
        return $this;
    }

    /**
     * 初始化验证场景规则
     * @param string $scene
     */
    public function initScene(string $scene): void
    {
        $this->only = $this->append = $this->remove = [];
        if (method_exists($this, 'scene' . $scene)) {
            // 场景方法存在则调用执行场景方法
            call_user_func([$this, 'scene' . $scene]);
        } elseif (isset($this->scene[$scene])) {
            // 设置了数组格式的场景规则
            $this->only = $this->scene[$scene];
        }
    }

    /**
     * 设置是否批量验证
     * @param bool $batch
     * @return $this
     */
    public function batch(bool $batch = true)
    {
        $this->batch = $batch;
        return $this;
    }

    /**
     * 设置验证规则提示信息
     * @param $type
     * @param string|null $msg
     */
    public function setTypeMsg($type, string $msg = null): void
    {
        if (is_array($type)) {
            $this->typeMsg = array_merge($this->typeMsg, $type);
        } else {
            $this->typeMsg[$type] = $msg;
        }
    }

    /**
     * 设置提示信息
     * @param array $message
     * @return $this
     */
    public function message(array $message)
    {
        $this->message = array_merge($this->message, $message);
        return $this;
    }

    /**
     * 判断验证场景是否存在
     * @param string $name
     * @return bool
     */
    public function hasScene(string $name): bool
    {
        return isset($this->scene[$name]) || method_exists($this, 'scene' . $name);
    }

    /**
     * 设置验证失败后是否抛出异常
     * @param bool $fail
     * @return $this
     */
    public function failException(bool $fail = true)
    {
        $this->failException = $fail;
        return $this;
    }

    /**
     * 指定需要验证的字段
     * @param array $fields
     * @return $this
     */
    public function only(array $fields)
    {
        $this->only = $fields;
        return $this;
    }

    /**
     * 移除指定字段的验证规则
     * @param $field
     * @param null $rule
     * @return $this
     */
    public function remove($field, $rule = null)
    {
        if (is_array($field)) {
            foreach ($field as $key => $rule) {
                if (is_int($key)) {
                    $this->remove($rule);
                } else {
                    $this->remove($key, $rule);
                }
            }
        } else {
            if (is_string($rule)) {
                $rule = explode('|', $rule);
            }
            $this->remove[$field] = $rule;
        }
        return $this;
    }

    /**
     * 追加指定字段的验证规则
     * @param $field
     * @param null $rule
     * @return $this
     */
    public function append($field, $rule = null)
    {
        if (is_array($field)) {
            foreach ($field as $key => $rule) {
                $this->append($key, $rule);
            }
        } else {
            if (is_string($rule)) {
                $rule = explode('|', $rule);
            }
            $this->append[$field] = $rule;
        }
        return $this;
    }

    /**
     * 获取错误信息
     * @return array|string
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * 获取验证场景的规则
     * @param string $name
     * @return array|mixed
     */
    public function getSceneRule(string $name)
    {
        return $this->scene[$name] ?? $this->rule;
    }

    /**
     * 检查方法
     * @param array $data
     * @param array $rules
     * @return bool
     */
    public function check(array $data, array $rules = []): bool
    {
        // 初始化错误信息
        $this->error = [];

        if ($this->currentScene) {
            // 获取当前场景配置信息
            $this->initScene($this->currentScene);
        }

        if (empty($rules)) {
            // 读取验证规则
            $rules = $this->rule;
        }
        // 处理追加验证规则
        foreach ($this->append as $key => $rule) {
            // 如果验证规则不存在 则追加
            if (!isset($rules[$key])) {
                $rules[$key] = $rule;
            }
        }
        foreach ($rules as $key => $rule) {
            if (strpos($key, '|')) {
                // key包含| 取出别名作为title
                [$key, $title] = explode('|', $key);
            } else {
                // 从字段描述中获取title 或直接使用key
                $title = $this->field[$key] ?? $key;
            }
            // 指定验证 但字段不包含直接返回
            if (!empty($this->only) && !in_array($key, $this->only)) {
                continue;
            }
            // 根据key值获取值
            $value = $this->getDataValue($data, $key);

            // 闭包
            if ($rule instanceof Closure) {
                $result = call_user_func_array($rule, [$value, $data]);
            } elseif ($rule instanceof ValidateRule) {
                $result = $this->checkItem($key, $value, $rule->getRule(), $data, $rule->getTitle(), $rule->getMsg());
            } else {
                $result = $this->checkItem($key, $value, $rule, $data, $title);
            }

            if (true !== $result) {
                // 没有返回true 则表示验证失败
                if (!empty($this->batch)) {
                    // 批量验证
                    $this->error[$key] = $result;
                } elseif ($this->failException) {
                    throw new ValidateException($result);
                } else {
                    $this->error = $result;
                    return false;
                }
            }
        }

        if (!empty($this->error)) {
            if ($this->failException) {
                throw new ValidateException($this->error);
            }
            return false;
        }

        return true;
    }


    /**
     * 验证单个字段规则
     * @param string $field
     * @param $value
     * @param $rules
     * @param array $data
     * @param string $title
     * @param array $msg
     * @return bool
     */
    public function checkItem(string $field, $value, $rules, array $data, string $title = '', array $msg = [])
    {
        if (isset($this->remove[$field]) && true === $this->remove[$field] && empty($this->append[$field])) {
            // 字段已经移除
            return true;
        }

        if (is_string($rules)) {
            // 支持多规则验证 require|in:a,b,c|... 或者 ['require','in'=>'a,b,c',...]
            $rules = explode('|', $rules);
        }

        if (isset($this->append[$field])) {
            // 追加额外的验证规则
            $rules = array_unique(array_merge($rules, $this->append[$field]), SORT_REGULAR);
        }
        // 规则不存在默认返回true
        $result = true;
        $i = 0;
        // 循环处理每个验证规则
        foreach ($rules as $key => $rule) {
            if ($rule instanceof Closure) {
                // 获取闭包执行结果
                $result = call_user_func_array($rule, [$value, $data]);
                $info = is_numeric($key) ? '' : $key;
            } else {
                // 获取规则类型
                [$type, $rule, $info] = $this->getValidateType($key, $rule);
                if (isset($this->remove[$field]) && in_array($info, $this->remove[$field])) {
                    // 字段或字段别名在移除列表中 且 没有在追加列表中
                    if (!isset($this->append[$field]) || !in_array($info, $this->append[$field])) {
                        // 规则已经移除
                        $i++;
                        continue;
                    }
                }

                if (isset($this->type[$type])) {
                    // 调用自定义验证类型方法
                    $result = call_user_func_array($this->type[$type], [$value, $rule, $data, $field, $title]);
                } elseif ('must' == $info || 0 === strpos($info, 'require') || (!is_null($value) && '' !== $value)) {
                    // 调用方法验证
                    $result = call_user_func_array([$this, $type], [$value, $rule, $data, $field, $title]);
                } else {
                    $result = true;
                }
            }

            if (false === $result) {
                // 验证失败
                if (!empty($msg[$i])) {
                    $message = $msg[$i];
                    $message = $this->translator(substr($message, 2, -1));
                } else {
                    $message = $this->getRuleMsg($field, $title, $info, $rule);
                }
                return $message;
            } elseif (true !== $result) {
                // 返回自定义错误信息
                if (is_string($result) && false !== strpos($result, ':')) {
                    $result = str_replace(':attribute', $title, $result);
                    if (strpos($result, ':rule') && is_scalar($rule)) {
                        $result = str_replace(':rule', (string)$rule, $result);
                    }
                }
                return $result;
            }
            $i++;
        }
        return $result;
    }

    /**
     * 通过key名获取数据值
     * @param array $data
     * @param $key
     * @return int|mixed|string|null
     */
    public function getDataValue(array $data, $key)
    {
        if (is_numeric($key)) {
            $value = $key;
        } elseif (is_string($key) && strpos($key, '.')) {
            $value = null;
            // 存在. 则获取多维数组数据
            foreach (explode('.', $key) as $key) {
                if (!isset($data[$key])) {
                    $value = null;
                    break;
                }
                $value = $data = $data[$key];
            }
        } else {
            $value = $data[$key] ?? null;
        }
        return $value;
    }

    /**
     * 获取当前验证类型及规则
     * @param $key
     * @param $rule
     * @return array
     */
    public function getValidateType($key, $rule): array
    {
        // 数组验证规则 (以数组形式传递规则)
        // ['require','in'=>'a,b,c',...]
        if (!is_numeric($key)) {
            if (isset($this->alias[$key])) {
                $key = $this->alias[$key];
            }
            // type rule info
            return [$key, $rule, $key];
        }
        // :分割验证规则 (以:分割数组传递规则)
        // require|in:a,b,c|...
        if (strpos($rule, ":")) {
            [$type, $rule] = explode(':', $rule, 2);
            if (isset($this->alias[$type])) {
                $type = $this->alias[$type];
            }
            $info = $type;
        } elseif (method_exists($this, $rule)) {
            // 自定义方法规则
            $type = $rule;
            $info = $rule;
            $rule = '';
        } else {
            // 普通规则
            $type = 'is';
            $info = $rule;
        }

        return [$type, $rule, $info];
    }

    /**
     * 获取验证规则的错误提示信息
     * @param string $attribute
     * @param string $title
     * @param string $type
     * @param $rule
     * @return array|string|string[]
     */
    public function getRuleMsg(string $attribute, string $title, string $type, $rule)
    {
        if (isset($this->message[$attribute . '.' . $type])) {
            $msg = $this->message[$attribute . '.' . $type];
        } elseif (isset($this->message[$attribute][$type])) {
            $msg = $this->message[$attribute][$type];
        } elseif (isset($this->message[$attribute])) {
            $msg = $this->message[$attribute];
        } elseif (isset($this->typeMsg[$type])) {
            $msg = $this->translator($type);
        } elseif (0 === strpos($type, 'require')) {
            $msg = $this->translator('require');
        } else {
            $msg = $title . $this->translator('not_rules');
        }

        if (is_array($msg)) {
            return $this->errorMsgIsArray($msg, $rule, $title);
        }
        return $this->parseErrorMsg($msg, $rule, $title);
    }

    /**
     * 翻译 多语言支持
     * @param $key
     * @return string
     */
    private function translator($key)
    {
        $lang = 'validation.' . $key;
        $lang = trans($lang);
        return $lang == 'validation.' . $key ? $this->typeMsg[$key] : $lang;
    }

    /**
     * 判断是否为图片
     * @param $image
     * @return false|int|mixed
     */
    protected function getImageType($image)
    {
        if (function_exists('exif_imagetype')) {
            return exif_imagetype($image);
        }

        try {
            $info = getimagesize($image);
            return $info ? $info[2] : false;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * 错误信息数组处理
     * @param array $msg
     * @param $rule
     * @param string $title
     * @return array
     */
    protected function errorMsgIsArray(array $msg, $rule, string $title)
    {
        foreach ($msg as $key => $val) {
            if (is_string($val)) {
                $msg[$key] = $this->parseErrorMsg($val, $rule, $title);
            }
        }
        return $msg;
    }

    /**
     * 获取验证规则的错误提示信息
     * @param string $msg
     * @param $rule
     * @param string $title
     * @return array|string|string[]
     */
    protected function parseErrorMsg(string $msg, $rule, string $title)
    {
        if (0 === strpos($msg, '{%')) {
            $msg = $this->translator(substr($msg, 2, -1));
        }

        if (is_array($msg)) {
            return $this->errorMsgIsArray($msg, $rule, $title);
        }

        if (is_scalar($rule) && false !== strpos($msg, ":")) {
            // 变量替换
            if (is_string($rule) && strpos($rule, ',')) {
                $array = array_pad(explode(',', $rule), 3, '');
            } else {
                $array = array_pad([], 3, '');
            }

            $msg = str_replace(
                [':attribute', ':1', ':2', ':3'],
                [$title, $array[0], $array[1], $array[2]],
                $msg
            );

            if (strpos($msg, ':rule')) {
                $msg = str_replace(':rule', (string)$rule, $msg);
            }
        }

        return $msg;
    }


    /******************** 验证方法 **************************************/
    /**
     * 验证字段值是否为有效格式
     * @param $value
     * @param string $rule
     * @param array $data
     * @return bool
     */
    public function is($value, string $rule, array $data = []): bool
    {
        switch (Str::camel($rule)) {
            case 'require':
                // 必须
                $result = !empty($value) || '0' == $value;
                break;
            case 'accepted':
                // 接受
                $result = in_array($value, ['1', 'on', 'yes']);
                break;
            case 'date':
                // 是否是一个有效日期
                $result = false !== strtotime($value);
                break;
            case 'activeUrl':
                // 是否为有效的网址
                $result = checkdnsrr($value);
                break;
            case 'boolean':
            case 'bool':
                // 是否为布尔值
                $result = in_array($value, [true, false, 0, 1, '0', '1'], true);
                break;
            case 'number':
                $result = ctype_digit((string)$value);
                break;
            case 'alphaNum':
                $result = ctype_alnum($value);
                break;
            case 'array':
                // 是否为数组
                $result = is_array($value);
                break;
            case 'file':
                $result = $value instanceof UploadedFile;
                break;
            case 'image':
                $result = $value instanceof UploadedFile && in_array($this->getImageType($value->getRealPath()), [1, 2, 3, 6]);
                break;
            default:
                if (isset($this->type[$rule])) {
                    // 注册的验证规则
                    $result = call_user_func_array($this->type[$rule], [$value]);
                } elseif (function_exists('ctype_' . $rule)) {
                    // ctype_ 方法验证规则
                    $ctypeFun = 'ctype_' . $rule;
                    $result = $ctypeFun($value);
                } elseif (isset($this->filter[$rule])) {
                    // Filter_var验证规则
                    $result = $this->filter($value, $this->filter[$rule]);
                } else {
                    $result = $this->regex($value, $rule);
                }
        }
        return $result;
    }

    /**
     * 使用filter_var方式验证
     * @param $value
     * @param $rule
     * @return bool
     */
    public function filter($value, $rule): bool
    {
        if (is_string($rule) && strpos($rule, ',')) {
            [$rule, $param] = explode(',', $rule);
        } elseif (is_array($rule)) {
            $param = $rule[1] ?? null;
            $rule = $rule[0];
        } else {
            $param = null;
        }
        return false !== filter_var($value, is_int($rule) ? $rule : filter_id($rule), $param);
    }

    /**
     * 使用正则验证数据
     * @param $value
     * @param $rule
     * @return bool
     */
    public function regex($value, $rule): bool
    {
        if (isset($this->regex[$rule])) {
            $rule = $this->regex[$rule];
        } elseif (isset($this->defaultRegex[$rule])) {
            $rule = $this->defaultRegex[$rule];
        }

        if (is_string($rule) && 0 !== strpos($rule, '/') && !preg_match('/\/[imsU]{0,4}$/', $rule)) {
            // 不是正则表达式则两端补上/
            $rule = '/^' . $rule . '$/';
        }

        return is_scalar($value) && 1 === preg_match($rule, (string)$value);
    }

    /**
     * 验证是否和某个字段的值一致
     * @param $value
     * @param $rule
     * @param array $data
     * @param string $field
     * @return bool
     */
    public function confirm($value, $rule, array $data = [], string $field = ''): bool
    {
        if ('' == $rule) {
            if (strpos($field, '_confirm')) {
                $rule = strstr($field, '_confirm', true);
            } else {
                $rule = $field . '_confirm';
            }
        }
        return $this->getDataValue($data, $rule) === $value;
    }

    /**
     * 验证是否和某个字段值不同
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function different($value, $rule, array $data = []): bool
    {
        return $this->getDataValue($data, $rule) != $value;
    }

    /**
     * 验证是否大于等于某个值
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function egt($value, $rule, array $data = []): bool
    {
        return $value >= $this->getDataValue($data, $rule);
    }

    /**
     * 验证是否大于某个值
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function gt($value, $rule, array $data = []): bool
    {
        return $value > $this->getDataValue($data, $rule);
    }

    /**
     * 验证是否小于等于某个值
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function elt($value, $rule, array $data = []): bool
    {
        return $value <= $this->getDataValue($data, $rule);
    }

    /**
     * 验证是否小于某个值
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function lt($value, $rule, array $data = []): bool
    {
        return $value < $this->getDataValue($data, $rule);
    }

    /**
     * 验证是否等于某个值
     * @param $value
     * @param $rule
     * @return bool
     */
    public function eq($value, $rule): bool
    {
        return $value == $rule;
    }

    /**
     * 必须验证
     * @param $value
     * @param null $rule
     * @return bool
     */
    public function must($value, $rule = null): bool
    {
        return !empty($value) || '0' == $value;
    }

    /**
     * 验证是否为合格的域名或者IP 支持A，MX，NS，SOA，PTR，CNAME，AAAA，A6， SRV，NAPTR，TXT 或者 ANY类型
     * @param string $value
     * @param string $rule
     * @return bool
     */
    public function activeUrl(string $value, string $rule = 'MX'): bool
    {
        if (!in_array($rule, ['A', 'MX', 'NS', 'SOA', 'PTR', 'CNAME', 'AAAA', 'A6', 'SRV', 'NAPTR', 'TXT', 'ANY'])) {
            $rule = 'MX';
        }

        return checkdnsrr($value, $rule);
    }

    /**
     * 验证是否有效IP
     * @param $value
     * @param string $rule
     * @return bool
     */
    public function ip($value, string $rule = 'ipv4'): bool
    {
        if (!in_array($rule, ['ipv4', 'ipv6'])) {
            $rule = 'ipv4';
        }

        return $this->filter($value, [FILTER_VALIDATE_IP, 'ipv6' == $rule ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4]);
    }

    /**
     * 验证上传文件后缀
     * @param $file
     * @param $rule
     * @return bool
     */
    public function fileExt($file, $rule): bool
    {
        if (is_array($file)) {
            foreach ($file as $item) {
                if (!($item instanceof UploadedFile) || !$this->checkExt($item, $rule)) {
                    return false;
                }
            }
            return true;
        } elseif ($file instanceof UploadedFile) {
            return $this->checkExt($file, $rule);
        }

        return false;
    }

    /**
     * 验证上传文件类型
     * @param $file
     * @param $rule
     * @return bool
     */
    public function fileMime($file, $rule): bool
    {
        if (is_array($file)) {
            foreach ($file as $item) {
                if (!($item instanceof UploadedFile) || !$this->checkMime($item, $rule)) {
                    return false;
                }
            }
            return true;
        } elseif ($file instanceof UploadedFile) {
            return $this->checkMime($file, $rule);
        }

        return false;
    }

    /**
     * 验证上传文件大小
     * @param $file
     * @param $rule
     * @return bool
     */
    public function fileSize($file, $rule): bool
    {
        if (is_array($file)) {
            foreach ($file as $item) {
                if (!($item instanceof UploadedFile) || !$this->checkSize($item, $rule)) {
                    return false;
                }
            }
            return true;
        } elseif ($file instanceof UploadedFile) {
            return $this->checkSize($file, $rule);
        }

        return false;
    }

    /**
     * 验证图片的宽高及类型
     * @param $file
     * @param $rule
     * @return bool
     */
    public function image($file, $rule): bool
    {
        if (!($file instanceof UploadedFile)) {
            return false;
        }
        if ($rule) {
            $rule = explode(',', $rule);
            [$width, $height, $type] = getimagesize($file->getRealPath());
            if (isset($rule[2])) {
                $imageType = strtolower($rule[2]);

                if ('jpg' == $imageType) {
                    $imageType = 'jpeg';
                }
                if (image_type_to_extension($type, false) != $imageType) {
                    return false;
                }
            }
            [$w, $h] = $rule;
            return $w == $width && $h == $height;
        }
        return in_array($this->getImageType($file->getRealPath()), [1, 2, 3, 6]);
    }

    /**
     * 验证时间和日期是否符合指定格式
     * @param $value
     * @param $rule
     * @return bool
     */
    public function dateFormat($value, $rule): bool
    {
        $info = date_parse_from_format($rule, $value);
        return 0 == $info['warning_count'] && 0 == $info['error_count'];
    }

    /**
     * 验证是否唯一
     * @param $value
     * @param $rule
     * @param array $data
     * @param string $field
     * @return bool
     */
    public function unique($value, $rule, array $data = [], string $field = ''): bool
    {
    }

    /**
     * 验证某个字段等于某个值的时候必须
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function requireIf($value, $rule, array $data = []): bool
    {
        [$field, $val] = explode(',', $rule);

        if ($this->getDataValue($data, $field) == $val) {
            return !empty($value) || '0' == $value;
        }

        return true;
    }

    /**
     * 通过回调方法验证某个字段是否必须
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function requireCallback($value, $rule, array $data = []): bool
    {
        $result = call_user_func_array([$this, $rule], [$value, $data]);

        if ($result) {
            return !empty($value) || '0' == $value;
        }

        return true;
    }

    /**
     * 验证某个字段有值的情况下必须
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function requireWith($value, $rule, array $data = []): bool
    {
        $val = $this->getDataValue($data, $rule);

        if (!empty($val)) {
            return !empty($value) || '0' == $value;
        }

        return true;
    }

    /**
     * 验证某个字段没有值的情况下必须
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function requireWithout($value, $rule, array $data = []): bool
    {
        $val = $this->getDataValue($data, $rule);

        if (empty($val)) {
            return !empty($value) || '0' == $value;
        }

        return true;
    }

    /**
     * 验证是否在范围内
     * @param $value
     * @param $rule
     * @return bool
     */
    public function in($value, $rule): bool
    {
        return in_array($value, is_array($rule) ? $rule : explode(',', $rule));
    }

    /**
     * 验证是否不在某个范围
     * @param $value
     * @param $rule
     * @return bool
     */
    public function notIn($value, $rule): bool
    {
        return !in_array($value, is_array($rule) ? $rule : explode(',', $rule));
    }

    /**
     * 验证数据在指定范围
     * @param $value
     * @param $rule
     * @return bool
     */
    public function between($value, $rule): bool
    {
        if (is_string($rule)) {
            $rule = explode(',', $rule);
        }
        [$min, $max] = $rule;

        return $value >= $min && $value <= $max;
    }

    /**
     * 验证数据不在指定范围
     * @param $value
     * @param $rule
     * @return bool
     */
    public function notBetween($value, $rule): bool
    {
        if (is_string($rule)) {
            $rule = explode(',', $rule);
        }
        [$min, $max] = $rule;

        return $value < $min || $value > $max;
    }

    /**
     * 验证数据长度
     * @param $value
     * @param $rule
     * @return bool
     */
    public function length($value, $rule): bool
    {
        if (is_array($value)) {
            $length = count($value);
        } elseif ($value instanceof UploadedFile) {
            $length = $value->getSize();
        } else {
            $length = mb_strlen((string)$value);
        }

        if (is_string($rule) && strpos($rule, ',')) {
            // 长度区间
            [$min, $max] = explode(',', $rule);
            return $length >= $min && $length <= $max;
        }

        // 指定长度
        return $length == $rule;
    }

    /**
     * 验证数据最大长度
     * @param $value
     * @param $rule
     * @return bool
     */
    public function max($value, $rule): bool
    {
        if (is_array($value)) {
            $length = count($value);
        } elseif ($value instanceof UploadedFile) {
            $length = $value->getSize();
        } else {
            $length = mb_strlen((string)$value);
        }

        return $length <= $rule;
    }

    /**
     * 验证数据最小长度
     * @param $value
     * @param $rule
     * @return bool
     */
    public function min($value, $rule): bool
    {
        if (is_array($value)) {
            $length = count($value);
        } elseif ($value instanceof UploadedFile) {
            $length = $value->getSize();
        } else {
            $length = mb_strlen((string)$value);
        }

        return $length >= $rule;
    }

    /**
     * 验证日期之后
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function after($value, $rule, array $data = []): bool
    {
        return strtotime($value) >= strtotime($rule);
    }

    /**
     * 验证日期之前
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function before($value, $rule, array $data = []): bool
    {
        return strtotime($value) <= strtotime($rule);
    }

    /**
     * 指定字段之后
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function afterWith($value, $rule, array $data = []): bool
    {
        $rule = $this->getDataValue($data, $rule);
        return !is_null($rule) && strtotime($value) >= strtotime($rule);
    }

    /**
     * 指定字段之前
     * @param $value
     * @param $rule
     * @param array $data
     * @return bool
     */
    public function beforeWith($value, $rule, array $data = []): bool
    {
        $rule = $this->getDataValue($data, $rule);
        return !is_null($rule) && strtotime($value) <= strtotime($rule);
    }

    /**
     * 验证是否在某个有效日期之内
     * @param $value
     * @param $rule
     * @return bool
     */
    public function expire($value, $rule): bool
    {
        if (is_string($rule)) {
            $rule = explode(',', $rule);
        }

        [$start, $end] = $rule;

        if (!is_numeric($start)) {
            $start = strtotime($start);
        }

        if (!is_numeric($end)) {
            $end = strtotime($end);
        }

        return time() >= $start && time() <= $end;
    }

    /**
     * 验证IP许可
     * @param $value
     * @param $rule
     * @return bool
     */
    public function allowIp($value, $rule): bool
    {
        return in_array($value, is_array($rule) ? $rule : explode(',', $rule));
    }

    /**
     * 验证IP禁用
     * @param $value
     * @param $rule
     * @return bool
     */
    public function denyIp($value, $rule): bool
    {
        return !in_array($value, is_array($rule) ? $rule : explode(',', $rule));
    }

    /**
     * 检测上传文件后缀
     * @param UploadedFile $file
     * @param $ext
     * @return bool
     */
    protected function checkExt(UploadedFile $file, $ext): bool
    {
        if (is_string($ext)) {
            $ext = explode(',', $ext);
        }

        return in_array(strtolower($file->getExtension()), $ext);
    }

    /**
     * 检测上传文件大小
     * @param UploadedFile $file
     * @param $size
     * @return bool
     */
    protected function checkSize(UploadedFile $file, $size): bool
    {
        return $file->getSize() <= (int)$size;
    }

    /**
     * 检测上传文件类型
     * @param UploadedFile $file
     * @param $mime
     * @return bool
     */
    protected function checkMime(UploadedFile $file, $mime): bool
    {
        if (is_string($mime)) {
            $mime = explode(',', $mime);
        }

        return in_array(strtolower($file->getMimeType()), $mime);
    }
}