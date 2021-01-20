<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace Alexzy\HyperfValidate;

class ConfigProvider
{
    public function __invoke(): array
    {
        $languagesPath = BASE_PATH . '/storage/languages';
        $translationConfigFile = BASE_PATH . '/config/autoload/translation.php';
        if (file_exists($translationConfigFile)) {
            $translationConfig = include $translationConfigFile;
            $languagesPath = $translationConfig['path'] ?? $languagesPath;
        }

        return [
            'dependencies' => [
            ],
            'commands' => [
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            'publish' => [
                [
                    'id' => 'en',
                    'description' => '验证器英语语言包', // 描述
                    // 建议默认配置放在 publish 文件夹中，文件命名和组件名称相同
                    'source' => __DIR__ . '/../publish/language/en/validation.php',  // 对应的配置文件路径
                    'destination' => $languagesPath . '/en/validation.php', // 复制为这个路径下的该文件
                ],
                [
                    'id' => 'zh_CN',
                    'description' => '验证器中文语言包', // 描述
                    // 建议默认配置放在 publish 文件夹中，文件命名和组件名称相同
                    'source' => __DIR__ . '/../publish/language/zh_CN/validation.php',  // 对应的配置文件路径
                    'destination' => $languagesPath . '/zh_CN/validation.php', // 复制为这个路径下的该文件
                ],
            ],
        ];
    }
}
