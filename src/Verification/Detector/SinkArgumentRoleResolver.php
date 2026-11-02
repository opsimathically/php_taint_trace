<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Detector;

use PhpTaintTrace\Model\SinkInvocation;

final class SinkArgumentRoleResolver
{
    /**
     * @return array<int, string>
     */
    public function resolve(SinkInvocation $invocation): array
    {
        $argumentCount = count($invocation->arguments());
        if ($argumentCount === 0) {
            return array();
        }

        $roleMap = $this->categoryRoleMap($invocation->sinkCategory()->value, $invocation->sinkName());
        if ($roleMap === array()) {
            $roleMap = $this->defaultRoleMap($argumentCount);
        }

        $result = array();
        for ($index = 0; $index < $argumentCount; $index++) {
            if (array_key_exists($index, $roleMap)) {
                $result[$index] = $roleMap[$index];
                continue;
            }

            $result[$index] = $index === 0 ? 'primary' : 'secondary';
        }

        return $result;
    }

    /**
     * @return array<int, string>
     */
    private function categoryRoleMap(string $sinkCategory, string $sinkName): array
    {
        return match ($sinkCategory) {
            'rce' => $this->rceRoleMap($sinkName),
            'sqli' => array(0 => 'primary'),
            'ssrf' => array(0 => 'primary'),
            'file' => $this->fileRoleMap($sinkName),
            'xss' => array(0 => 'primary'),
            'idor' => array(0 => 'resource_id'),
            'xxe' => array(0 => 'primary'),
            default => array(),
        };
    }

    /**
     * @return array<int, string>
     */
    private function rceRoleMap(string $sinkName): array
    {
        return match ($sinkName) {
            'do_fcall',
            'do_fcall_by_name',
            'do_icall',
            'do_ucall',
            'init_dynamic_call',
            'init_method_call',
            'init_user_call',
            'proc_open' => array(
                0 => 'primary',
                1 => 'secondary',
            ),
            'mail' => array(0 => 'primary'),
            default => array(0 => 'primary'),
        };
    }

    /**
     * @return array<int, string>
     */
    private function fileRoleMap(string $sinkName): array
    {
        return match ($sinkName) {
            'copy',
            'link',
            'rename',
            'symlink' => array(
                0 => 'primary',
                1 => 'secondary',
            ),
            'SplFileObject::__construct' => array(
                0 => 'primary',
            ),
            default => array(0 => 'primary'),
        };
    }

    /**
     * @return array<int, string>
     */
    private function defaultRoleMap(int $argumentCount): array
    {
        $result = array();
        for ($index = 0; $index < $argumentCount; $index++) {
            $result[$index] = $index === 0 ? 'primary' : 'secondary';
        }

        return $result;
    }
}
