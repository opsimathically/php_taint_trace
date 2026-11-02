<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Detector\SinkArgumentRoleResolver;
use PHPUnit\Framework\TestCase;

final class SinkArgumentRoleResolverTest extends TestCase
{
    public function testResolveMapsRepresentativeSinkRoles(): void
    {
        $resolver = new SinkArgumentRoleResolver();

        self::assertSame(
            array(0 => 'primary', 1 => 'secondary'),
            $resolver->resolve(new SinkInvocation('do_fcall', SinkCategory::RCE, array('callable', array('arg'))))
        );
        self::assertSame(
            array(0 => 'primary'),
            $resolver->resolve(new SinkInvocation('mysqli_query', SinkCategory::SQLI, array('SELECT 1')))
        );
        self::assertSame(
            array(0 => 'primary', 1 => 'secondary'),
            $resolver->resolve(new SinkInvocation('copy', SinkCategory::FILE, array('/tmp/a', '/tmp/b')))
        );
        self::assertSame(
            array(0 => 'primary', 1 => 'secondary'),
            $resolver->resolve(new SinkInvocation('symlink', SinkCategory::FILE, array('/tmp/a', '/tmp/b')))
        );
        self::assertSame(
            array(0 => 'primary'),
            $resolver->resolve(new SinkInvocation('mail', SinkCategory::RCE, array('-X /tmp/out')))
        );
        self::assertSame(
            array(0 => 'primary'),
            $resolver->resolve(new SinkInvocation('SplFileObject::__construct', SinkCategory::FILE, array('/tmp/a')))
        );
        self::assertSame(
            array(0 => 'primary'),
            $resolver->resolve(new SinkInvocation('echo', SinkCategory::XSS, array('hello')))
        );
        self::assertSame(
            array(0 => 'primary'),
            $resolver->resolve(new SinkInvocation('simplexml_load_string', SinkCategory::XXE, array('<root/>')))
        );
    }
}
