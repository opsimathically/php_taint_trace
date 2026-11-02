<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PHPUnit\Framework\TestCase;

final class DetectorPipelineTest extends TestCase
{
    public function testPipelineReturnsMultipleFindings(): void
    {
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );

        $invocation = new SinkInvocation(
            sinkName: 'system',
            sinkCategory: SinkCategory::RCE,
            arguments: array(TaintedValue::tainted('id xtanzi', 'query.cmd'))
        );

        $findings = $pipeline->detect($invocation);

        self::assertCount(2, $findings);
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testPayloadDetectorIgnoresMissingKeyword(): void
    {
        $pipeline = new DetectorPipeline(new PayloadKeywordDetector('xtanzi'));

        $invocation = new SinkInvocation(
            sinkName: 'system',
            sinkCategory: SinkCategory::RCE,
            arguments: array('id safe')
        );

        self::assertCount(0, $pipeline->detect($invocation));
    }
}
