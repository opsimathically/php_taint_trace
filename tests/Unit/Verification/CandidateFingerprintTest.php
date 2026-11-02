<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Detector\CandidateFingerprint;
use PhpTaintTrace\Verification\Model\DetectorEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;
use PHPUnit\Framework\TestCase;

final class CandidateFingerprintTest extends TestCase
{
    public function testGenerateIsDeterministicForSameInputs(): void
    {
        $fingerprint = new CandidateFingerprint();

        $invocation = new SinkInvocation('system', SinkCategory::RCE, array(TaintedValue::tainted('id', '_GET')));
        $request = new RequestEvidence('2026-04-22T00:00:00+00:00', 'cli', 'GET', '/?cmd=id');
        $taint = new TaintEvidence(true, array(0), array('_GET'));
        $sink = new SinkEvidence('system', 'rce', 1, array(0 => 'primary'));
        $detector = new DetectorEvidence(1, array('taint-input-detector'), array('debug'), array('Tainted input reached sink.'));
        $reasonCodes = array(ReasonCode::CATEGORY_RCE, ReasonCode::DETECTOR_TAINT_INPUT);

        $first = $fingerprint->generate($invocation, $request, $taint, $sink, $detector, $reasonCodes);
        $second = $fingerprint->generate($invocation, $request, $taint, $sink, $detector, $reasonCodes);

        self::assertSame($first, $second);
    }

    public function testGenerateChangesWhenSinkOrRequestChanges(): void
    {
        $fingerprint = new CandidateFingerprint();

        $invocation = new SinkInvocation('system', SinkCategory::RCE, array(TaintedValue::tainted('id', '_GET')));
        $requestA = new RequestEvidence('2026-04-22T00:00:00+00:00', 'cli', 'GET', '/?cmd=id');
        $requestB = new RequestEvidence('2026-04-22T00:00:00+00:00', 'cli', 'GET', '/?cmd=whoami');
        $taint = new TaintEvidence(true, array(0), array('_GET'));
        $sink = new SinkEvidence('system', 'rce', 1, array(0 => 'primary'));
        $detector = new DetectorEvidence(1, array('taint-input-detector'), array('debug'), array('Tainted input reached sink.'));
        $reasonCodes = array(ReasonCode::CATEGORY_RCE, ReasonCode::DETECTOR_TAINT_INPUT);

        $first = $fingerprint->generate($invocation, $requestA, $taint, $sink, $detector, $reasonCodes);
        $second = $fingerprint->generate($invocation, $requestB, $taint, $sink, $detector, $reasonCodes);

        self::assertNotSame($first, $second);
    }

    public function testGenerateHandlesNonUtf8StringsWithoutThrowing(): void
    {
        $fingerprint = new CandidateFingerprint();

        $binary = hex2bin('80fffe00');
        self::assertNotFalse($binary);

        $invocation = new SinkInvocation('system', SinkCategory::RCE, array($binary));
        $request = new RequestEvidence('2026-04-22T00:00:00+00:00', 'fpm-fcgi', 'GET', '/?cmd=binary');
        $taint = new TaintEvidence(false, array(), array());
        $sink = new SinkEvidence('system', 'rce', 1, array(0 => 'primary'));
        $detector = new DetectorEvidence(0, array(), array(), array());
        $reasonCodes = array(ReasonCode::CATEGORY_RCE);

        $id = $fingerprint->generate($invocation, $request, $taint, $sink, $detector, $reasonCodes);

        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $id);
    }
}
