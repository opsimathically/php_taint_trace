<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\AuthorizationEvidence;
use PhpTaintTrace\Verification\Model\CandidateCollection;
use PhpTaintTrace\Verification\Model\DetectorCandidate;
use PhpTaintTrace\Verification\Model\DetectorEvidence;
use PhpTaintTrace\Verification\Model\EnvironmentEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;
use PHPUnit\Framework\TestCase;

final class DetectorCandidateTest extends TestCase
{
    public function testCandidateSerializesWithRequiredShapeAndReasonCodes(): void
    {
        $candidate = $this->candidate('abc123');

        $payload = $candidate->toArray();
        self::assertSame('abc123', $payload['id']);
        self::assertSame('system', $payload['sink_name']);
        self::assertSame('rce', $payload['sink_category']);
        self::assertSame(
            array('CATEGORY_RCE', 'DETECTOR_TAINT_INPUT', 'SINK_ARGUMENT_ROLE_PRIMARY', 'TAINT_SOURCE_PRESENT'),
            $payload['reason_codes']
        );
        self::assertArrayHasKey('detector_evidence', $payload);
        self::assertArrayHasKey('taint_evidence', $payload);
        self::assertArrayHasKey('sink_evidence', $payload);
        self::assertArrayHasKey('request_evidence', $payload);
        self::assertArrayHasKey('environment_evidence', $payload);
        self::assertArrayHasKey('authorization_evidence', $payload);
    }

    public function testCandidateCollectionRemainsImmutableWhenAddingEntries(): void
    {
        $first = $this->candidate('candidate-1');
        $collection = new CandidateCollection($first);

        $updated = $collection->withCandidate($this->candidate('candidate-2'));

        self::assertCount(1, $collection->all());
        self::assertCount(2, $updated->all());
        self::assertSame('candidate-1', $collection->first()?->id());
        self::assertSame('candidate-1', $updated->first()?->id());
    }

    private function candidate(string $id): DetectorCandidate
    {
        return new DetectorCandidate(
            id: $id,
            sinkName: 'system',
            sinkCategory: 'rce',
            reasonCodes: array(
                ReasonCode::TAINT_SOURCE_PRESENT,
                ReasonCode::SINK_ARGUMENT_ROLE_PRIMARY,
                ReasonCode::CATEGORY_RCE,
                ReasonCode::DETECTOR_TAINT_INPUT,
            ),
            detectorEvidence: new DetectorEvidence(
                findingCount: 1,
                detectors: array('taint-input-detector'),
                severities: array('debug'),
                messages: array('Tainted input reached sink.')
            ),
            taintEvidence: new TaintEvidence(true, array(0), array('_GET')),
            sinkEvidence: new SinkEvidence('system', 'rce', 1, array(0 => 'primary')),
            requestEvidence: new RequestEvidence('2026-04-22T00:00:00+00:00', 'cli', 'GET', '/?cmd=id'),
            environmentEvidence: new EnvironmentEvidence('8.3.6', 'cli', array('xmark')),
            authorizationEvidence: new AuthorizationEvidence(null, null, null)
        );
    }
}
