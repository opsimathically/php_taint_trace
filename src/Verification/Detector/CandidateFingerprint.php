<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Detector;

use JsonException;
use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Model\DetectorEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;
use RuntimeException;

final class CandidateFingerprint
{
    /**
     * @param ReasonCode[] $reasonCodes
     */
    public function generate(
        SinkInvocation $invocation,
        RequestEvidence $requestEvidence,
        TaintEvidence $taintEvidence,
        SinkEvidence $sinkEvidence,
        DetectorEvidence $detectorEvidence,
        array $reasonCodes
    ): string {
        $payload = array(
            'sink_name' => $invocation->sinkName(),
            'sink_category' => $invocation->sinkCategory()->value,
            'arguments' => $this->normalize($invocation->arguments()),
            'request_method' => $requestEvidence->requestMethod(),
            'request_uri' => $requestEvidence->requestUri(),
            'tainted_argument_indexes' => $taintEvidence->taintedArgumentIndexes(),
            'source_families' => $taintEvidence->sourceFamilies(),
            'argument_roles' => $sinkEvidence->argumentRoles(),
            'detectors' => $detectorEvidence->detectors(),
            'reason_codes' => array_map(
                static fn (ReasonCode $reasonCode): string => $reasonCode->value,
                $reasonCodes
            ),
        );

        try {
            $encoded = json_encode(
                $payload,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new RuntimeException('Failed to build candidate fingerprint payload.', 0, $e);
        }

        return hash('sha256', $encoded);
    }

    private function normalize(mixed $value): mixed
    {
        if ($value instanceof TaintedValue) {
            return array(
                'type' => 'tainted',
                'sources' => $value->metadata()->sources(),
                'value' => $this->normalize($value->value()),
            );
        }

        if (is_array($value)) {
            $keys = array_keys($value);
            $sequential = $keys === range(0, count($value) - 1);

            if ($sequential) {
                return array_map(fn (mixed $inner): mixed => $this->normalize($inner), $value);
            }

            ksort($value);
            $result = array();
            foreach ($value as $key => $inner) {
                $result[(string) $key] = $this->normalize($inner);
            }

            return $result;
        }

        if (is_object($value)) {
            return array('type' => 'object', 'class' => $value::class);
        }

        if (is_resource($value)) {
            return array(
                'type' => 'resource',
                'resource_type' => get_resource_type($value),
            );
        }

        if (is_string($value)) {
            return $this->normalizeString($value);
        }

        return $value;
    }

    private function normalizeString(string $value): mixed
    {
        if (preg_match('//u', $value) === 1) {
            return $value;
        }

        return array(
            'type' => 'binary_string',
            'length' => strlen($value),
            'sha256' => hash('sha256', $value),
        );
    }
}
