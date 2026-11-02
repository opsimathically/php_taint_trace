<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Detector;

use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Model\AuthorizationEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;

final class ReasonCodeEmitter
{
    /**
     * @param Finding[] $findings
     * @return ReasonCode[]
     */
    public function emit(
        SinkInvocation $invocation,
        array $findings,
        TaintEvidence $taintEvidence,
        SinkEvidence $sinkEvidence,
        AuthorizationEvidence $authorizationEvidence
    ): array {
        $detectorNames = array();
        foreach ($findings as $finding) {
            $detectorNames[] = $finding->detector();
        }

        $codes = array();
        if (in_array('taint-input-detector', $detectorNames, true)) {
            $codes[ReasonCode::DETECTOR_TAINT_INPUT->value] = ReasonCode::DETECTOR_TAINT_INPUT;
        }

        if (in_array('payload-keyword-detector', $detectorNames, true)) {
            $codes[ReasonCode::DETECTOR_PAYLOAD_KEYWORD->value] = ReasonCode::DETECTOR_PAYLOAD_KEYWORD;
        }

        if ($sinkEvidence->hasPrimaryRole()) {
            $codes[ReasonCode::SINK_ARGUMENT_ROLE_PRIMARY->value] = ReasonCode::SINK_ARGUMENT_ROLE_PRIMARY;
        }

        if ($taintEvidence->sourcePresent()) {
            $codes[ReasonCode::TAINT_SOURCE_PRESENT->value] = ReasonCode::TAINT_SOURCE_PRESENT;
        }

        if ($authorizationEvidence->isPresent()) {
            $codes[ReasonCode::AUTHZ_EVIDENCE_PRESENT->value] = ReasonCode::AUTHZ_EVIDENCE_PRESENT;
        } elseif ($authorizationEvidence->isPartial()) {
            $codes[ReasonCode::AUTHZ_EVIDENCE_PARTIAL->value] = ReasonCode::AUTHZ_EVIDENCE_PARTIAL;
        } else {
            $codes[ReasonCode::AUTHZ_EVIDENCE_UNAVAILABLE->value] = ReasonCode::AUTHZ_EVIDENCE_UNAVAILABLE;
        }

        $categoryReasonCode = $this->categoryReasonCode($invocation->sinkCategory()->value);
        if ($categoryReasonCode !== null) {
            $codes[$categoryReasonCode->value] = $categoryReasonCode;
        }

        ksort($codes);
        return array_values($codes);
    }

    private function categoryReasonCode(string $sinkCategory): ?ReasonCode
    {
        return match ($sinkCategory) {
            'rce' => ReasonCode::CATEGORY_RCE,
            'sqli' => ReasonCode::CATEGORY_SQLI,
            'ssrf' => ReasonCode::CATEGORY_SSRF,
            'file' => ReasonCode::CATEGORY_FILE,
            'xss' => ReasonCode::CATEGORY_XSS,
            'idor' => ReasonCode::CATEGORY_IDOR,
            'xxe' => ReasonCode::CATEGORY_XXE,
            default => null,
        };
    }
}
