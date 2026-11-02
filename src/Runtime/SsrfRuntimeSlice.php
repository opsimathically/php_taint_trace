<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\BaselineHookPlan;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookPhase;
use PhpTaintTrace\Instrumentation\HookHandlerRegistry;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationBootstrapReport;
use PhpTaintTrace\Instrumentation\LegacyBaselineHookPlanFactory;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PhpTaintTrace\Instrumentation\RuntimeInstrumentationBootstrap;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;
use PhpTaintTrace\Verification\Model\DetectorCandidate;

final class SsrfRuntimeSlice
{
    /**
     * @var array<string, mixed>
     */
    private array $curlUrlByHandle = array();
    /**
     * @var array<string, array<int, string>>
     */
    private array $curlHandleKeysByMultiHandle = array();

    private readonly HookFindingStore $store;
    private readonly HookCandidateStore $candidateStore;
    private readonly HookDetectionRunner $runner;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        ?DetectorPipeline $pipeline = null,
        private readonly bool $emitCandidates = false
    ) {
        $this->store = new HookFindingStore();
        $this->candidateStore = new HookCandidateStore();
        $this->runner = new HookDetectionRunner(
            $pipeline ?? new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            ),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $sinkPlan = $this->ssrfSinkHookPlan();
        $auxPlan = $this->ssrfAuxHookPlan();
        $runtimePlan = new BaselineHookPlan(
            ...array_merge(
                $sinkPlan->hooks(),
                $auxPlan->hooks()
            )
        );

        $handlers = new HookHandlerRegistry(true);
        foreach ($sinkPlan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName): void {
                $arguments = $this->extractSsrfArguments($hookId, $context->arguments(), $context->metadata());
                $this->runner->inspect($sinkName, SinkCategory::SSRF, $arguments);
            });
        }

        foreach ($auxPlan->hooks() as $hook) {
            $hookId = $hook->id();
            $handlers->register($hookId, function ($context) use ($hookId): void {
                $arguments = $context->arguments();
                if ($hookId === 'aux.ssrf.curl_init') {
                    $this->trackCurlInit($arguments, $context->result());
                    return;
                }

                if ($hookId === 'aux.ssrf.curl_setopt') {
                    $this->trackCurlSetopt($arguments);
                    return;
                }

                if ($hookId === 'aux.ssrf.curl_setopt_array') {
                    $this->trackCurlSetoptArray($arguments);
                    return;
                }

                if ($hookId === 'aux.ssrf.curl_multi_add_handle') {
                    $this->trackCurlMultiAddHandle($arguments);
                }
            });
        }

        $bootstrap = new RuntimeInstrumentationBootstrap($this->backend);
        return $bootstrap->bootstrap($runtimePlan, $handlers);
    }

    public function requestTaintSeeder(): RequestTaintSeeder
    {
        return new RequestTaintSeeder($this->backend);
    }

    /**
     * @return Finding[]
     */
    public function findings(): array
    {
        return $this->store->all();
    }

    public function clearFindings(): void
    {
        $this->store->clear();
        $this->curlUrlByHandle = array();
        $this->curlHandleKeysByMultiHandle = array();
    }

    /**
     * @return DetectorCandidate[]
     */
    public function candidates(): array
    {
        return $this->candidateStore->all();
    }

    public function clearCandidates(): void
    {
        $this->candidateStore->clear();
    }

    private function ssrfSinkHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.ssrf.')
                || str_starts_with($hook->id(), 'method.ssrf.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    private function ssrfAuxHookPlan(): BaselineHookPlan
    {
        return new BaselineHookPlan(
            HookDefinition::function(
                id: 'aux.ssrf.curl_init',
                functionName: 'curl_init',
                phase: HookPhase::AFTER,
                metadata: array(
                    'domain' => 'aux',
                    'category' => 'ssrf',
                )
            ),
            HookDefinition::function(
                id: 'aux.ssrf.curl_setopt',
                functionName: 'curl_setopt',
                phase: HookPhase::BEFORE,
                metadata: array(
                    'domain' => 'aux',
                    'category' => 'ssrf',
                )
            ),
            HookDefinition::function(
                id: 'aux.ssrf.curl_setopt_array',
                functionName: 'curl_setopt_array',
                phase: HookPhase::BEFORE,
                metadata: array(
                    'domain' => 'aux',
                    'category' => 'ssrf',
                )
            ),
            HookDefinition::function(
                id: 'aux.ssrf.curl_multi_add_handle',
                functionName: 'curl_multi_add_handle',
                phase: HookPhase::BEFORE,
                metadata: array(
                    'domain' => 'aux',
                    'category' => 'ssrf',
                )
            )
        );
    }

    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     * @return array<int, mixed>
     */
    private function extractSsrfArguments(string $hookId, array $arguments, array $metadata): array
    {
        if ($hookId === 'sink.ssrf.curl_exec') {
            $effectiveUrl = $metadata['effective_url'] ?? null;
            if (is_string($effectiveUrl)) {
                return array($effectiveUrl);
            }

            $handle = $arguments[0] ?? null;
            $trackedUrl = $this->trackedCurlUrl($handle);
            if ($trackedUrl !== null) {
                return array($trackedUrl);
            }

            return array();
        }

        if ($hookId === 'sink.ssrf.curl_multi_exec') {
            $multiHandle = $arguments[0] ?? null;
            return $this->trackedCurlUrlsForMultiHandle($multiHandle);
        }

        if ($hookId === 'method.ssrf.soapclient.__construct') {
            return $this->extractSoapClientConstructArguments($arguments);
        }

        return $this->takeArgument($arguments, 0);
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function extractSoapClientConstructArguments(array $arguments): array
    {
        $result = array();

        $wsdl = $arguments[0] ?? null;
        if (is_string($wsdl) || $wsdl instanceof TaintedValue) {
            $result[] = $wsdl;
        }

        $options = $arguments[1] ?? null;
        if (is_array($options) && array_key_exists('location', $options)) {
            $location = $options['location'];
            if (is_string($location) || $location instanceof TaintedValue) {
                $result[] = $location;
            }
        }

        return $result;
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function takeArgument(array $arguments, int $index): array
    {
        if (!array_key_exists($index, $arguments)) {
            return array();
        }

        return array($arguments[$index]);
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function trackCurlInit(array $arguments, mixed $result): void
    {
        $handleKey = $this->curlHandleKey($result);
        if ($handleKey === null) {
            return;
        }

        $url = $arguments[0] ?? null;
        if (is_string($url) || $url instanceof \PhpTaintTrace\Core\TaintedValue) {
            $this->curlUrlByHandle[$handleKey] = $url;
        }
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function trackCurlSetopt(array $arguments): void
    {
        $handle = $arguments[0] ?? null;
        $option = $arguments[1] ?? null;
        $value = $arguments[2] ?? null;
        if (!$this->isCurlUrlOption($option)) {
            return;
        }

        $handleKey = $this->curlHandleKey($handle);
        if ($handleKey === null) {
            return;
        }

        if (is_string($value) || $value instanceof TaintedValue) {
            $this->curlUrlByHandle[$handleKey] = $value;
        }
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function trackCurlSetoptArray(array $arguments): void
    {
        $handle = $arguments[0] ?? null;
        $options = $arguments[1] ?? null;
        if (!is_array($options)) {
            return;
        }

        $handleKey = $this->curlHandleKey($handle);
        if ($handleKey === null) {
            return;
        }

        foreach ($options as $option => $value) {
            if (!$this->isCurlUrlOption($option)) {
                continue;
            }

            if (is_string($value) || $value instanceof TaintedValue) {
                $this->curlUrlByHandle[$handleKey] = $value;
            }
        }
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function trackCurlMultiAddHandle(array $arguments): void
    {
        $multiHandle = $arguments[0] ?? null;
        $handle = $arguments[1] ?? null;

        $multiHandleKey = $this->curlHandleKey($multiHandle);
        $handleKey = $this->curlHandleKey($handle);
        if ($multiHandleKey === null || $handleKey === null) {
            return;
        }

        if (!array_key_exists($multiHandleKey, $this->curlHandleKeysByMultiHandle)) {
            $this->curlHandleKeysByMultiHandle[$multiHandleKey] = array();
        }

        if (!in_array($handleKey, $this->curlHandleKeysByMultiHandle[$multiHandleKey], true)) {
            $this->curlHandleKeysByMultiHandle[$multiHandleKey][] = $handleKey;
        }
    }

    private function trackedCurlUrl(mixed $handle): mixed
    {
        $handleKey = $this->curlHandleKey($handle);
        if ($handleKey === null) {
            return null;
        }

        return $this->curlUrlByHandle[$handleKey] ?? null;
    }

    /**
     * @return array<int, mixed>
     */
    private function trackedCurlUrlsForMultiHandle(mixed $multiHandle): array
    {
        $multiHandleKey = $this->curlHandleKey($multiHandle);
        if ($multiHandleKey === null) {
            return array();
        }

        $result = array();
        $handleKeys = $this->curlHandleKeysByMultiHandle[$multiHandleKey] ?? array();
        foreach ($handleKeys as $handleKey) {
            if (array_key_exists($handleKey, $this->curlUrlByHandle)) {
                $result[] = $this->curlUrlByHandle[$handleKey];
            }
        }

        return $result;
    }

    private function curlHandleKey(mixed $handle): ?string
    {
        if (is_object($handle)) {
            return 'o:' . (string) spl_object_id($handle);
        }

        if (is_resource($handle)) {
            return 'r:' . (string) get_resource_id($handle);
        }

        return null;
    }

    private function isCurlUrlOption(mixed $option): bool
    {
        $curloptUrl = defined('CURLOPT_URL') ? (int) constant('CURLOPT_URL') : 10002;
        if (is_int($option)) {
            return $option === $curloptUrl;
        }

        if (is_string($option)) {
            return $option === 'CURLOPT_URL' || $option === (string) $curloptUrl;
        }

        return false;
    }
}
