<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Verification\Model\DetectorCandidate;

final class BaselineRuntime
{
    private ?BaselineRuntimeBootstrapReport $bootstrapReport = null;
    private readonly RequestTaintSeeder $requestTaintSeeder;
    private readonly FilterRuntimeSlice $filterSlice;
    private readonly FileRuntimeSlice $fileSlice;
    private readonly RceRuntimeSlice $rceSlice;
    private readonly SqliRuntimeSlice $sqliSlice;
    private readonly SsrfRuntimeSlice $ssrfSlice;
    private readonly XssRuntimeSlice $xssSlice;
    private readonly XxeRuntimeSlice $xxeSlice;
    private readonly ?OpcodeRuntimeSlice $opcodeSlice;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        private readonly bool $enableOpcodeSlice = true,
        private readonly string $opcodeHookProfile = OpcodeRuntimeSlice::HOOK_PROFILE_FULL,
        private readonly bool $emitCandidates = false
    ) {
        $this->requestTaintSeeder = new RequestTaintSeeder($backend);
        $this->filterSlice = new FilterRuntimeSlice($backend);
        $this->fileSlice = new FileRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->rceSlice = new RceRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->sqliSlice = new SqliRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->ssrfSlice = new SsrfRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->xssSlice = new XssRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->xxeSlice = new XxeRuntimeSlice($backend, emitCandidates: $this->emitCandidates);
        $this->opcodeSlice = $this->enableOpcodeSlice
            ? new OpcodeRuntimeSlice(
                $backend,
                emitCandidates: $this->emitCandidates,
                hookProfile: $this->opcodeHookProfile
            )
            : null;
    }

    public function bootstrap(): BaselineRuntimeBootstrapReport
    {
        if ($this->bootstrapReport !== null) {
            return $this->bootstrapReport;
        }

        $report = new BaselineRuntimeBootstrapReport();

        // Mirrors legacy bootstrap ordering: sinks -> filters -> opcode.
        foreach ($this->sinkSlicesByName() as $name => $slice) {
            $report->addSliceReport($name, $slice->bootstrap());
        }
        $report->addSliceReport('filter', $this->filterSlice->bootstrap());
        if ($this->opcodeSlice !== null) {
            $report->addSliceReport('opcode', $this->opcodeSlice->bootstrap());
        }

        $this->bootstrapReport = $report;
        return $this->bootstrapReport;
    }

    public function hasBootstrapped(): bool
    {
        return $this->bootstrapReport !== null;
    }

    /**
     * @param array<string, mixed> $get
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     * @param array<string, mixed> $files
     * @param array<string, mixed> $request
     * @param array<string, mixed> $server
     */
    public function startRequest(
        array &$get,
        array &$post,
        array &$cookie,
        array &$files,
        array &$request,
        array &$server
    ): BaselineRuntimeRequestReport {
        $bootstrappedNow = !$this->hasBootstrapped();
        $bootstrapReport = $this->bootstrap();
        $this->clearFindings();
        $this->clearCandidates();
        $seededSources = $this->requestTaintSeeder->seedSuperglobals(
            $get,
            $post,
            $cookie,
            $files,
            $request,
            $server
        );

        return new BaselineRuntimeRequestReport(
            $bootstrapReport,
            $seededSources,
            $bootstrappedNow
        );
    }

    public function requestTaintSeeder(): RequestTaintSeeder
    {
        return $this->requestTaintSeeder;
    }

    /**
     * @return Finding[]
     */
    public function findings(): array
    {
        $findings = array();
        foreach ($this->sinkSlices() as $slice) {
            $findings = array_merge($findings, $slice->findings());
        }

        if ($this->opcodeSlice !== null) {
            $findings = array_merge($findings, $this->opcodeSlice->findings());
        }

        return $findings;
    }

    public function clearFindings(): void
    {
        foreach ($this->sinkSlices() as $slice) {
            $slice->clearFindings();
        }
        if ($this->opcodeSlice !== null) {
            $this->opcodeSlice->clearFindings();
        }
    }

    /**
     * @return DetectorCandidate[]
     */
    public function candidates(): array
    {
        $candidates = array();
        foreach ($this->sinkSlices() as $slice) {
            $candidates = array_merge($candidates, $slice->candidates());
        }

        if ($this->opcodeSlice !== null) {
            $candidates = array_merge($candidates, $this->opcodeSlice->candidates());
        }

        return $candidates;
    }

    public function clearCandidates(): void
    {
        foreach ($this->sinkSlices() as $slice) {
            $slice->clearCandidates();
        }
        if ($this->opcodeSlice !== null) {
            $this->opcodeSlice->clearCandidates();
        }
    }

    /**
     * @return array<string, RceRuntimeSlice|SqliRuntimeSlice|SsrfRuntimeSlice|FileRuntimeSlice|XssRuntimeSlice|XxeRuntimeSlice>
     */
    private function sinkSlicesByName(): array
    {
        return array(
            'file' => $this->fileSlice,
            'rce' => $this->rceSlice,
            'sqli' => $this->sqliSlice,
            'ssrf' => $this->ssrfSlice,
            'xss' => $this->xssSlice,
            'xxe' => $this->xxeSlice,
        );
    }

    /**
     * @return array<int, RceRuntimeSlice|SqliRuntimeSlice|SsrfRuntimeSlice|FileRuntimeSlice|XssRuntimeSlice|XxeRuntimeSlice>
     */
    private function sinkSlices(): array
    {
        return array_values($this->sinkSlicesByName());
    }
}
