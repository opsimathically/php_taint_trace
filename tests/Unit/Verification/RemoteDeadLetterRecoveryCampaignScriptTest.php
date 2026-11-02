<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class RemoteDeadLetterRecoveryCampaignScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-remote-dead-letter-campaign';
    }

    public function testCampaignConvergesWhenSelectedRowsDropToZero(): void
    {
        $stubScript = $this->createStubRecoveryScript();
        $stateFile = $this->tmpRoot . '/state_converge.txt';
        file_put_contents($stateFile, '0');
        $dummyConfig = $this->tmpRoot . '/config.json';
        file_put_contents($dummyConfig, '{}');

        $result = $this->runScript(
            array(
                'bash',
                'scripts/run_remote_dead_letter_recovery_campaign.sh',
                '--config', $dummyConfig,
                '--host-label', 'dummy',
                '--remote-root', '/tmp/remote',
                '--max-rounds', '4',
                '--max-stall-rounds', '1',
            ),
            array(
                'PHP_TAINT_TRACE_REMOTE_DEAD_LETTER_RECOVERY_CYCLE_SCRIPT' => $stubScript,
                'FAKE_CAMPAIGN_SCENARIO' => 'converge',
                'FAKE_CAMPAIGN_STATE_FILE' => $stateFile,
            )
        );

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertStringContainsString('converged: no matching dead letters remain', $result['stdout']);
        self::assertStringContainsString('completed successfully', $result['stdout']);
    }

    public function testCampaignFailsWhenStallBudgetIsExceeded(): void
    {
        $stubScript = $this->createStubRecoveryScript();
        $stateFile = $this->tmpRoot . '/state_stall.txt';
        file_put_contents($stateFile, '0');
        $dummyConfig = $this->tmpRoot . '/config.json';
        file_put_contents($dummyConfig, '{}');

        $result = $this->runScript(
            array(
                'bash',
                'scripts/run_remote_dead_letter_recovery_campaign.sh',
                '--config', $dummyConfig,
                '--host-label', 'dummy',
                '--remote-root', '/tmp/remote',
                '--max-rounds', '4',
                '--max-stall-rounds', '1',
            ),
            array(
                'PHP_TAINT_TRACE_REMOTE_DEAD_LETTER_RECOVERY_CYCLE_SCRIPT' => $stubScript,
                'FAKE_CAMPAIGN_SCENARIO' => 'stall',
                'FAKE_CAMPAIGN_STATE_FILE' => $stateFile,
            )
        );

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('stalled: selected_rows did not improve', $result['stderr']);
    }

    private function createStubRecoveryScript(): string
    {
        $path = $this->tmpRoot . '/fake_remote_dead_letter_recovery_cycle.sh';
        $script = <<<'BASH'
#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="${FAKE_CAMPAIGN_STATE_FILE:?missing FAKE_CAMPAIGN_STATE_FILE}"
SCENARIO="${FAKE_CAMPAIGN_SCENARIO:-converge}"

is_summary=0
for arg in "$@"; do
  if [[ "${arg}" == "--summary-only" ]]; then
    is_summary=1
    break
  fi
done

if [[ ! -f "${STATE_FILE}" ]]; then
  echo "0" > "${STATE_FILE}"
fi

if [[ "${is_summary}" -eq 1 ]]; then
  count="$(cat "${STATE_FILE}")"
  count=$((count + 1))
  echo "${count}" > "${STATE_FILE}"

  if [[ "${SCENARIO}" == "stall" ]]; then
    selected_rows=2
    dead_letter_total=2
  else
    if [[ "${count}" -eq 1 ]]; then
      selected_rows=3
      dead_letter_total=3
    elif [[ "${count}" -eq 2 ]]; then
      selected_rows=1
      dead_letter_total=2
    else
      selected_rows=0
      dead_letter_total=0
    fi
  fi

  cat <<JSON
{
  "selected_rows": ${selected_rows},
  "dead_letter_total": ${dead_letter_total}
}
JSON
  exit 0
fi

echo '{"mode":"requeue","enqueued_rows":1}'
BASH;
        file_put_contents($path, $script);
        chmod($path, 0775);
        return $path;
    }
}
