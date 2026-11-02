import { describe, expect, it } from 'vitest';
import { resolveCandidateTriggerCommand } from '../../src/plugins/triggerResolver.js';
import { redactTranscriptEntries } from '../../src/transcript/redaction.js';

describe('plugin interfaces', () => {
  it('uses trigger resolver plugin override when provided', () => {
    const command = resolveCandidateTriggerCommand(
      'curl ${candidateId}',
      {
        candidateId: 'cand-1',
        sinkCategory: 'rce',
        metadata: {},
      },
      [
        {
          name: 'override',
          resolve() {
            return "echo 'plugin-command'";
          },
        },
      ]
    );

    expect(command).toBe("echo 'plugin-command'");
  });

  it('uses transcript redaction plugin to sanitize custom keys', () => {
    const redacted = redactTranscriptEntries(
      [
        {
          timestamp: new Date().toISOString(),
          direction: 'in',
          type: 'response',
          payload: {
            custom_secret: 'abc123',
          },
        },
      ],
      {
        plugins: [
          {
            name: 'custom-secret-redactor',
            redact(context) {
              if (context.key === 'custom_secret') {
                return { handled: true, value: '[PLUGIN_REDACTED]' };
              }
              return undefined;
            },
          },
        ],
      }
    );

    expect((redacted[0]?.payload as { custom_secret: string }).custom_secret).toBe(
      '[PLUGIN_REDACTED]'
    );
  });
});
