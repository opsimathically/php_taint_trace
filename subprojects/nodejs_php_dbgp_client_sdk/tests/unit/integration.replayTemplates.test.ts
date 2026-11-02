import { describe, expect, it } from 'vitest';
import {
  getDebugReplayTemplateByName,
  getDebugReplayTemplateForCategory,
  resolveDebugReplayTemplate,
} from '../../src/integration/replayTemplates.js';

describe('debug replay templates', () => {
  it('resolves templates by name and category', () => {
    const byName = getDebugReplayTemplateByName('rce');
    const byCategory = getDebugReplayTemplateForCategory('sql_injection');
    const fallback = getDebugReplayTemplateForCategory('unknown');

    expect(byName.name).toBe('rce');
    expect(byCategory.name).toBe('sqli');
    expect(fallback.name).toBe('default');
  });

  it('builds resolved template replay plan with deterministic checks and overrides', () => {
    const resolved = resolveDebugReplayTemplate(
      {
        sinkCategory: 'ssrf',
      },
      {
        mutationTarget: '$targetUrl',
        payloads: ['http://a.test', 'http://b.test'],
        resetValue: 'http://safe.test',
        comparePhase: 'post',
      }
    );

    expect(resolved.template.name).toBe('ssrf');
    expect(resolved.template.mutationTarget).toBe('$targetUrl');
    expect(resolved.replayPlan.variations).toHaveLength(2);
    expect(resolved.replayPlan.variations[0]?.mutations?.[0]?.propertyName).toBe('$targetUrl');
    expect(resolved.replayPlan.variations[0]?.resetMutations?.[0]?.value).toBe('http://safe.test');
    expect(resolved.replayPlan.deterministicChecks?.enabled).toBe(true);
    expect(resolved.replayPlan.deterministicChecks?.comparePhase).toBe('post');
    expect(resolved.evaluateExpressions.length).toBeGreaterThan(0);
  });

  it('derives mutation target from trigger request uri and metadata hints', () => {
    const requestDerived = resolveDebugReplayTemplate({
      sinkCategory: 'file',
      sinkName: 'include',
      requestUri: '/index.php?page=home&lang=en',
    });
    expect(requestDerived.template.mutationTarget).toBe('$_GET["page"]');
    expect(requestDerived.replayPlan.variations[0]?.mutations?.[0]?.propertyName).toBe(
      '$_GET["page"]'
    );

    const metadataDerived = resolveDebugReplayTemplate({
      sinkCategory: 'ssrf',
      metadata: {
        targetParam: 'callback',
        replayPayloads: ['http://127.0.0.1:9999/a', 'http://127.0.0.1:9999/b'],
        replayResetValue: 'http://127.0.0.1:9999/reset',
      },
    });
    expect(metadataDerived.template.mutationTarget).toBe('$_GET["callback"]');
    expect(metadataDerived.template.payloads).toEqual([
      'http://127.0.0.1:9999/a',
      'http://127.0.0.1:9999/b',
    ]);
    expect(metadataDerived.replayPlan.variations[0]?.resetMutations?.[0]?.value).toBe(
      'http://127.0.0.1:9999/reset'
    );
  });

  it('resolves php_taint_trace-style nested replay plan metadata', () => {
    const resolved = resolveDebugReplayTemplate({
      sinkCategory: 'rce',
      metadata: {
        candidate_snapshot: {
          replay_plan: {
            target_query_param: 'cmd',
            target_param_location: 'body',
          },
          request_evidence: {
            request_uri: '/index.php?cmd=id&mode=exec',
            request_method: 'POST',
          },
        },
      },
    });

    expect(resolved.template.mutationTarget).toBe('$_POST["cmd"]');
    expect(resolved.replayPlan.variations[0]?.mutations?.[0]?.propertyName).toBe('$_POST["cmd"]');
  });

  it('uses sink argument roles and nested request evidence when target param is implicit', () => {
    const resolved = resolveDebugReplayTemplate({
      metadata: {
        candidate_snapshot: {
          sink_category: 'idor',
          sink_name: 'printf',
          sink_evidence: {
            argument_roles: {
              0: 'resource_id',
              1: 'secondary',
            },
          },
          request_evidence: {
            request_uri: '/index.php?actor_id=100&resource_id=200',
          },
        },
      },
    });

    expect(resolved.template.name).toBe('idor');
    expect(resolved.template.mutationTarget).toBe('$_GET["resource_id"]');
  });
});
