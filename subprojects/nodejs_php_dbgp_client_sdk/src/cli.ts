#!/usr/bin/env node
import { Command } from 'commander';
import { exec as execCallback } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { promisify } from 'node:util';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import {
  DbgpServer,
  DebugEventOrchestrator,
  DebugIntegrationService,
  PhpDebugInspector,
  ReplayController,
  TranscriptArtifactStore,
  CandidateVerificationBridge,
  type BreakpointSetOptions,
  type CandidateRecord,
  type CandidateBridgeRunResult,
  type ReplayPlan,
  type ReplayResult,
  type TraceStepAction,
  type DbgpSession,
  type DbgpServerOptions,
  type TranscriptRedactionPlugin,
  type CandidateTriggerResolverPlugin,
  shellEscape,
} from './index.js';
import { getCaptureProfileByName } from './profiles/packs.js';
import { getPolicyPackByName } from './policies/packs.js';
import { resolveCandidateTriggerCommand } from './plugins/triggerResolver.js';
import { buildExpandedReplayPlan, validateReplayPlan } from './replay/matrix.js';
import { summarizeReplayDiffs } from './replay/diff.js';
import { buildReplayStabilityReport } from './replay/stability.js';
import {
  createReplayArtifactManifest,
  verifyReplayArtifactManifest,
  type ReplayArtifactManifest,
} from './replay/manifest.js';
import {
  getReplayGateProfileByName,
  getReplayGateProfileForCategory,
} from './replay/gateProfiles.js';
import { validateJsonSchema, type JsonSchemaDocument } from './schema/validator.js';

type OutputMode = 'human' | 'json';

interface CommonCliOptions {
  host: string;
  port: number;
  timeoutMs: number;
  output: OutputMode;
  strict: boolean;
}

interface CliConfigFile {
  host?: string;
  port?: number;
  timeoutMs?: number;
  output?: OutputMode;
  strict?: boolean;
}

const exec = promisify(execCallback);
const schemaCache = new Map<string, JsonSchemaDocument>();

interface ReplayArtifactOutput {
  kind: string;
  path: string;
}

const program = new Command();
program
  .name('php-dbgp-sdk')
  .description('Xdebug DBGp listener and inspector toolkit for Node.js.')
  .showHelpAfterError(true);

addCommonOptions(
  program
    .command('listen')
    .description('Start DBGp listener and print inbound session details.')
    .option('--interactive', 'Start an interactive debugger shell on first session.', false)
).action(async (options) => {
  const cliOptions = normalizeCommonOptions(options);
  const server = new DbgpServer(toServerOptions(cliOptions));
  await server.start();
  const address = server.getAddress();
  printOutput(cliOptions.output, {
    event: 'listening',
    host: address?.address ?? cliOptions.host,
    port: address?.port ?? cliOptions.port,
  });

  try {
    const session = await server.waitForNextSession(cliOptions.timeoutMs);
    const init = await session.waitForInit(cliOptions.timeoutMs);

    printOutput(cliOptions.output, {
      event: 'session_connected',
      sessionId: session.id,
      init,
    });

    if (options.interactive) {
      await runInteractiveShell(session, cliOptions);
    }
  } finally {
    await server.stop();
  }
});

addCommonOptions(
  program.command('snapshot').description('Capture a session snapshot once first session connects.')
).action(async (options) => {
  await runOneShot(options, async (inspector) => inspector.captureSnapshot());
});

addCommonOptions(program.command('stack').description('Fetch current stack frames.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.stackGet());
  }
);

addCommonOptions(program.command('contexts').description('Fetch context names.'))
  .option('-d, --depth <depth>', 'Stack depth.', '0')
  .action(async (options) => {
    await runOneShot(options, async (inspector) => inspector.contextNames(Number(options.depth)));
  });

addCommonOptions(program.command('context-get').description('Fetch properties for a context.'))
  .option('-c, --context-id <id>', 'Context id.', '0')
  .option('-d, --depth <depth>', 'Stack depth.', '0')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.contextGet(Number(options.contextId), Number(options.depth))
    );
  });

addCommonOptions(program.command('eval').description('Evaluate expression in current debug context.'))
  .requiredOption('-e, --expression <expr>', 'Expression to evaluate.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) => inspector.evaluate(options.expression));
  });

addCommonOptions(program.command('feature-get').description('Read debugger feature value.'))
  .requiredOption('-n, --name <name>', 'Feature name.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) => inspector.featureGet(options.name));
  });

addCommonOptions(program.command('feature-set').description('Set debugger feature value.'))
  .requiredOption('-n, --name <name>', 'Feature name.')
  .requiredOption('-v, --value <value>', 'Feature value.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.featureSet(options.name, coerceScalar(options.value))
    );
  });

addCommonOptions(program.command('source').description('Read source from target file path in debugger.'))
  .option('-f, --file-uri <uri>', 'file:// URI.')
  .option('-b, --begin-line <line>', 'First line.')
  .option('-e, --end-line <line>', 'Last line.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.source({
        fileUri: options.fileUri,
        beginLine: options.beginLine ? Number(options.beginLine) : undefined,
        endLine: options.endLine ? Number(options.endLine) : undefined,
      })
    );
  });

addCommonOptions(program.command('property-get').description('Fetch one property by full name.'))
  .requiredOption('-n, --name <name>', 'Property full name.')
  .option('-c, --context-id <id>', 'Context id.', '0')
  .option('-d, --depth <depth>', 'Stack depth.', '0')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.propertyGet(options.name, Number(options.contextId), Number(options.depth))
    );
  });

addCommonOptions(program.command('property-value').description('Fetch property value only.'))
  .requiredOption('-n, --name <name>', 'Property full name.')
  .option('-c, --context-id <id>', 'Context id.', '0')
  .option('-d, --depth <depth>', 'Stack depth.', '0')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.propertyValue(options.name, Number(options.contextId), Number(options.depth))
    );
  });

addCommonOptions(program.command('property-set').description('Set property value in current frame.'))
  .requiredOption('-n, --name <name>', 'Property full name.')
  .requiredOption('-v, --value <value>', 'New value.')
  .option('-c, --context-id <id>', 'Context id.', '0')
  .option('-d, --depth <depth>', 'Stack depth.', '0')
  .option('-t, --type <type>', 'Property type hint.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.propertySet(options.name, options.value, {
        contextId: Number(options.contextId),
        stackDepth: Number(options.depth),
        type: options.type,
      })
    );
  });

addCommonOptions(program.command('run').description('Continue execution from break state.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.run());
  }
);

addCommonOptions(program.command('step-into').description('Step into next statement.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.stepInto());
  }
);

addCommonOptions(program.command('step-over').description('Step over next statement.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.stepOver());
  }
);

addCommonOptions(program.command('step-out').description('Step out of current function.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.stepOut());
  }
);

addCommonOptions(program.command('breakpoint-set').description('Set breakpoint on first session.'))
  .option('-t, --type <type>', 'Breakpoint type.', 'line')
  .option('-f, --file-uri <uri>', 'file:// URI for line breakpoint.')
  .option('-n, --line <line>', 'Line number.')
  .option('-x, --expression <expr>', 'Conditional expression for breakpoint.')
  .option('--function-name <name>', 'Function name for call/return breakpoints.')
  .option('--exception <name>', 'Exception name for exception breakpoints.')
  .option('--temporary', 'Temporary breakpoint.', false)
  .option('--disabled', 'Create disabled breakpoint.', false)
  .action(async (options) => {
    const breakpoint: BreakpointSetOptions = {
      type: options.type,
      fileUri: options.fileUri,
      line: options.line ? Number(options.line) : undefined,
      expression: options.expression,
      functionName: options.functionName,
      exception: options.exception,
      temporary: options.temporary,
      disabled: options.disabled,
    };

    await runOneShot(options, async (inspector) => inspector.breakpointSet(breakpoint));
  });

addCommonOptions(
  program.command('breakpoint-clear').description('Remove breakpoint by debugger breakpoint id.')
)
  .requiredOption('-i, --id <id>', 'Breakpoint id.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) => inspector.breakpointRemove(options.id));
  });

addCommonOptions(program.command('breakpoint-get').description('Get a breakpoint definition.'))
  .requiredOption('-i, --id <id>', 'Breakpoint id.')
  .action(async (options) => {
    await runOneShot(options, async (inspector) => inspector.breakpointGet(options.id));
  });

addCommonOptions(program.command('breakpoint-list').description('List active breakpoints.')).action(
  async (options) => {
    await runOneShot(options, async (inspector) => inspector.breakpointList());
  }
);

addCommonOptions(program.command('breakpoint-update').description('Update a breakpoint.'))
  .requiredOption('-i, --id <id>', 'Breakpoint id.')
  .option('--state <state>', 'enabled|disabled')
  .option('-n, --line <line>', 'Updated line.')
  .option('-h, --hit-value <value>', 'Updated hit value.')
  .option('-o, --hit-condition <op>', '>=|==|%')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.breakpointUpdate({
        id: options.id,
        state: options.state,
        line: options.line ? Number(options.line) : undefined,
        hitValue: options.hitValue ? Number(options.hitValue) : undefined,
        hitCondition: options.hitCondition,
      })
    );
  });

addCommonOptions(program.command('stdout-mode').description('Configure DBGp stdout forwarding mode.'))
  .requiredOption('-m, --mode <mode>', '0 disable, 1 copy, 2 redirect')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.setStdIo('stdout', normalizeStdIoMode(options.mode))
    );
  });

addCommonOptions(program.command('stderr-mode').description('Configure DBGp stderr forwarding mode.'))
  .requiredOption('-m, --mode <mode>', '0 disable, 1 copy, 2 redirect')
  .action(async (options) => {
    await runOneShot(options, async (inspector) =>
      inspector.setStdIo('stderr', normalizeStdIoMode(options.mode))
    );
  });

addCommonOptions(program.command('trace-exec').description('Trace execution step-by-step with watch expressions.'))
  .requiredOption('-s, --steps <count>', 'Number of steps to execute.')
  .option(
    '-a, --action <action>',
    'Trace action: run|step_into|step_over|step_out',
    'step_over'
  )
  .option(
    '--prime-action <action>',
    'Action to enter a break state when status=starting: run|step_into|step_over|step_out',
    'step_into'
  )
  .option('-w, --watch <expr>', 'Expression to evaluate each step.', collectString, [])
  .option('--capture-snapshots', 'Capture full snapshot each step.', false)
  .option(
    '--snapshot-contexts <list>',
    'Comma-separated context ids used when capture-snapshots is enabled.'
  )
  .action(async (options) => {
    await runOneShot(options, async (inspector) => {
      const status = await inspector.status();
      if (status.status === 'starting') {
        await runStepAction(inspector, normalizeTraceAction(options.primeAction));
      }

      return inspector.traceExecution({
        steps: Number(options.steps),
        action: normalizeTraceAction(options.action),
        watchExpressions: (options.watch as string[]) ?? [],
        captureSnapshots: options.captureSnapshots,
        snapshotContextIds: parseContextList(options.snapshotContexts),
      });
    });
  });

addCommonOptions(
  program.command('transcript-save').description('Capture and persist transcript artifact for one session.')
)
  .requiredOption('-p, --artifact-path <path>', 'Output JSON path for transcript artifact.')
  .option('--redact', 'Apply redaction rules before writing artifact.', true)
  .option(
    '--redaction-plugin <path>',
    'Path/module for transcript redaction plugin (repeatable).',
    collectString,
    []
  )
  .option('--prime-action <action>', 'run|step_into|step_over|step_out', 'step_into')
  .option('--include-snapshot', 'Capture one snapshot before persisting transcript.', false)
  .action(async (options) => {
    const redactionPlugins = await loadTranscriptRedactionPlugins(
      (options.redactionPlugin as string[]) ?? []
    );
    await runOneShot(options, async (inspector, session) => {
      const status = await inspector.status();
      if (status.status === 'starting') {
        await runStepAction(inspector, normalizeTraceAction(options.primeAction));
      }
      if (options.includeSnapshot) {
        await inspector.captureSnapshot([0]);
      }

      const store = new TranscriptArtifactStore();
      const resolved = path.resolve(options.artifactPath);
      const persistedPath = await store.persistSession(session, resolved, {
        redaction: options.redact ? { plugins: redactionPlugins } : undefined,
      });
      return { artifactPath: persistedPath, sessionId: session.id };
    });
  });

addCommonOptions(
  program
    .command('watch-breaks')
    .description('Listen for break/exception events and optional conditional auto-capture.')
)
  .option('--max-events <count>', 'Stop after this many break events.', '1')
  .option('--auto-capture-exceptions', 'Capture snapshot/watch data automatically on exceptions.', true)
  .option('--policy-pack <name>', 'Policy pack name for default watch/snapshot behavior.', 'default')
  .option('--capture-profile <name>', 'Capture profile name for default watch/snapshot behavior.', 'default')
  .option('-w, --watch <expr>', 'Expression evaluated during auto-capture.', collectString, [])
  .option('--snapshot-contexts <list>', 'Comma-separated context ids for auto-capture snapshots.')
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const server = new DbgpServer(toServerOptions(common));
    await server.start();

    try {
      const session = await server.waitForNextSession(common.timeoutMs);
      await session.waitForInit(common.timeoutMs);
      const inspector = new PhpDebugInspector(session, {
        commandTimeoutMs: common.timeoutMs,
        strict: common.strict,
      });
      const orchestrator = new DebugEventOrchestrator(session, inspector);
      const policy = getPolicyPackByName(options.policyPack);
      const profile = getCaptureProfileByName(options.captureProfile);
      const maxEvents = Number(options.maxEvents);
      const events: unknown[] = [];
      const captures: unknown[] = [];
      let resolveDone: (() => void) | undefined;
      const done = new Promise<void>((resolve) => {
        resolveDone = resolve;
      });
      const timeout = setTimeout(() => resolveDone?.(), common.timeoutMs);

      orchestrator.onBreak((event) => {
        events.push(event);
        if (events.length >= maxEvents) {
          resolveDone?.();
        }
      });

      if (options.autoCaptureExceptions) {
        orchestrator.addAutoCaptureRule({
          id: 'exception_auto_capture',
          when: (event) => Boolean(event.exceptionName),
          snapshotContextIds:
            parseContextList(options.snapshotContexts) ??
            (profile.snapshotContextIds.length > 0
              ? profile.snapshotContextIds
              : policy.snapshotContextIds),
          watchExpressions:
            ((options.watch as string[]) ?? []).length > 0
              ? ((options.watch as string[]) ?? [])
              : (profile.watchExpressions.length > 0
                ? profile.watchExpressions
                : policy.watchExpressions),
        });
        orchestrator.onAutoCapture((record) => {
          captures.push(record);
        });
      }

      orchestrator.start();
      await done;
      clearTimeout(timeout);
      await orchestrator.flush();
      orchestrator.stop();

      printOutput(common.output, {
        ok: true,
        sessionId: session.id,
        breakEvents: events,
        autoCaptures: captures,
      });
    } finally {
      await server.stop();
    }
  });

addCommonOptions(
  program
    .command('replay')
    .description(
      'Run replay plan across multiple fresh sessions with optional trigger command per variation.'
    )
)
  .requiredOption('--plan <path>', 'Replay plan JSON file.')
  .option('--rounds <count>', 'Number of repeated replay rounds for stability scoring.', '1')
  .option('--output-results <path>', 'Write replay run results JSON to this path.')
  .option('--output-stability <path>', 'Write replay stability report JSON to this path.')
  .option(
    '--trigger-cmd <cmd>',
    'Shell command executed per variation. Supports ${variationId} and ${round} placeholders.'
  )
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const server = new DbgpServer(toServerOptions(common));
    const replayPlan = loadReplayPlan(options.plan);
    const validationErrors = validateReplayPlan(replayPlan);
    if (validationErrors.length > 0) {
      throw new Error(`Replay plan validation failed: ${validationErrors.join(' | ')}`);
    }
    const rounds = Math.max(1, Number(options.rounds ?? 1));
    const controller = new ReplayController(server, common);
    await server.start();

    try {
      const roundResults: Array<{
        round: number;
        results: Awaited<ReturnType<ReplayController['run']>>;
      }> = [];
      const flattened: Awaited<ReturnType<ReplayController['run']>> = [];

      for (let round = 1; round <= rounds; round += 1) {
        const results = await controller.run(replayPlan, async (variation) => {
          if (typeof options.triggerCmd !== 'string' || options.triggerCmd.trim() === '') {
            return;
          }

          const command = options.triggerCmd
            .replaceAll('${variationId}', variation.id)
            .replaceAll('${round}', String(round));
          await exec(command);
        });
        roundResults.push({ round, results });
        flattened.push(...results);
      }

      const stabilityReport = buildReplayStabilityReport(
        roundResults.map((item) => ({
          round: item.round,
          results: item.results.map((entry) => entry.result),
        }))
      );

      const payload = {
        ok: true,
        rounds,
        totalRuns: flattened.length,
        stabilityReport,
        data: flattened,
        roundResults,
      };
      assertSchemaOrThrow('replay-results.schema.json', payload, 'Replay results artifact');

      const stabilityPayload = {
        ok: true,
        minOverall: 0,
        minVariation: 0,
        thresholdsPassed: true,
        failingVariations: [] as Array<{ variationId: string; stabilityScore: number }>,
        report: stabilityReport,
      };
      assertSchemaOrThrow('replay-stability.schema.json', stabilityPayload, 'Replay stability artifact');

      if (options.outputResults) {
        writeFileSync(path.resolve(options.outputResults), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
      }
      if (options.outputStability) {
        writeFileSync(
          path.resolve(options.outputStability),
          `${JSON.stringify(stabilityPayload, null, 2)}\n`,
          'utf8'
        );
      }

      printOutput(common.output, payload);
    } finally {
      await server.stop();
    }
  });

addCommonOptions(
  program
    .command('replay-matrix')
    .description('Validate and expand replay plan matrix combinations.')
)
  .requiredOption('--plan <path>', 'Replay plan JSON file.')
  .option('--output-plan <path>', 'Write expanded replay plan JSON to this path.')
  .option('--validate-only', 'Only validate matrix/variation contract.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const replayPlan = loadReplayPlan(options.plan);
    const validationErrors = validateReplayPlan(replayPlan);
    if (validationErrors.length > 0) {
      throw new Error(`Replay plan validation failed: ${validationErrors.join(' | ')}`);
    }

    const expanded = buildExpandedReplayPlan(replayPlan);
    if (options.outputPlan && !options.validateOnly) {
      writeFileSync(path.resolve(options.outputPlan), `${JSON.stringify(expanded, null, 2)}\n`, 'utf8');
    }

    printOutput(common.output, {
      ok: true,
      validateOnly: Boolean(options.validateOnly),
      originalVariationCount: replayPlan.variations.length,
      expandedVariationCount: expanded.variations.length,
      expandedVariationIds: expanded.variations.map((variation) => variation.id),
      outputPlanPath: options.outputPlan ? path.resolve(options.outputPlan) : undefined,
    });
  });

addCommonOptions(
  program
    .command('replay-diff')
    .description('Compute structured replay drift diffs from saved replay results JSON.')
)
  .requiredOption('--results <path>', 'Replay results JSON path produced by replay command.')
  .option('--compare-phase <phase>', 'pre|post|post_reset')
  .option('--gate-profile <name>', 'Replay gate profile name.')
  .option('--sink-category <value>', 'Sink category.')
  .option('--output-diff <path>', 'Write replay diff report JSON to this path.')
  .option('--manifest-path <path>', 'Write replay artifact manifest JSON for emitted output files.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--fail-on-violations', 'Exit non-zero when drift violations are detected.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const gateProfile = resolveReplayGateProfile(options);
    const comparePhase = normalizeComparePhase(
      toOptionalString(options.comparePhase) ?? gateProfile.comparePhase
    );
    const artifact = loadReplayResultsArtifact(path.resolve(options.results));
    const summary = summarizeReplayDiffs(artifact.results, comparePhase);
    const payload: Record<string, unknown> = {
      ok: !options.failOnViolations || summary.driftDetected === 0,
      comparePhase,
      gateProfile: gateProfile.name,
      summary,
    };
    assertSchemaOrThrow('replay-diff.schema.json', payload, 'Replay diff artifact');

    const emittedArtifacts: ReplayArtifactOutput[] = [];
    if (options.outputDiff) {
      const outputPath = path.resolve(options.outputDiff);
      writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
      emittedArtifacts.push({ kind: 'replay_diff', path: outputPath });
    }

    const manifest = writeManifestIfRequested(options, emittedArtifacts);
    if (manifest) {
      payload.manifestPath = manifest.path;
    }

    printOutput(common.output, payload);
    if (options.failOnViolations && summary.driftDetected > 0) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('replay-stability')
    .description('Compute replay stability scores from saved replay results JSON.')
)
  .requiredOption('--results <path>', 'Replay results JSON path produced by replay command.')
  .option('--min-overall-score <value>', 'Minimum overall stability score (0.0-1.0).')
  .option('--min-variation-score <value>', 'Minimum per-variation stability score (0.0-1.0).')
  .option('--gate-profile <name>', 'Replay gate profile name.')
  .option('--sink-category <value>', 'Sink category.')
  .option('--output-report <path>', 'Write replay stability report JSON to this path.')
  .option('--manifest-path <path>', 'Write replay artifact manifest JSON for emitted output files.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--fail-below-thresholds', 'Exit non-zero when scores are below configured thresholds.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const gateProfile = resolveReplayGateProfile(options);
    const artifact = loadReplayResultsArtifact(path.resolve(options.results));
    const rounds = artifact.roundResults;
    const report = buildReplayStabilityReport(rounds);
    const minOverall = toOptionalNumber(options.minOverallScore) ?? gateProfile.minOverallScore;
    const minVariation = toOptionalNumber(options.minVariationScore) ?? gateProfile.minVariationScore;

    const failingVariations = report.variationScores
      .filter((entry) => entry.stabilityScore < minVariation)
      .map((entry) => ({
        variationId: entry.variationId,
        stabilityScore: entry.stabilityScore,
      }));

    const thresholdsPassed =
      report.overallStabilityScore >= minOverall && failingVariations.length === 0;

    const payload: Record<string, unknown> = {
      ok: !options.failBelowThresholds || thresholdsPassed,
      minOverall,
      minVariation,
      gateProfile: gateProfile.name,
      thresholdsPassed,
      failingVariations,
      report,
    };
    assertSchemaOrThrow('replay-stability.schema.json', payload, 'Replay stability artifact');

    const emittedArtifacts: ReplayArtifactOutput[] = [];
    if (options.outputReport) {
      const outputPath = path.resolve(options.outputReport);
      writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
      emittedArtifacts.push({ kind: 'replay_stability', path: outputPath });
    }

    const manifest = writeManifestIfRequested(options, emittedArtifacts);
    if (manifest) {
      payload.manifestPath = manifest.path;
    }

    printOutput(common.output, payload);
    if (options.failBelowThresholds && !thresholdsPassed) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('replay-gate')
    .description('Run combined replay diff + stability gate checks on a replay results artifact.')
)
  .requiredOption('--results <path>', 'Replay results JSON path produced by replay command.')
  .option('--compare-phase <phase>', 'pre|post|post_reset')
  .option('--max-drift-detected <count>', 'Maximum allowed diff drift detections.')
  .option('--min-overall-score <value>', 'Minimum overall stability score (0.0-1.0).')
  .option('--min-variation-score <value>', 'Minimum per-variation stability score (0.0-1.0).')
  .option('--gate-profile <name>', 'Replay gate profile name.')
  .option('--sink-category <value>', 'Sink category.')
  .option('--output-gate <path>', 'Write gate report JSON to this path.')
  .option('--manifest-path <path>', 'Write replay artifact manifest JSON for emitted output files.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--fail-on-gate', 'Exit non-zero when gate fails.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const gateProfile = resolveReplayGateProfile(options);
    const comparePhase = normalizeComparePhase(
      toOptionalString(options.comparePhase) ?? gateProfile.comparePhase
    );
    const artifact = loadReplayResultsArtifact(path.resolve(options.results));
    const diffSummary = summarizeReplayDiffs(artifact.results, comparePhase);
    const stabilityReport = buildReplayStabilityReport(artifact.roundResults);
    const maxDriftDetected = Math.max(
      0,
      toOptionalNumber(options.maxDriftDetected) ?? gateProfile.maxDriftDetected
    );
    const minOverall = toOptionalNumber(options.minOverallScore) ?? gateProfile.minOverallScore;
    const minVariation = toOptionalNumber(options.minVariationScore) ?? gateProfile.minVariationScore;

    const failingVariations = stabilityReport.variationScores
      .filter((entry) => entry.stabilityScore < minVariation)
      .map((entry) => ({
        variationId: entry.variationId,
        stabilityScore: entry.stabilityScore,
      }));
    const diffPassed = diffSummary.driftDetected <= maxDriftDetected;
    const stabilityPassed =
      stabilityReport.overallStabilityScore >= minOverall && failingVariations.length === 0;
    const gatePassed = diffPassed && stabilityPassed;

    const diffPayload = {
      ok: diffPassed,
      comparePhase,
      summary: diffSummary,
    };
    assertSchemaOrThrow('replay-diff.schema.json', diffPayload, 'Replay diff artifact');

    const stabilityPayload = {
      ok: stabilityPassed,
      minOverall,
      minVariation,
      thresholdsPassed: stabilityPassed,
      failingVariations,
      report: stabilityReport,
    };
    assertSchemaOrThrow('replay-stability.schema.json', stabilityPayload, 'Replay stability artifact');

    const payload: Record<string, unknown> = {
      ok: !options.failOnGate || gatePassed,
      gatePassed,
      gate: {
        gateProfile: gateProfile.name,
        diffPassed,
        stabilityPassed,
        comparePhase,
        maxDriftDetected,
        minOverall,
        minVariation,
      },
      diff: diffPayload,
      stability: stabilityPayload,
    };

    const emittedArtifacts: ReplayArtifactOutput[] = [];
    if (options.outputGate) {
      const outputPath = path.resolve(options.outputGate);
      writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
      emittedArtifacts.push({ kind: 'replay_gate', path: outputPath });
    }

    const manifest = writeManifestIfRequested(options, emittedArtifacts);
    if (manifest) {
      payload.manifestPath = manifest.path;
    }

    printOutput(common.output, payload);
    if (options.failOnGate && !gatePassed) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('replay-ci')
    .description('Run one-shot replay verification pipeline (results, diff, stability, gate).')
)
  .option('--plan <path>', 'Replay plan JSON file to execute live.')
  .option('--results <path>', 'Existing replay results JSON path (skip live replay execution).')
  .option('--rounds <count>', 'Number of rounds when --plan is used.', '1')
  .option(
    '--trigger-cmd <cmd>',
    'Shell command executed per variation when --plan is used. Supports ${variationId} and ${round}.'
  )
  .option('--compare-phase <phase>', 'pre|post|post_reset')
  .option('--max-drift-detected <count>', 'Maximum allowed diff drift detections.')
  .option('--min-overall-score <value>', 'Minimum overall stability score (0.0-1.0).')
  .option('--min-variation-score <value>', 'Minimum per-variation stability score (0.0-1.0).')
  .option('--gate-profile <name>', 'Replay gate profile name.')
  .option('--sink-category <value>', 'Sink category.')
  .option('--output-dir <path>', 'Directory where replay-ci artifacts are written.')
  .option('--manifest-path <path>', 'Write replay artifact manifest JSON for emitted output files.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--fail-on-gate', 'Exit non-zero when gate fails.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const run = await runReplayCiPipeline(common, options);
    printOutput(common.output, run.payload);
    if (options.failOnGate && !run.gatePassed) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('verifier-decision')
    .description(
      'Run bounded replay attempts and emit php_taint_trace-compatible verifier decision payload.'
    )
)
  .requiredOption('--candidate-id <value>', 'Candidate id.')
  .option('--sink-category <value>', 'Sink category used for replay template selection.', 'rce')
  .option('--sink-name <value>', 'Sink name.')
  .option('--request-uri <value>', 'Request URI for replay target inference.')
  .option('--correlation-id <value>', 'Correlation id.')
  .option('--request-id <value>', 'Request id.')
  .option('--finding-id <value>', 'Finding id.')
  .option('--trace-id <value>', 'Trace id.')
  .option('--attempts <count>', 'Maximum replay attempts.', '3')
  .option(
    '--no-stop-on-first-success',
    'Keep running attempts even after a successful replay confirmation.'
  )
  .option(
    '--no-require-replay-evidence',
    'Allow success when replay result list is empty (advanced use).'
  )
  .option(
    '--trigger-cmd <cmd>',
    'Shell command executed per attempt. Supports ${candidateId}, ${sinkCategory}, ${sinkName}, ${requestUri}, ${correlationId}, ${requestId}, ${findingId}, ${traceId}, ${attempt}, ${attemptIndex}.'
  )
  .option('--template-name <value>', 'Replay template name override.')
  .option('--template-category <value>', 'Replay template category override.')
  .option('--template-mutation-target <value>', 'Replay mutation target expression override.')
  .option('--template-target-param <value>', 'Target request param hint for replay target resolution.')
  .option('--template-payload <value>', 'Replay payload override (repeatable).', collectString, [])
  .option('--template-reset-value <value>', 'Replay reset payload override.')
  .option('--artifact-dir <path>', 'Output directory for replay-attempt artifacts.')
  .option('--manifest-path <path>', 'Optional artifact manifest output path.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign artifact manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--decision-output <path>', 'Write verifier decision JSON payload to this path.')
  .option('--decision-jsonl <path>', 'Append verifier decision JSON payload as JSONL line to this path.')
  .option('--fail-on-unconfirmed', 'Exit non-zero unless verifier outcome is confirmed.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const run = await runVerifierDecisionPipeline(common, options);
    printOutput(common.output, run.payload);
    if (options.failOnUnconfirmed && run.payload.ok !== true) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('verifier-decision-batch')
    .description(
      'Consume candidate JSONL and emit verifier decision JSONL per candidate.'
    )
)
  .requiredOption('--candidates-jsonl <path>', 'Candidate or envelope JSONL input path.')
  .requiredOption(
    '--trigger-cmd <cmd>',
    'Shell command executed per attempt/candidate. Supports ${candidateId}, ${sinkCategory}, ${sinkName}, ${requestUri}, ${correlationId}, ${requestId}, ${findingId}, ${traceId}, ${attempt}, ${attemptIndex}.'
  )
  .requiredOption('--decisions-jsonl <path>', 'Append verifier decisions JSONL to this path.')
  .option('--limit <count>', 'Maximum number of candidates to process.', '20')
  .option('--sink-category <value>', 'Fallback sink category when candidate category is absent.', 'rce')
  .option('--attempts <count>', 'Maximum replay attempts per candidate.', '3')
  .option(
    '--concurrency <count>',
    'Maximum candidates processed concurrently within a single DBGp batch listener.',
    '1'
  )
  .option(
    '--no-stop-on-first-success',
    'Keep running attempts even after a successful replay confirmation.'
  )
  .option(
    '--no-require-replay-evidence',
    'Allow success when replay result list is empty (advanced use).'
  )
  .option('--template-name <value>', 'Replay template name override.')
  .option('--template-category <value>', 'Replay template category override.')
  .option('--template-mutation-target <value>', 'Replay mutation target expression override.')
  .option('--template-target-param <value>', 'Target request param hint for replay target resolution.')
  .option('--template-payload <value>', 'Replay payload override (repeatable).', collectString, [])
  .option('--template-reset-value <value>', 'Replay reset payload override.')
  .option('--artifact-dir <path>', 'Per-candidate artifact root directory for replay-attempt evidence.')
  .option('--decision-dir <path>', 'Optional directory to write per-candidate decision JSON files.')
  .option('--truncate-decisions-jsonl', 'Truncate decisions JSONL output before writing.', false)
  .option('--stop-on-error', 'Stop processing when one candidate errors.', false)
  .option('--fail-on-unconfirmed', 'Exit non-zero unless every candidate outcome is confirmed.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const run = await runVerifierDecisionBatchPipeline(common, options);
    printOutput(common.output, run.payload);
    if (options.failOnUnconfirmed && run.payload.ok !== true) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('artifact-verify')
    .description('Verify replay artifact files against a replay manifest.')
)
  .requiredOption('--manifest <path>', 'Replay manifest JSON path.')
  .option('--base-dir <path>', 'Resolve relative manifest entries from this base directory.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret to validate signed manifest entries.')
  .option('--fail-on-invalid', 'Exit non-zero when verification fails.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const manifestPath = path.resolve(options.manifest);
    const manifest = loadReplayManifest(manifestPath);
    const baseDir = toOptionalString(options.baseDir) ?? path.dirname(manifestPath);
    const verification = verifyReplayArtifactManifest(manifest, {
      baseDir,
      hmacSecret: toOptionalString(options.manifestHmacSecret),
    });
    const payload = {
      ok: !options.failOnInvalid || verification.ok,
      manifestPath,
      baseDir: path.resolve(baseDir),
      schema: manifest.schema,
      checked: verification.checked,
      mismatches: verification.mismatches,
      signature: verification.signature,
    };
    printOutput(common.output, payload);
    if (options.failOnInvalid && !verification.ok) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('bridge-candidates')
    .description('Consume php_taint_trace candidates JSONL and run debugger evidence capture.')
)
  .requiredOption('--candidates-jsonl <path>', 'Path to candidate/envelope JSONL file.')
  .requiredOption(
    '--trigger-cmd <cmd>',
    'Shell command run per candidate. Supports ${candidateId}, ${sinkCategory}, ${sinkName}, ${requestUri}, ${correlationId}, ${requestId}, ${findingId}.'
  )
  .option('--artifacts-dir <path>', 'Output directory for transcript artifacts.', '.dbgp_bridge_artifacts')
  .option('--limit <n>', 'Maximum candidates to process.', '20')
  .option('--trace-steps <n>', 'Trace steps per candidate (0 = use policy default).', '0')
  .option('--policy-pack <name>', 'Policy pack name when category mapping is disabled.', 'default')
  .option('--disable-category-policy-pack', 'Disable auto policy by sink category.', false)
  .option('--capture-profile <name>', 'Capture profile name when category mapping is disabled.', 'default')
  .option('--disable-category-capture-profile', 'Disable auto capture profile by sink category.', false)
  .option(
    '--trigger-resolver-plugin <path>',
    'Path/module for trigger resolver plugin (repeatable).',
    collectString,
    []
  )
  .option(
    '--redaction-plugin <path>',
    'Path/module for transcript redaction plugin (repeatable).',
    collectString,
    []
  )
  .option('-w, --watch <expr>', 'Watch expression during trace.', collectString, [])
  .option('--snapshot-contexts <list>', 'Comma-separated context ids for snapshot capture.')
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const bridgeRun = await runBridgeCandidates(common, options);
    printOutput(common.output, {
      ok: true,
      processed: bridgeRun.processed,
      results: bridgeRun.results,
    });
  });

addCommonOptions(
  program
    .command('bridge-replay-ci')
    .description('Run candidate bridge capture, then replay-ci gating in one command.')
)
  .requiredOption('--candidates-jsonl <path>', 'Path to candidate/envelope JSONL file.')
  .requiredOption(
    '--trigger-cmd <cmd>',
    'Shell command run per candidate. Supports ${candidateId}, ${sinkCategory}, ${sinkName}, ${requestUri}, ${correlationId}, ${requestId}, ${findingId}.'
  )
  .option('--artifacts-dir <path>', 'Output directory for transcript artifacts.', '.dbgp_bridge_artifacts')
  .option('--limit <n>', 'Maximum candidates to process.', '20')
  .option('--trace-steps <n>', 'Trace steps per candidate (0 = use policy default).', '0')
  .option('--policy-pack <name>', 'Policy pack name when category mapping is disabled.', 'default')
  .option('--disable-category-policy-pack', 'Disable auto policy by sink category.', false)
  .option('--capture-profile <name>', 'Capture profile name when category mapping is disabled.', 'default')
  .option('--disable-category-capture-profile', 'Disable auto capture profile by sink category.', false)
  .option(
    '--trigger-resolver-plugin <path>',
    'Path/module for trigger resolver plugin (repeatable).',
    collectString,
    []
  )
  .option(
    '--redaction-plugin <path>',
    'Path/module for transcript redaction plugin (repeatable).',
    collectString,
    []
  )
  .option('-w, --watch <expr>', 'Watch expression during trace.', collectString, [])
  .option('--snapshot-contexts <list>', 'Comma-separated context ids for snapshot capture.')
  .option('--replay-plan <path>', 'Replay plan JSON file to execute live.')
  .option('--replay-results <path>', 'Existing replay results JSON path (skip live replay execution).')
  .option('--replay-rounds <count>', 'Number of rounds when --replay-plan is used.', '1')
  .option(
    '--replay-trigger-cmd <cmd>',
    'Shell command executed per replay variation when --replay-plan is used. Supports ${variationId} and ${round}.'
  )
  .option('--replay-compare-phase <phase>', 'pre|post|post_reset')
  .option('--replay-max-drift-detected <count>', 'Maximum allowed diff drift detections.')
  .option('--replay-min-overall-score <value>', 'Minimum overall stability score (0.0-1.0).')
  .option('--replay-min-variation-score <value>', 'Minimum per-variation stability score (0.0-1.0).')
  .option('--replay-gate-profile <name>', 'Replay gate profile name.')
  .option('--replay-sink-category <value>', 'Sink category for replay gate profile fallback.')
  .option('--replay-output-dir <path>', 'Directory where replay-ci artifacts are written.')
  .option('--manifest-path <path>', 'Write replay artifact manifest JSON for emitted output files.')
  .option('--manifest-hmac-secret <value>', 'Optional HMAC secret used to sign manifest output.')
  .option('--manifest-hmac-key-id <value>', 'Optional key id metadata written into manifest signature.')
  .option('--fail-on-gate', 'Exit non-zero when replay gate fails.', false)
  .action(async (options) => {
    const common = normalizeCommonOptions(options);
    const bridgeRun = await runBridgeCandidates(common, options);
    const replayOptions: Record<string, unknown> = {
      plan: options.replayPlan,
      results: options.replayResults,
      rounds: options.replayRounds,
      triggerCmd: options.replayTriggerCmd,
      comparePhase: options.replayComparePhase,
      maxDriftDetected: options.replayMaxDriftDetected,
      minOverallScore: options.replayMinOverallScore,
      minVariationScore: options.replayMinVariationScore,
      gateProfile: options.replayGateProfile,
      sinkCategory: options.replaySinkCategory,
      outputDir: options.replayOutputDir,
      manifestPath: options.manifestPath,
      manifestHmacSecret: options.manifestHmacSecret,
      manifestHmacKeyId: options.manifestHmacKeyId,
      failOnGate: options.failOnGate,
    };
    const replayRun = await runReplayCiPipeline(common, replayOptions);
    const payload = {
      ok: replayRun.payload.ok === true && replayRun.gatePassed,
      bridge: {
        processed: bridgeRun.processed,
        results: bridgeRun.results,
      },
      replayCi: replayRun.payload,
    };
    printOutput(common.output, payload);
    if (options.failOnGate && !replayRun.gatePassed) {
      process.exitCode = 1;
    }
  });

addCommonOptions(
  program
    .command('resolve-trigger')
    .description('Resolve trigger template with candidate placeholders (debug helper).')
)
  .requiredOption('--template <value>', 'Trigger template string.')
  .requiredOption('--candidate-id <value>', 'Candidate id.')
  .option('--sink-category <value>', 'Sink category.')
  .option('--sink-name <value>', 'Sink name.')
  .option('--request-uri <value>', 'Request URI.')
  .option('--correlation-id <value>', 'Correlation id.')
  .option('--request-id <value>', 'Request id.')
  .option('--finding-id <value>', 'Finding id.')
  .option(
    '--trigger-resolver-plugin <path>',
    'Path/module for trigger resolver plugin (repeatable).',
    collectString,
    []
  )
  .action(async (options) => {
    const plugins = await loadCandidateTriggerResolverPlugins(
      (options.triggerResolverPlugin as string[]) ?? []
    );
    const candidate: CandidateRecord = {
      candidateId: options.candidateId,
      sinkCategory: options.sinkCategory,
      sinkName: options.sinkName,
      requestUri: options.requestUri,
      correlationId: options.correlationId,
      requestId: options.requestId,
      findingId: options.findingId,
      metadata: {},
    };
    const command = resolveCandidateTriggerCommand(options.template, candidate, plugins);
    printOutput('human', { ok: true, command });
  });

program.parseAsync(process.argv).catch((error) => {
  printOutput('human', {
    ok: false,
    error: error instanceof Error ? error.message : String(error),
  });
  process.exitCode = 1;
});

function addCommonOptions(command: Command): Command {
  return command
    .option('--config <path>', 'Path to JSON config file with CLI defaults.')
    .option('--host <host>', 'Host to bind listener.', '127.0.0.1')
    .option('--port <port>', 'Port to bind listener.', '9003')
    .option('--timeout-ms <ms>', 'Timeout for inbound session and command response.', '30000')
    .option('--output <mode>', 'Output mode: human|json', 'human')
    .option('--strict', 'Strict protocol mode.', true);
}

function normalizeCommonOptions(options: Record<string, unknown>): CommonCliOptions {
  const config = loadConfig(options.config);
  const outputMode = normalizeOutputMode(options.output ?? config.output);
  return {
    host: String(options.host ?? config.host ?? '127.0.0.1'),
    port: Number(options.port ?? config.port ?? 9003),
    timeoutMs: Number(options.timeoutMs ?? config.timeoutMs ?? 30000),
    output: outputMode,
    strict: options.strict !== undefined ? options.strict !== false : (config.strict ?? true),
  };
}

function loadConfig(value: unknown): CliConfigFile {
  if (typeof value !== 'string' || value.trim() === '') {
    return {};
  }

  const raw = readFileSync(value, 'utf8');
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  return {
    host: typeof parsed.host === 'string' ? parsed.host : undefined,
    port: typeof parsed.port === 'number' ? parsed.port : undefined,
    timeoutMs: typeof parsed.timeoutMs === 'number' ? parsed.timeoutMs : undefined,
    output: normalizeOutputMode(parsed.output),
    strict: typeof parsed.strict === 'boolean' ? parsed.strict : undefined,
  };
}

function normalizeOutputMode(value: unknown): OutputMode {
  return value === 'json' ? 'json' : 'human';
}

function toOptionalString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function toOptionalNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== 'string' || value.trim() === '') {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function resolveReplayGateProfile(options: Record<string, unknown>) {
  const explicitName = toOptionalString(options.gateProfile);
  if (explicitName) {
    return getReplayGateProfileByName(explicitName);
  }
  const category = toOptionalString(options.sinkCategory);
  if (category) {
    return getReplayGateProfileForCategory(category);
  }
  return getReplayGateProfileByName('default');
}

function normalizeStdIoMode(value: string): 0 | 1 | 2 {
  if (value !== '0' && value !== '1' && value !== '2') {
    throw new Error(`Invalid stdout/stderr mode '${value}', expected one of 0,1,2.`);
  }

  return Number(value) as 0 | 1 | 2;
}

function normalizeTraceAction(value: string): TraceStepAction {
  const allowed = new Set(['run', 'step_into', 'step_over', 'step_out']);
  if (!allowed.has(value)) {
    throw new Error(`Invalid trace action '${value}', expected run|step_into|step_over|step_out.`);
  }

  return value as TraceStepAction;
}

async function runStepAction(inspector: PhpDebugInspector, action: TraceStepAction): Promise<void> {
  switch (action) {
    case 'run':
      await inspector.run();
      break;
    case 'step_into':
      await inspector.stepInto();
      break;
    case 'step_out':
      await inspector.stepOut();
      break;
    case 'step_over':
    default:
      await inspector.stepOver();
      break;
  }
}

function parseContextList(value: unknown): number[] | undefined {
  if (typeof value !== 'string' || value.trim() === '') {
    return undefined;
  }

  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item !== '')
    .map((item) => Number(item))
    .filter((item) => Number.isFinite(item));
}

function collectString(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function coerceScalar(value: string): string | number | boolean {
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  if (/^-?\d+$/u.test(value)) {
    return Number(value);
  }
  return value;
}

function loadReplayPlan(path: string): ReplayPlan {
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as ReplayPlan;
  if (!parsed) {
    throw new Error('Replay plan is invalid: JSON object is required.');
  }
  if (!Array.isArray(parsed.variations)) {
    parsed.variations = [];
  }
  if (!Array.isArray(parsed.matrix)) {
    parsed.matrix = [];
  }
  if (parsed.variations.length === 0 && parsed.matrix.length === 0) {
    throw new Error('Replay plan is invalid: variations[] or matrix[] is required.');
  }

  return parsed;
}

function loadReplayResultsArtifact(pathValue: string): {
  raw: unknown;
  results: ReplayResult[];
  roundResults: Array<{ round: number; results: ReplayResult[] }>;
} {
  const raw = readFileSync(pathValue, 'utf8');
  const parsed = JSON.parse(raw) as unknown;
  assertSchemaOrThrow('replay-results.schema.json', parsed, 'Replay results artifact');
  return {
    raw: parsed,
    results: extractPrimaryReplayResults(parsed),
    roundResults: extractReplayRoundResults(parsed),
  };
}

function loadReplayManifest(pathValue: string): ReplayArtifactManifest {
  const raw = readFileSync(pathValue, 'utf8');
  const parsed = JSON.parse(raw) as unknown;
  assertSchemaOrThrow('replay-manifest.schema.json', parsed, 'Replay manifest');
  return parsed as ReplayArtifactManifest;
}

async function runReplayRounds(
  common: CommonCliOptions,
  replayPlan: ReplayPlan,
  rounds: number,
  triggerCommandTemplate: string | undefined
): Promise<{
  payload: unknown;
  results: ReplayResult[];
  roundResults: Array<{ round: number; results: ReplayResult[] }>;
}> {
  const server = new DbgpServer(toServerOptions(common));
  const controller = new ReplayController(server, common);
  await server.start();
  try {
    const roundResults: Array<{ round: number; results: Awaited<ReturnType<ReplayController['run']>> }> = [];
    const flattened: Awaited<ReturnType<ReplayController['run']>> = [];

    for (let round = 1; round <= rounds; round += 1) {
      const results = await controller.run(replayPlan, async (variation) => {
        if (!triggerCommandTemplate || triggerCommandTemplate.trim() === '') {
          return;
        }
        const command = triggerCommandTemplate
          .replaceAll('${variationId}', variation.id)
          .replaceAll('${round}', String(round));
        await exec(command);
      });
      roundResults.push({ round, results });
      flattened.push(...results);
    }

    const stabilityReport = buildReplayStabilityReport(
      roundResults.map((entry) => ({
        round: entry.round,
        results: entry.results.map((item) => item.result),
      }))
    );

    const payload = {
      ok: true,
      rounds,
      totalRuns: flattened.length,
      stabilityReport,
      data: flattened,
      roundResults,
    };

    return {
      payload,
      results: flattened.map((entry) => entry.result),
      roundResults: roundResults.map((entry) => ({
        round: entry.round,
        results: entry.results.map((item) => item.result),
      })),
    };
  } finally {
    await server.stop();
  }
}

async function runReplayCiPipeline(
  common: CommonCliOptions,
  options: Record<string, unknown>
): Promise<{
  payload: Record<string, unknown>;
  gatePassed: boolean;
}> {
  const gateProfile = resolveReplayGateProfile(options);
  const comparePhase = normalizeComparePhase(
    toOptionalString(options.comparePhase) ?? gateProfile.comparePhase
  );
  const maxDriftDetected = Math.max(
    0,
    toOptionalNumber(options.maxDriftDetected) ?? gateProfile.maxDriftDetected
  );
  const minOverall = toOptionalNumber(options.minOverallScore) ?? gateProfile.minOverallScore;
  const minVariation = toOptionalNumber(options.minVariationScore) ?? gateProfile.minVariationScore;

  const planPath = toOptionalString(options.plan);
  const resultsPath = toOptionalString(options.results);
  if (!planPath && !resultsPath) {
    throw new Error('replay-ci requires either --plan or --results.');
  }
  if (planPath && resultsPath) {
    throw new Error('replay-ci accepts only one source: --plan or --results.');
  }

  let replayPayload: unknown;
  let replayResultsArtifact: {
    raw: unknown;
    results: ReplayResult[];
    roundResults: Array<{ round: number; results: ReplayResult[] }>;
  };

  if (resultsPath) {
    replayResultsArtifact = loadReplayResultsArtifact(path.resolve(resultsPath));
    replayPayload = replayResultsArtifact.raw;
  } else {
    const replayPlan = loadReplayPlan(path.resolve(planPath as string));
    const validationErrors = validateReplayPlan(replayPlan);
    if (validationErrors.length > 0) {
      throw new Error(`Replay plan validation failed: ${validationErrors.join(' | ')}`);
    }
    const rounds = Math.max(1, toOptionalNumber(options.rounds) ?? 1);
    const replayRun = await runReplayRounds(common, replayPlan, rounds, toOptionalString(options.triggerCmd));
    replayPayload = replayRun.payload;
    replayResultsArtifact = {
      raw: replayRun.payload,
      results: replayRun.results,
      roundResults: replayRun.roundResults,
    };
    assertSchemaOrThrow('replay-results.schema.json', replayPayload, 'Replay results artifact');
  }

  const diffSummary = summarizeReplayDiffs(replayResultsArtifact.results, comparePhase);
  const stabilityReport = buildReplayStabilityReport(replayResultsArtifact.roundResults);
  const failingVariations = stabilityReport.variationScores
    .filter((entry) => entry.stabilityScore < minVariation)
    .map((entry) => ({
      variationId: entry.variationId,
      stabilityScore: entry.stabilityScore,
    }));
  const diffPassed = diffSummary.driftDetected <= maxDriftDetected;
  const stabilityPassed =
    stabilityReport.overallStabilityScore >= minOverall && failingVariations.length === 0;
  const gatePassed = diffPassed && stabilityPassed;

  const diffPayload = {
    ok: diffPassed,
    comparePhase,
    gateProfile: gateProfile.name,
    summary: diffSummary,
  };
  assertSchemaOrThrow('replay-diff.schema.json', diffPayload, 'Replay diff artifact');

  const stabilityPayload = {
    ok: stabilityPassed,
    minOverall,
    minVariation,
    gateProfile: gateProfile.name,
    thresholdsPassed: stabilityPassed,
    failingVariations,
    report: stabilityReport,
  };
  assertSchemaOrThrow('replay-stability.schema.json', stabilityPayload, 'Replay stability artifact');

  const gatePayload = {
    ok: !options.failOnGate || gatePassed,
    gatePassed,
    gate: {
      gateProfile: gateProfile.name,
      comparePhase,
      diffPassed,
      stabilityPassed,
      maxDriftDetected,
      minOverall,
      minVariation,
    },
    diff: diffPayload,
    stability: stabilityPayload,
  };

  const ciPayload: Record<string, unknown> = {
    ok: !options.failOnGate || gatePassed,
    source: resultsPath ? 'results' : 'plan',
    gateProfile: gateProfile.name,
    comparePhase,
    replayResultsPath: resultsPath ? path.resolve(resultsPath) : undefined,
    replay: replayPayload,
    diff: diffPayload,
    stability: stabilityPayload,
    gate: gatePayload,
  };

  const emittedArtifacts: ReplayArtifactOutput[] = [];
  if (options.outputDir) {
    const outputDir = path.resolve(String(options.outputDir));
    const baseName = 'replay-ci';
    const replayPath = path.join(outputDir, `${baseName}.results.json`);
    const diffPath = path.join(outputDir, `${baseName}.diff.json`);
    const stabilityPath = path.join(outputDir, `${baseName}.stability.json`);
    const gatePath = path.join(outputDir, `${baseName}.gate.json`);
    const ciPath = path.join(outputDir, `${baseName}.report.json`);
    writeJsonFile(replayPath, replayPayload);
    writeJsonFile(diffPath, diffPayload);
    writeJsonFile(stabilityPath, stabilityPayload);
    writeJsonFile(gatePath, gatePayload);
    writeJsonFile(ciPath, ciPayload);
    emittedArtifacts.push(
      { kind: 'replay_results', path: replayPath },
      { kind: 'replay_diff', path: diffPath },
      { kind: 'replay_stability', path: stabilityPath },
      { kind: 'replay_gate', path: gatePath },
      { kind: 'replay_ci', path: ciPath }
    );
    ciPayload.outputDir = outputDir;
  }

  const manifest = writeManifestIfRequested(options, emittedArtifacts);
  if (manifest) {
    ciPayload.manifestPath = manifest.path;
  }

  return {
    payload: ciPayload,
    gatePassed,
  };
}

async function runVerifierDecisionPipeline(
  common: CommonCliOptions,
  options: Record<string, unknown>
): Promise<{
  payload: Record<string, unknown>;
}> {
  const server = new DbgpServer(toServerOptions(common));
  await server.start();
  try {
    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: common.timeoutMs,
      strict: common.strict,
      sessionTimeoutMs: common.timeoutMs,
    });

    const candidateId = toOptionalString(options.candidateId);
    if (!candidateId) {
      throw new Error('verifier-decision requires --candidate-id.');
    }

    const trigger = {
      candidateId,
      sinkCategory: toOptionalString(options.sinkCategory),
      sinkName: toOptionalString(options.sinkName),
      requestUri: toOptionalString(options.requestUri),
      correlationId: toOptionalString(options.correlationId),
      requestId: toOptionalString(options.requestId),
      findingId: toOptionalString(options.findingId),
      traceId: toOptionalString(options.traceId),
      metadata: buildVerifierTriggerMetadata(options),
    };

    const templatePayloads = ((options.templatePayload as string[]) ?? []).map((entry) =>
      String(entry)
    );
    const template = {
      name: toOptionalString(options.templateName),
      category: toOptionalString(options.templateCategory),
      mutationTarget: toOptionalString(options.templateMutationTarget),
      payloads: templatePayloads.length > 0 ? templatePayloads : undefined,
      resetValue: toOptionalString(options.templateResetValue),
    };

    const artifactDir = toOptionalString(options.artifactDir)
      ? path.resolve(String(options.artifactDir))
      : undefined;
    const manifestPath = toOptionalString(options.manifestPath)
      ? path.resolve(String(options.manifestPath))
      : undefined;
    const manifestSecret = toOptionalString(options.manifestHmacSecret);
    const manifestKeyId = toOptionalString(options.manifestHmacKeyId);

    const run = await integration.runReplayAttemptsAsVerifierDecision(
      {
        trigger,
        attempts: Math.max(1, toOptionalNumber(options.attempts) ?? 3),
        stopOnFirstSuccess: options.stopOnFirstSuccess !== false,
        requireReplayEvidence: options.requireReplayEvidence !== false,
        includeTranscript: artifactDir !== undefined,
        artifactDir,
        artifactManifestPath: manifestPath,
        manifestSignature: manifestSecret
          ? {
              hmacSecret: manifestSecret,
              keyId: manifestKeyId,
            }
          : undefined,
        template,
      },
      async (resolvedTrigger, attemptIndex) => {
        const commandTemplate = toOptionalString(options.triggerCmd);
        if (!commandTemplate) {
          return;
        }
        const command = resolveVerifierTriggerCommand(
          commandTemplate,
          resolvedTrigger,
          attemptIndex
        );
        await exec(command);
      }
    );

    assertSchemaOrThrow(
      'verifier-decision.schema.json',
      run.verificationResult,
      'Verifier decision payload'
    );

    const decisionOutputPath = toOptionalString(options.decisionOutput)
      ? path.resolve(String(options.decisionOutput))
      : undefined;
    if (decisionOutputPath) {
      writeJsonFile(decisionOutputPath, run.verificationResult);
    }

    const decisionJsonlPath = toOptionalString(options.decisionJsonl)
      ? path.resolve(String(options.decisionJsonl))
      : undefined;
    if (decisionJsonlPath) {
      appendJsonlLine(decisionJsonlPath, run.verificationResult);
    }

    const confirmed = run.verificationResult.outcome === 'confirmed';
    const payload: Record<string, unknown> = {
      ok: !options.failOnUnconfirmed || confirmed,
      confirmed,
      decision: run.verificationResult,
      replay: {
        finalStatus: run.replay.bundle.finalStatus,
        successfulAttempt: run.replay.bundle.successfulAttempt,
        attempts: run.replay.bundle.attempts,
        artifactManifestPath: run.replay.artifactManifestPath,
      },
      decisionOutputPath,
      decisionJsonlPath,
    };

    return { payload };
  } finally {
    await server.stop();
  }
}

async function runVerifierDecisionBatchPipeline(
  common: CommonCliOptions,
  options: Record<string, unknown>
): Promise<{
  payload: Record<string, unknown>;
}> {
  const candidatePath = toOptionalString(options.candidatesJsonl);
  if (!candidatePath) {
    throw new Error('verifier-decision-batch requires --candidates-jsonl.');
  }
  const triggerCommandTemplate = toOptionalString(options.triggerCmd);
  if (!triggerCommandTemplate) {
    throw new Error('verifier-decision-batch requires --trigger-cmd.');
  }
  const decisionsJsonlPath = toOptionalString(options.decisionsJsonl);
  if (!decisionsJsonlPath) {
    throw new Error('verifier-decision-batch requires --decisions-jsonl.');
  }
  const resolvedDecisionsJsonlPath = path.resolve(decisionsJsonlPath);
  if (options.truncateDecisionsJsonl) {
    mkdirSync(path.dirname(resolvedDecisionsJsonlPath), { recursive: true });
    writeFileSync(resolvedDecisionsJsonlPath, '', 'utf8');
  }

  const allCandidates = await CandidateVerificationBridge.loadCandidatesFromJsonl(
    path.resolve(candidatePath)
  );
  const limit = Math.max(0, toOptionalNumber(options.limit) ?? allCandidates.length);
  const candidates = allCandidates.slice(0, limit);

  const server = new DbgpServer(toServerOptions(common));
  await server.start();
  try {
    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: common.timeoutMs,
      strict: common.strict,
      sessionTimeoutMs: common.timeoutMs,
    });

    const templatePayloads = ((options.templatePayload as string[]) ?? []).map((entry) =>
      String(entry)
    );
    const template = {
      name: toOptionalString(options.templateName),
      category: toOptionalString(options.templateCategory),
      mutationTarget: toOptionalString(options.templateMutationTarget),
      payloads: templatePayloads.length > 0 ? templatePayloads : undefined,
      resetValue: toOptionalString(options.templateResetValue),
    };
    const stopOnError = options.stopOnError === true;
    const artifactRootDir = toOptionalString(options.artifactDir)
      ? path.resolve(String(options.artifactDir))
      : undefined;
    const decisionDir = toOptionalString(options.decisionDir)
      ? path.resolve(String(options.decisionDir))
      : undefined;
    const fallbackSinkCategory = toOptionalString(options.sinkCategory) ?? 'rce';
    const attempts = Math.max(1, toOptionalNumber(options.attempts) ?? 3);
    const concurrency = Math.max(1, Math.floor(toOptionalNumber(options.concurrency) ?? 1));

    const rowsByIndex: Array<Record<string, unknown> | undefined> = new Array(candidates.length);
    const decisionsByIndex: Array<unknown | undefined> = new Array(candidates.length);
    let confirmedCount = 0;
    let errorCount = 0;
    let nextIndex = 0;
    let stopRequested = false;

    const processCandidate = async (index: number, candidate: CandidateRecord): Promise<void> => {
      const trigger = buildVerifierDecisionBatchTrigger(candidate, options, fallbackSinkCategory);
      const candidateArtifactDir = artifactRootDir
        ? path.join(
            artifactRootDir,
            `${String(index + 1).padStart(4, '0')}-${toSafePathToken(candidate.candidateId)}`
          )
        : undefined;
      const candidateManifestPath = candidateArtifactDir
        ? path.join(candidateArtifactDir, 'replay-attempts.manifest.json')
        : undefined;

      try {
        const run = await integration.runReplayAttemptsAsVerifierDecision(
          {
            trigger,
            attempts,
            stopOnFirstSuccess: options.stopOnFirstSuccess !== false,
            requireReplayEvidence: options.requireReplayEvidence !== false,
            includeTranscript: candidateArtifactDir !== undefined,
            artifactDir: candidateArtifactDir,
            artifactManifestPath: candidateManifestPath,
            template,
          },
          async (resolvedTrigger, attemptIndex) => {
            const command = resolveVerifierTriggerCommand(
              triggerCommandTemplate,
              resolvedTrigger,
              attemptIndex
            );
            await exec(command);
          }
        );

        const decision = run.verificationResult;
        assertSchemaOrThrow('verifier-decision.schema.json', decision, 'Verifier decision payload');

        let decisionPath: string | undefined;
        if (decisionDir) {
          decisionPath = path.join(
            decisionDir,
            `${String(index + 1).padStart(4, '0')}-${toSafePathToken(candidate.candidateId)}.json`
          );
          writeJsonFile(decisionPath, decision);
        }

        const confirmed = decision.outcome === 'confirmed';
        if (confirmed) {
          confirmedCount += 1;
        }
        rowsByIndex[index] = {
          candidateId: candidate.candidateId,
          outcome: decision.outcome,
          confirmed,
          decisionPath,
          artifactManifestPath: run.replay.artifactManifestPath,
          attempts: run.replay.bundle.attempts.length,
        };
        decisionsByIndex[index] = decision;
      } catch (error) {
        errorCount += 1;
        const decision = buildBatchErrorDecision(candidate, error);

        let decisionPath: string | undefined;
        if (decisionDir) {
          decisionPath = path.join(
            decisionDir,
            `${String(index + 1).padStart(4, '0')}-${toSafePathToken(candidate.candidateId)}.json`
          );
          writeJsonFile(decisionPath, decision);
        }

        rowsByIndex[index] = {
          candidateId: candidate.candidateId,
          outcome: decision.outcome,
          confirmed: false,
          error: decision.summary,
          decisionPath,
        };
        decisionsByIndex[index] = decision;

        if (stopOnError) {
          stopRequested = true;
        }
      }
    };

    const workerCount = Math.max(1, Math.min(concurrency, candidates.length));
    const worker = async (): Promise<void> => {
      while (true) {
        if (stopRequested) {
          return;
        }

        const index = nextIndex;
        nextIndex += 1;
        if (index >= candidates.length) {
          return;
        }

        const candidate = candidates[index];
        if (!candidate) {
          return;
        }

        await processCandidate(index, candidate);
      }
    };

    await Promise.all(Array.from({ length: workerCount }, () => worker()));

    const rows = rowsByIndex.filter((row): row is Record<string, unknown> => row !== undefined);
    const decisions = decisionsByIndex.filter((decision): decision is unknown => decision !== undefined);
    for (const decision of decisions) {
      appendJsonlLine(resolvedDecisionsJsonlPath, decision);
    }

    const processed = rows.length;
    const nonConfirmedCount = processed - confirmedCount;
    const payload: Record<string, unknown> = {
      ok: !options.failOnUnconfirmed || nonConfirmedCount === 0,
      inputCandidates: allCandidates.length,
      processed,
      confirmedCount,
      nonConfirmedCount,
      errorCount,
      decisionsJsonlPath: resolvedDecisionsJsonlPath,
      results: rows,
    };
    return { payload };
  } finally {
    await server.stop();
  }
}

async function runBridgeCandidates(
  common: CommonCliOptions,
  options: Record<string, unknown>
): Promise<{
  processed: number;
  results: CandidateBridgeRunResult[];
}> {
  const server = new DbgpServer(toServerOptions(common));
  const triggerResolverPlugins = await loadCandidateTriggerResolverPlugins(
    ((options.triggerResolverPlugin as string[]) ?? []).map((value) => String(value))
  );
  const redactionPlugins = await loadTranscriptRedactionPlugins(
    ((options.redactionPlugin as string[]) ?? []).map((value) => String(value))
  );
  await server.start();

  try {
    const candidatePath = toOptionalString(options.candidatesJsonl);
    const triggerCommand = toOptionalString(options.triggerCmd);
    if (!candidatePath || !triggerCommand) {
      throw new Error('bridge-candidates requires --candidates-jsonl and --trigger-cmd.');
    }
    const loaded = await CandidateVerificationBridge.loadCandidatesFromJsonl(path.resolve(candidatePath));
    const limit = Math.max(0, toOptionalNumber(options.limit) ?? loaded.length);
    const limited = loaded.slice(0, limit);
    const bridge = new CandidateVerificationBridge(server, {
      commandTimeoutMs: common.timeoutMs,
      strict: common.strict,
      artifactsDir: path.resolve(String(options.artifactsDir ?? '.dbgp_bridge_artifacts')),
      traceSteps: Number(options.traceSteps ?? 0),
      watchExpressions: (options.watch as string[]) ?? [],
      snapshotContextIds: parseContextList(options.snapshotContexts) ?? [],
      policyPackName: String(options.policyPack ?? 'default'),
      policyPackByCategory: options.disableCategoryPolicyPack !== true,
      captureProfileName: String(options.captureProfile ?? 'default'),
      captureProfileByCategory: options.disableCategoryCaptureProfile !== true,
      triggerResolverPlugins,
      transcriptRedaction: redactionPlugins.length > 0 ? { plugins: redactionPlugins } : undefined,
    });

    const results = await bridge.runCandidatesWithTemplateTrigger(
      limited,
      triggerCommand,
      async (command) => {
        await exec(command);
      }
    );

    return {
      processed: limited.length,
      results,
    };
  } finally {
    await server.stop();
  }
}

function buildVerifierDecisionBatchTrigger(
  candidate: CandidateRecord,
  options: Record<string, unknown>,
  fallbackSinkCategory: string
): {
  candidateId: string;
  sinkCategory: string;
  sinkName?: string;
  requestUri?: string;
  correlationId?: string;
  requestId?: string;
  findingId?: string;
  traceId?: string;
  metadata: Record<string, unknown>;
} {
  const metadata: Record<string, unknown> = {};
  if (candidate.metadata && typeof candidate.metadata === 'object') {
    Object.assign(metadata, candidate.metadata);
  }
  Object.assign(metadata, buildVerifierTriggerMetadata(options));

  return {
    candidateId: candidate.candidateId,
    sinkCategory: candidate.sinkCategory ?? fallbackSinkCategory,
    sinkName: candidate.sinkName,
    requestUri: candidate.requestUri,
    correlationId: candidate.correlationId,
    requestId: candidate.requestId,
    findingId: candidate.findingId,
    traceId: candidate.traceId,
    metadata,
  };
}

function buildBatchErrorDecision(
  candidate: CandidateRecord,
  error: unknown
): Record<string, unknown> {
  const message = error instanceof Error ? error.message : String(error);
  return {
    job_id: `batch_error_${toSafePathToken(candidate.candidateId)}_${Date.now()}`,
    candidate_id: candidate.candidateId,
    outcome: 'replay_failed',
    reason_codes: ['VERIFIER_DEBUG_BATCH_PIPELINE_ERROR'],
    summary: message,
    artifacts: [],
    replay_transcripts: [],
    created_at: new Date().toISOString(),
    metadata: {
      source: 'verifier-decision-batch',
      sink_category: candidate.sinkCategory ?? null,
      sink_name: candidate.sinkName ?? null,
      request_uri: candidate.requestUri ?? null,
    },
  };
}

function extractPrimaryReplayResults(input: unknown): ReplayResult[] {
  if (input && typeof input === 'object') {
    const object = input as Record<string, unknown>;
    if (Array.isArray(object.data)) {
      return extractReplayResultObjects(object.data);
    }
    if (Array.isArray(object.roundResults)) {
      return object.roundResults.flatMap((entry) => {
        if (!entry || typeof entry !== 'object') {
          return [];
        }
        return extractReplayResultObjects((entry as Record<string, unknown>).results);
      });
    }
  }

  return extractReplayResultObjects(input);
}

function extractReplayRoundResults(input: unknown): Array<{ round: number; results: ReplayResult[] }> {
  if (input && typeof input === 'object') {
    const object = input as Record<string, unknown>;
    if (Array.isArray(object.roundResults)) {
      const rounds = object.roundResults
        .map((entry) => {
          if (!entry || typeof entry !== 'object') {
            return undefined;
          }
          const item = entry as Record<string, unknown>;
          const roundRaw = typeof item.round === 'number' ? item.round : Number(item.round ?? 0);
          const results = extractReplayResultObjects(item.results);
          if (!Number.isFinite(roundRaw) || roundRaw <= 0) {
            return undefined;
          }
          return { round: roundRaw, results };
        })
        .filter((entry): entry is { round: number; results: ReplayResult[] } => Boolean(entry));
      if (rounds.length > 0) {
        return rounds;
      }
    }
  }

  return [{ round: 1, results: extractReplayResultObjects(input) }];
}

function extractReplayResultObjects(input: unknown): ReplayResult[] {
  if (!input) {
    return [];
  }

  if (Array.isArray(input)) {
    return input.flatMap((entry) => extractReplayResultObjects(entry));
  }

  if (typeof input !== 'object') {
    return [];
  }

  const object = input as Record<string, unknown>;
  const output: ReplayResult[] = [];

  if (Array.isArray(object.data)) {
    output.push(...extractReplayResultObjects(object.data));
  }
  if (Array.isArray(object.results)) {
    output.push(...extractReplayResultObjects(object.results));
  }
  if (Array.isArray(object.roundResults)) {
    output.push(...extractReplayResultObjects(object.roundResults));
  }

  if (object.result && typeof object.result === 'object' && !Array.isArray(object.result)) {
    const result = toReplayResult(object.result);
    if (result) {
      output.push(result);
    }
  } else {
    const result = toReplayResult(object);
    if (result) {
      output.push(result);
    }
  }

  return output;
}

function toReplayResult(value: unknown): ReplayResult | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  const candidate = value as Record<string, unknown>;
  const variation = candidate.variation;
  if (!variation || typeof variation !== 'object') {
    return undefined;
  }
  const variationId = (variation as Record<string, unknown>).id;
  if (typeof variationId !== 'string' || variationId.trim() === '') {
    return undefined;
  }

  const evalResults = candidate.evalResults;
  const errors = candidate.errors;
  if (!evalResults || typeof evalResults !== 'object' || !Array.isArray(errors)) {
    return undefined;
  }

  return candidate as unknown as ReplayResult;
}

function assertSchemaOrThrow(schemaFile: string, value: unknown, label: string): void {
  const schema = loadSchema(schemaFile);
  const errors = validateJsonSchema(schema, value);
  if (errors.length > 0) {
    throw new Error(`${label} failed schema validation: ${errors.join(' | ')}`);
  }
}

function writeManifestIfRequested(
  options: Record<string, unknown>,
  artifacts: ReplayArtifactOutput[]
): { path: string } | undefined {
  const manifestPath = toOptionalString(options.manifestPath);
  if (!manifestPath || artifacts.length === 0) {
    return undefined;
  }

  const resolvedManifestPath = path.resolve(manifestPath);
  const manifestDir = path.dirname(resolvedManifestPath);
  const hmacSecret = toOptionalString(options.manifestHmacSecret);
  const hmacKeyId = toOptionalString(options.manifestHmacKeyId);
  const manifest = createReplayArtifactManifest(
    artifacts.map((artifact) => ({
      kind: artifact.kind,
      path: artifact.path,
    })),
    {
      baseDir: manifestDir,
      signature: hmacSecret
        ? {
            hmacSecret,
            keyId: hmacKeyId,
          }
        : undefined,
    }
  );
  assertSchemaOrThrow('replay-manifest.schema.json', manifest, 'Replay manifest');
  writeJsonFile(resolvedManifestPath, manifest);
  return { path: resolvedManifestPath };
}

function writeJsonFile(outputPath: string, payload: unknown): void {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

function appendJsonlLine(outputPath: string, payload: unknown): void {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  appendFileSync(outputPath, `${JSON.stringify(payload)}\n`, 'utf8');
}

function toSafePathToken(value: string): string {
  const normalized = value.replace(/[^A-Za-z0-9._-]/gu, '_');
  return normalized === '' ? 'value' : normalized;
}

function loadSchema(schemaFile: string): JsonSchemaDocument {
  const cached = schemaCache.get(schemaFile);
  if (cached) {
    return cached;
  }

  const schemaPath = resolveSchemaPath(schemaFile);
  const raw = readFileSync(schemaPath, 'utf8');
  const parsed = JSON.parse(raw) as JsonSchemaDocument;
  schemaCache.set(schemaFile, parsed);
  return parsed;
}

function resolveSchemaPath(schemaFile: string): string {
  const candidates = new Set<string>();
  candidates.add(path.resolve(process.cwd(), 'schemas', schemaFile));
  candidates.add(path.resolve(process.cwd(), 'subprojects/nodejs_php_dbgp_client_sdk/schemas', schemaFile));

  for (const argv of process.argv) {
    if (typeof argv !== 'string' || argv.trim() === '') {
      continue;
    }
    const resolved = path.resolve(argv);
    const dir = path.dirname(resolved);
    candidates.add(path.resolve(dir, 'schemas', schemaFile));
    candidates.add(path.resolve(dir, '../schemas', schemaFile));
  }

  if (typeof __dirname === 'string') {
    candidates.add(path.resolve(__dirname, '../schemas', schemaFile));
  }

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(`Unable to resolve schema path for '${schemaFile}'.`);
}

function normalizeComparePhase(value: string): 'pre' | 'post' | 'post_reset' {
  if (value === 'pre' || value === 'post' || value === 'post_reset') {
    return value;
  }

  throw new Error(`Invalid compare phase '${value}', expected pre|post|post_reset.`);
}

function buildVerifierTriggerMetadata(options: Record<string, unknown>): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  const targetParam = toOptionalString(options.templateTargetParam);
  if (targetParam) {
    metadata.targetParam = targetParam;
  }

  return metadata;
}

function resolveVerifierTriggerCommand(
  template: string,
  trigger: {
    candidateId?: string;
    sinkCategory?: string;
    sinkName?: string;
    requestUri?: string;
    correlationId?: string;
    requestId?: string;
    findingId?: string;
    traceId?: string;
  },
  attemptIndex: number
): string {
  const attemptNumber = attemptIndex + 1;
  return template
    .replaceAll('${candidateId}', shellEscape(trigger.candidateId ?? ''))
    .replaceAll('${sinkCategory}', shellEscape(trigger.sinkCategory ?? ''))
    .replaceAll('${sinkName}', shellEscape(trigger.sinkName ?? ''))
    .replaceAll('${requestUri}', shellEscape(trigger.requestUri ?? ''))
    .replaceAll('${correlationId}', shellEscape(trigger.correlationId ?? trigger.candidateId ?? ''))
    .replaceAll('${requestId}', shellEscape(trigger.requestId ?? ''))
    .replaceAll('${findingId}', shellEscape(trigger.findingId ?? ''))
    .replaceAll('${traceId}', shellEscape(trigger.traceId ?? ''))
    .replaceAll('${attempt}', shellEscape(String(attemptNumber)))
    .replaceAll('${attemptIndex}', shellEscape(String(attemptIndex)));
}

function toServerOptions(options: CommonCliOptions): DbgpServerOptions {
  return {
    host: options.host,
    port: options.port,
    strict: options.strict,
    commandTimeoutMs: options.timeoutMs,
  };
}

async function runOneShot<T>(
  rawOptions: Record<string, unknown>,
  task: (inspector: PhpDebugInspector, session: DbgpSession) => Promise<T>
): Promise<void> {
  const options = normalizeCommonOptions(rawOptions);
  const server = new DbgpServer(toServerOptions(options));
  await server.start();

  try {
    const session = await server.waitForNextSession(options.timeoutMs);
    await session.waitForInit(options.timeoutMs);
    const inspector = new PhpDebugInspector(session, {
      commandTimeoutMs: options.timeoutMs,
      strict: options.strict,
    });
    const data = await task(inspector, session);
    printOutput(options.output, {
      ok: true,
      sessionId: session.id,
      data,
    });
  } finally {
    await server.stop();
  }
}

async function runInteractiveShell(session: DbgpSession, options: CommonCliOptions): Promise<void> {
  const inspector = new PhpDebugInspector(session, {
    commandTimeoutMs: options.timeoutMs,
    strict: options.strict,
  });
  const rl = readline.createInterface({ input, output });

  printOutput(options.output, {
    event: 'interactive_ready',
    commands: [
      'stack',
      'contexts',
      'context-get <id>',
      'eval <expression>',
      'run',
      'step-into',
      'step-over',
      'step-out',
      'snapshot',
      'transcript',
      'quit',
    ],
  });

  try {
    while (true) {
      const line = (await rl.question('dbgp> ')).trim();
      if (!line) {
        continue;
      }
      if (line === 'quit' || line === 'exit') {
        break;
      }

      const [command, ...rest] = line.split(/\s+/u);
      switch (command) {
        case 'stack':
          printOutput(options.output, { data: await inspector.stackGet() });
          break;
        case 'contexts':
          printOutput(options.output, { data: await inspector.contextNames() });
          break;
        case 'context-get':
          printOutput(options.output, {
            data: await inspector.contextGet(Number(rest[0] ?? '0')),
          });
          break;
        case 'eval':
          printOutput(options.output, {
            data: await inspector.evaluate(rest.join(' ')),
          });
          break;
        case 'run':
          printOutput(options.output, { data: await inspector.run() });
          break;
        case 'step-into':
          printOutput(options.output, { data: await inspector.stepInto() });
          break;
        case 'step-over':
          printOutput(options.output, { data: await inspector.stepOver() });
          break;
        case 'step-out':
          printOutput(options.output, { data: await inspector.stepOut() });
          break;
        case 'snapshot':
          printOutput(options.output, { data: await inspector.captureSnapshot() });
          break;
        case 'transcript':
          printOutput(options.output, { data: session.getTranscript() });
          break;
        default:
          printOutput(options.output, { error: `Unknown command: ${command}` });
          break;
      }
    }
  } finally {
    rl.close();
  }
}

function printOutput(mode: OutputMode, payload: unknown): void {
  if (mode === 'json') {
    process.stdout.write(`${JSON.stringify(payload)}\n`);
    return;
  }

  if (typeof payload === 'string') {
    process.stdout.write(`${payload}\n`);
    return;
  }

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

async function loadTranscriptRedactionPlugins(
  moduleSpecs: string[]
): Promise<TranscriptRedactionPlugin[]> {
  const plugins: TranscriptRedactionPlugin[] = [];

  for (const moduleSpec of moduleSpecs) {
    const before = plugins.length;
    const moduleExports = await importUserModule(moduleSpec);
    for (const candidate of collectPluginCandidates(moduleExports)) {
      if (isTranscriptRedactionPlugin(candidate)) {
        plugins.push(candidate);
      }
    }
    if (plugins.length === before) {
      throw new Error(
        `No TranscriptRedactionPlugin export found in '${moduleSpec}'. Export default/plugin/plugins with { name, redact }.`
      );
    }
  }

  return plugins;
}

async function loadCandidateTriggerResolverPlugins(
  moduleSpecs: string[]
): Promise<CandidateTriggerResolverPlugin[]> {
  const plugins: CandidateTriggerResolverPlugin[] = [];

  for (const moduleSpec of moduleSpecs) {
    const before = plugins.length;
    const moduleExports = await importUserModule(moduleSpec);
    for (const candidate of collectPluginCandidates(moduleExports)) {
      if (isCandidateTriggerResolverPlugin(candidate)) {
        plugins.push(candidate);
      }
    }
    if (plugins.length === before) {
      throw new Error(
        `No CandidateTriggerResolverPlugin export found in '${moduleSpec}'. Export default/plugin/plugins with { name, resolve }.`
      );
    }
  }

  return plugins;
}

async function importUserModule(moduleSpec: string): Promise<Record<string, unknown>> {
  const trimmed = moduleSpec.trim();
  if (trimmed === '') {
    throw new Error('Plugin module spec cannot be empty.');
  }

  const specifier =
    trimmed.startsWith('.') || trimmed.startsWith('/')
      ? pathToFileURL(path.resolve(trimmed)).href
      : trimmed;
  return (await import(specifier)) as Record<string, unknown>;
}

function collectPluginCandidates(moduleExports: Record<string, unknown>): unknown[] {
  const candidates: unknown[] = [];
  if ('default' in moduleExports) {
    candidates.push(moduleExports.default);
  }
  if ('plugin' in moduleExports) {
    candidates.push(moduleExports.plugin);
  }
  if (Array.isArray(moduleExports.plugins)) {
    candidates.push(...moduleExports.plugins);
  }

  if (candidates.length > 0) {
    return candidates;
  }

  return Object.values(moduleExports);
}

function isTranscriptRedactionPlugin(value: unknown): value is TranscriptRedactionPlugin {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const plugin = value as { name?: unknown; redact?: unknown };
  return typeof plugin.name === 'string' && typeof plugin.redact === 'function';
}

function isCandidateTriggerResolverPlugin(value: unknown): value is CandidateTriggerResolverPlugin {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const plugin = value as { name?: unknown; resolve?: unknown };
  return typeof plugin.name === 'string' && typeof plugin.resolve === 'function';
}
