import type { ReplayMutation, ReplayPlan, TracePlan } from '../inspector/types.js';
import { getCaptureProfileByName, getCaptureProfileForCategory } from '../profiles/packs.js';
import type {
  DebugReplayTemplate,
  DebugReplayTemplateSelection,
  ResolvedDebugReplayTemplate,
  SinkTriggerContext,
} from './types.js';

const REPLAY_TEMPLATES: DebugReplayTemplate[] = [
  {
    name: 'default',
    categories: ['default'],
    description: 'Generic deterministic replay around a command-like variable.',
    captureProfile: 'default',
    mutationTarget: '$cmd',
    payloads: ['safe_probe', 'alt_probe'],
    resetValue: 'baseline_probe',
    driftExpressions: ['$cmd'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: false,
    maxExpressionDriftCount: 0,
    allowedExpressionDrift: [],
  },
  {
    name: 'rce',
    categories: ['rce', 'command', 'os_command'],
    description: 'Command execution mutation template.',
    captureProfile: 'rce',
    mutationTarget: '$cmd',
    payloads: ['id', 'whoami'],
    resetValue: 'echo baseline',
    driftExpressions: ['$cmd', '$_GET["cmd"]'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: false,
    maxExpressionDriftCount: 0,
    allowedExpressionDrift: [],
  },
  {
    name: 'ssrf',
    categories: ['ssrf', 'network'],
    description: 'Outbound URL mutation template.',
    captureProfile: 'ssrf',
    mutationTarget: '$url',
    payloads: ['http://127.0.0.1:8080/probe', 'http://example.invalid/probe'],
    resetValue: 'http://127.0.0.1:80/reset',
    driftExpressions: ['$url', '$_GET["url"]'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: false,
    maxExpressionDriftCount: 1,
    allowedExpressionDrift: ['$last_error'],
  },
  {
    name: 'sqli',
    categories: ['sqli', 'sql_injection'],
    description: 'SQL query mutation template.',
    captureProfile: 'sqli',
    mutationTarget: '$sql',
    payloads: ['1 OR 1=1', '1 UNION SELECT 1'],
    resetValue: '1',
    driftExpressions: ['$sql', '$query', '$_GET["id"]'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: false,
    maxExpressionDriftCount: 1,
    allowedExpressionDrift: ['$lastInsertId'],
  },
  {
    name: 'file',
    categories: ['file', 'lfi', 'path_traversal'],
    description: 'Filesystem/path mutation template.',
    captureProfile: 'file',
    mutationTarget: '$path',
    payloads: ['../../etc/passwd', '/etc/hosts'],
    resetValue: '/tmp/safe.txt',
    driftExpressions: ['$path', '$filename', '$_GET["file"]'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: true,
    maxExpressionDriftCount: 1,
    allowedExpressionDrift: ['$realpathCache'],
  },
  {
    name: 'xss',
    categories: ['xss'],
    description: 'Output buffer mutation template.',
    captureProfile: 'xss',
    mutationTarget: '$output',
    payloads: ['<script>alert(1)</script>', '"><svg/onload=alert(1)>'],
    resetValue: 'safe-output',
    driftExpressions: ['$output', '$html', '$_GET["q"]'],
    comparePhase: 'post',
    failOnDrift: false,
    allowSnapshotDrift: true,
    maxExpressionDriftCount: 1,
    allowedExpressionDrift: ['$output_buffer'],
  },
  {
    name: 'idor',
    categories: ['idor', 'authorization'],
    description: 'Resource identifier mutation template.',
    captureProfile: 'idor',
    mutationTarget: '$resourceId',
    payloads: ['1001', '1002'],
    resetValue: '1000',
    driftExpressions: ['$resourceId', '$ownerId', '$userId', '$_GET["id"]'],
    comparePhase: 'post_reset',
    failOnDrift: false,
    allowSnapshotDrift: false,
    maxExpressionDriftCount: 1,
    allowedExpressionDrift: ['$requestId'],
  },
];

export function getDebugReplayTemplateByName(name: string): DebugReplayTemplate {
  const normalized = name.trim().toLowerCase();
  const matched = REPLAY_TEMPLATES.find((template) => template.name === normalized);
  return matched ?? REPLAY_TEMPLATES[0];
}

export function getDebugReplayTemplateForCategory(category?: string): DebugReplayTemplate {
  const normalized = (category ?? '').trim().toLowerCase();
  if (normalized === '') {
    return getDebugReplayTemplateByName('default');
  }
  const matched = REPLAY_TEMPLATES.find(
    (template) =>
      template.name === normalized ||
      template.categories.some((entry) => entry === normalized)
  );
  return matched ?? getDebugReplayTemplateByName('default');
}

export function resolveDebugReplayTemplate(
  trigger: SinkTriggerContext,
  selection?: DebugReplayTemplateSelection
): ResolvedDebugReplayTemplate {
  const metadata = readMetadata(trigger);
  const resolvedCategory = (selection?.category ?? trigger.sinkCategory ?? metadata.sinkCategory)?.trim();
  const base = selection?.name
    ? getDebugReplayTemplateByName(selection.name)
    : getDebugReplayTemplateForCategory(resolvedCategory);
  const payloads = selection?.payloads && selection.payloads.length > 0
    ? selection.payloads
    : metadata.replayPayloads ?? base.payloads;
  const mutationTarget =
    selection?.mutationTarget ??
    metadata.mutationTarget ??
    deriveMutationTarget(
      trigger,
      base.name,
      metadata,
      resolvedCategory,
      trigger.sinkName ?? metadata.sinkName
    ) ??
    base.mutationTarget;
  const resetValue = selection?.resetValue ?? metadata.resetValue ?? base.resetValue;
  const driftExpressions = unique([
    ...(selection?.driftExpressions ?? []),
    ...base.driftExpressions,
    mutationTarget,
  ]);
  const comparePhase = selection?.comparePhase ?? base.comparePhase;
  const failOnDrift = selection?.failOnDrift ?? base.failOnDrift;
  const allowSnapshotDrift = selection?.allowSnapshotDrift ?? base.allowSnapshotDrift;
  const maxExpressionDriftCount =
    selection?.maxExpressionDriftCount ?? base.maxExpressionDriftCount;
  const allowedExpressionDrift = unique([
    ...(selection?.allowedExpressionDrift ?? []),
    ...base.allowedExpressionDrift,
  ]);

  const profile = getCaptureProfileByName(base.captureProfile);
  const profileByCategory = getCaptureProfileForCategory(resolvedCategory);
  const traceProfile = profileByCategory.name === 'default' ? profile : profileByCategory;

  const replayPlan = buildReplayPlan({
    templateName: base.name,
    mutationTarget,
    payloads,
    resetValue,
    driftExpressions,
    comparePhase,
    failOnDrift,
    allowSnapshotDrift,
    maxExpressionDriftCount,
    allowedExpressionDrift,
    snapshotContextIds: traceProfile.snapshotContextIds,
  });

  const tracePlan: TracePlan = {
    steps: traceProfile.traceSteps,
    action: traceProfile.traceAction,
    watchExpressions: [...traceProfile.watchExpressions],
    snapshotContextIds: [...traceProfile.snapshotContextIds],
    stopOnStatuses: [...traceProfile.stopOnStatuses],
  };

  const evaluateExpressions = unique([
    ...driftExpressions,
    ...traceProfile.watchExpressions,
  ]);

  return {
    template: {
      ...base,
      mutationTarget,
      payloads: [...payloads],
      resetValue,
      driftExpressions: [...driftExpressions],
      comparePhase,
      failOnDrift,
      allowSnapshotDrift,
      maxExpressionDriftCount,
      allowedExpressionDrift: [...allowedExpressionDrift],
      captureProfile: traceProfile.name,
    },
    replayPlan,
    tracePlan,
    evaluateExpressions,
    snapshotContextIds: [...traceProfile.snapshotContextIds],
    primeAction: 'step_into',
  };
}

function buildReplayPlan(input: {
  templateName: string;
  mutationTarget: string;
  payloads: string[];
  resetValue: string;
  driftExpressions: string[];
  comparePhase: 'pre' | 'post' | 'post_reset';
  failOnDrift: boolean;
  allowSnapshotDrift: boolean;
  maxExpressionDriftCount: number;
  allowedExpressionDrift: string[];
  snapshotContextIds: number[];
}): ReplayPlan {
  const resetMutation: ReplayMutation = {
    propertyName: input.mutationTarget,
    value: input.resetValue,
  };

  return {
    variations: input.payloads.map((payload, index) => ({
      id: `${input.templateName}_payload_${index + 1}`,
      description: `${input.templateName} replay payload #${index + 1}`,
      mutations: [
        {
          propertyName: input.mutationTarget,
          value: payload,
        },
      ],
      evalExpressions: [...input.driftExpressions],
      resetMutations: [resetMutation],
    })),
    baselineMutations: [resetMutation],
    captureBaseline: true,
    captureBefore: true,
    captureAfter: true,
    capturePostReset: true,
    snapshotContextIds: [...input.snapshotContextIds],
    continueAfterMutation: false,
    continueAfterReset: false,
    failOnResetError: false,
    deterministicChecks: {
      enabled: true,
      failOnDrift: input.failOnDrift,
      comparePhase: input.comparePhase,
      driftExpressions: [...input.driftExpressions],
      thresholds: {
        allowSnapshotDrift: input.allowSnapshotDrift,
        maxExpressionDriftCount: input.maxExpressionDriftCount,
        allowedExpressionDrift: [...input.allowedExpressionDrift],
      },
    },
  };
}

function unique(values: string[]): string[] {
  const set = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (normalized !== '') {
      set.add(normalized);
    }
  }
  return [...set];
}

function readMetadata(trigger: SinkTriggerContext): {
  mutationTarget?: string;
  resetValue?: string;
  replayPayloads?: string[];
  requestUri?: string;
  requestMethod?: string;
  sinkCategory?: string;
  sinkName?: string;
  queryParam?: string;
  targetQueryParam?: string;
  targetBodyParam?: string;
  targetParamLocation?: string;
  sourceParamNames: string[];
  sinkArgumentRoles: string[];
  taintedArgumentIndexes: number[];
} {
  const metadata = trigger.metadata;
  if (!metadata || typeof metadata !== 'object') {
    return {
      sourceParamNames: [],
      sinkArgumentRoles: [],
      taintedArgumentIndexes: [],
    };
  }

  const mutationTarget = firstStringAtPaths(metadata, [
    ['mutationTarget'],
    ['replayMutationTarget'],
    ['targetExpression'],
  ]) ?? firstString(metadata, [
    'mutationTarget',
    'replayMutationTarget',
    'targetExpression',
  ]);
  const resetValue = firstStringAtPaths(metadata, [
    ['resetValue'],
    ['replayResetValue'],
  ]) ?? firstString(metadata, ['resetValue', 'replayResetValue']);
  const replayPayloads =
    firstStringArrayAtPaths(metadata, [['payloads'], ['replayPayloads']]) ??
    firstStringArray(metadata, ['payloads', 'replayPayloads']);
  const requestUri = firstStringAtPaths(metadata, [
    ['requestUri'],
    ['request_uri'],
    ['request_evidence', 'request_uri'],
    ['candidate_snapshot', 'request_evidence', 'request_uri'],
    ['candidateSnapshot', 'requestEvidence', 'requestUri'],
  ]);
  const requestMethod = firstStringAtPaths(metadata, [
    ['requestMethod'],
    ['request_method'],
    ['request_evidence', 'request_method'],
    ['candidate_snapshot', 'request_evidence', 'request_method'],
    ['candidateSnapshot', 'requestEvidence', 'requestMethod'],
  ]);
  const sinkCategory = firstStringAtPaths(metadata, [
    ['sinkCategory'],
    ['sink_category'],
    ['candidate_snapshot', 'sink_category'],
    ['candidateSnapshot', 'sinkCategory'],
  ]);
  const sinkName = firstStringAtPaths(metadata, [
    ['sinkName'],
    ['sink_name'],
    ['sink_evidence', 'sink_name'],
    ['candidate_snapshot', 'sink_name'],
    ['candidate_snapshot', 'sink_evidence', 'sink_name'],
    ['candidateSnapshot', 'sinkName'],
  ]);
  const queryParam = firstStringAtPaths(metadata, [
    ['queryParam'],
    ['requestParam'],
    ['targetParam'],
  ]) ?? firstString(metadata, ['queryParam', 'requestParam', 'targetParam']);
  const targetQueryParam = firstStringAtPaths(metadata, [
    ['target_query_param'],
    ['targetQueryParam'],
    ['payload_plan', 'target_query_param'],
    ['payloadPlan', 'targetQueryParam'],
    ['replay_plan', 'target_query_param'],
    ['replayPlan', 'targetQueryParam'],
    ['candidate_snapshot', 'payload_plan', 'target_query_param'],
    ['candidateSnapshot', 'payloadPlan', 'targetQueryParam'],
    ['candidate_snapshot', 'replay_plan', 'target_query_param'],
    ['candidateSnapshot', 'replayPlan', 'targetQueryParam'],
  ]);
  const targetBodyParam = firstStringAtPaths(metadata, [
    ['target_body_param'],
    ['targetBodyParam'],
    ['replay_plan', 'target_body_param'],
    ['replayPlan', 'targetBodyParam'],
    ['candidate_snapshot', 'replay_plan', 'target_body_param'],
    ['candidateSnapshot', 'replayPlan', 'targetBodyParam'],
  ]);
  const targetParamLocation = firstStringAtPaths(metadata, [
    ['target_param_location'],
    ['targetParamLocation'],
    ['replay_plan', 'target_param_location'],
    ['replayPlan', 'targetParamLocation'],
    ['candidate_snapshot', 'replay_plan', 'target_param_location'],
    ['candidateSnapshot', 'replayPlan', 'targetParamLocation'],
  ]);
  const sourceParamNames = unique([
    ...(firstStringArrayAtPaths(metadata, [
      ['source_param_names'],
      ['sourceParamNames'],
      ['taint_evidence', 'metadata', 'source_param_names'],
      ['taint_evidence', 'metadata', 'source_params'],
      ['taint_evidence', 'metadata', 'source_keys'],
      ['candidate_snapshot', 'taint_evidence', 'metadata', 'source_param_names'],
      ['candidate_snapshot', 'taint_evidence', 'metadata', 'source_params'],
      ['candidate_snapshot', 'taint_evidence', 'metadata', 'source_keys'],
      ['candidateSnapshot', 'taintEvidence', 'metadata', 'sourceParamNames'],
      ['candidateSnapshot', 'taintEvidence', 'metadata', 'sourceParams'],
      ['candidateSnapshot', 'taintEvidence', 'metadata', 'sourceKeys'],
    ]) ?? []),
  ]);
  const sinkArgumentRoles = unique([
    ...(readStringCollectionAtPath(metadata, ['sink_evidence', 'argument_roles']) ?? []),
    ...(readStringCollectionAtPath(metadata, ['candidate_snapshot', 'sink_evidence', 'argument_roles']) ?? []),
    ...(readStringCollectionAtPath(metadata, ['candidateSnapshot', 'sinkEvidence', 'argumentRoles']) ?? []),
  ]);
  const taintedArgumentIndexes = uniqueNumbers([
    ...(readNumberCollectionAtPath(metadata, ['taint_evidence', 'tainted_argument_indexes']) ?? []),
    ...(readNumberCollectionAtPath(metadata, ['candidate_snapshot', 'taint_evidence', 'tainted_argument_indexes']) ?? []),
    ...(readNumberCollectionAtPath(metadata, ['candidateSnapshot', 'taintEvidence', 'taintedArgumentIndexes']) ?? []),
  ]);
  return {
    mutationTarget,
    resetValue,
    replayPayloads,
    requestUri,
    requestMethod,
    sinkCategory,
    sinkName,
    queryParam,
    targetQueryParam,
    targetBodyParam,
    targetParamLocation,
    sourceParamNames,
    sinkArgumentRoles,
    taintedArgumentIndexes,
  };
}

function deriveMutationTarget(
  trigger: SinkTriggerContext,
  templateName: string,
  metadata: {
    requestUri?: string;
    requestMethod?: string;
    queryParam?: string;
    targetQueryParam?: string;
    targetBodyParam?: string;
    targetParamLocation?: string;
    sourceParamNames: string[];
    sinkArgumentRoles: string[];
    taintedArgumentIndexes: number[];
  },
  sinkCategory?: string,
  sinkName?: string
): string | undefined {
  if (metadata.queryParam) {
    return buildRequestExpression('query', metadata.queryParam);
  }

  if (metadata.targetBodyParam) {
    const location = metadata.targetParamLocation?.toLowerCase() === 'query' ? 'query' : 'body';
    return buildRequestExpression(location, metadata.targetBodyParam);
  }

  if (metadata.targetQueryParam) {
    const location = metadata.targetParamLocation?.toLowerCase() === 'body' ? 'body' : 'query';
    return buildRequestExpression(location, metadata.targetQueryParam);
  }

  const roleHints = roleBasedParamHints(metadata.sinkArgumentRoles);
  const sourceHints = unique([
    ...metadata.sourceParamNames,
    ...roleHints,
  ]);

  const queryParam = chooseQueryParamFromRequest(
    trigger.requestUri ?? metadata.requestUri,
    templateName,
    sinkName,
    sinkCategory,
    sourceHints
  );
  if (queryParam) {
    const shouldPreferBody =
      metadata.targetParamLocation?.toLowerCase() === 'body' ||
      (metadata.requestMethod?.toUpperCase() === 'POST' &&
        sourceHints.some((hint) => hint.toLowerCase() === queryParam.toLowerCase()));
    return buildRequestExpression(shouldPreferBody ? 'body' : 'query', queryParam);
  }

  return undefined;
}

function chooseQueryParamFromRequest(
  requestUri: string | undefined,
  templateName: string,
  sinkName?: string,
  sinkCategory?: string,
  preferredParamHints: string[] = []
): string | undefined {
  if (!requestUri || requestUri.trim() === '') {
    return undefined;
  }

  let url: URL;
  try {
    url = new URL(requestUri, 'http://debug.local');
  } catch {
    return undefined;
  }

  const allParams = [...url.searchParams.keys()].map((entry) => entry.trim()).filter(Boolean);
  if (allParams.length === 0) {
    return undefined;
  }

  const sinkHints = sinkName ? inferSinkHints(sinkName) : [];
  const categoryHints = sinkCategory
    ? TEMPLATE_PARAM_HINTS[sinkCategory.toLowerCase()] ?? []
    : [];
  const templateHints = TEMPLATE_PARAM_HINTS[templateName] ?? TEMPLATE_PARAM_HINTS.default;
  const hinted = unique([
    ...preferredParamHints,
    ...sinkHints,
    ...categoryHints,
    ...templateHints,
  ]).map((entry) => entry.toLowerCase());
  for (const hint of hinted) {
    const match = allParams.find((param) => param.toLowerCase() === hint);
    if (match) {
      return match;
    }
  }

  const nonRouting = allParams.find((param) => !ROUTING_PARAM_NAMES.has(param.toLowerCase()));
  if (nonRouting) {
    return nonRouting;
  }

  return allParams[0];
}

function inferSinkHints(sinkName: string): string[] {
  const normalized = sinkName.trim().toLowerCase();
  if (normalized.includes('include') || normalized.includes('require') || normalized.includes('eval')) {
    return ['file', 'path', 'page', 'include', 'template', 'view', 'src'];
  }
  if (normalized.includes('curl')) {
    return ['url', 'target', 'uri', 'dest', 'endpoint'];
  }
  if (normalized.includes('query') || normalized.includes('exec') || normalized.includes('prepare')) {
    return ['query', 'sql', 'id', 'where'];
  }
  return [];
}

function buildGetExpression(paramName: string): string {
  return `$_GET["${paramName.replaceAll('"', '\\"')}"]`;
}

function buildPostExpression(paramName: string): string {
  return `$_POST["${paramName.replaceAll('"', '\\"')}"]`;
}

function buildRequestExpression(location: 'query' | 'body', paramName: string): string {
  const normalized = paramName.trim();
  if (normalized === '') {
    return buildGetExpression(paramName);
  }
  if (location === 'body') {
    return buildPostExpression(normalized);
  }
  return buildGetExpression(normalized);
}

const TEMPLATE_PARAM_HINTS: Record<string, string[]> = {
  default: ['id', 'q', 'cmd', 'url', 'file'],
  rce: ['cmd', 'command', 'exec', 'shell', 'run'],
  ssrf: ['url', 'uri', 'target', 'dest', 'destination', 'endpoint'],
  sqli: ['id', 'query', 'sql', 'where', 'filter'],
  file: ['file', 'path', 'page', 'template', 'include', 'view', 'src'],
  xss: ['q', 'query', 'search', 'input', 'msg', 'message', 'comment', 'html'],
  idor: ['id', 'user', 'userid', 'resource', 'object', 'account', 'order', 'invoice'],
};

const ROUTING_PARAM_NAMES = new Set<string>([
  'sink',
  'mode',
  'action',
  'route',
  'controller',
  'method',
  'page',
  'view',
  'feature',
  'op',
  'csrf',
  '_token',
  'token',
]);

function roleBasedParamHints(roles: string[]): string[] {
  const lowerRoles = roles.map((entry) => entry.toLowerCase());
  if (lowerRoles.includes('resource_id')) {
    return ['resource_id', 'id'];
  }
  if (lowerRoles.includes('path')) {
    return ['path', 'file', 'filename'];
  }
  if (lowerRoles.includes('url')) {
    return ['url', 'uri', 'target'];
  }
  return [];
}

function firstString(
  source: Record<string, unknown>,
  keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === 'string' && value.trim() !== '') {
      return value.trim();
    }
  }
  return undefined;
}

function firstStringAtPaths(
  source: Record<string, unknown>,
  paths: string[][]
): string | undefined {
  for (const path of paths) {
    const value = readAtPath(source, path);
    if (typeof value === 'string' && value.trim() !== '') {
      return value.trim();
    }
  }
  return undefined;
}

function firstStringArray(
  source: Record<string, unknown>,
  keys: string[]
): string[] | undefined {
  for (const key of keys) {
    const value = source[key];
    if (!Array.isArray(value)) {
      continue;
    }
    const normalized = value
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');
    if (normalized.length > 0) {
      return normalized;
    }
  }
  return undefined;
}

function firstStringArrayAtPaths(
  source: Record<string, unknown>,
  paths: string[][]
): string[] | undefined {
  for (const path of paths) {
    const value = readAtPath(source, path);
    if (!Array.isArray(value)) {
      continue;
    }
    const normalized = value
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');
    if (normalized.length > 0) {
      return normalized;
    }
  }
  return undefined;
}

function readStringCollectionAtPath(
  source: Record<string, unknown>,
  path: string[]
): string[] | undefined {
  const value = readAtPath(source, path);
  if (Array.isArray(value)) {
    const normalized = value
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');
    return normalized.length > 0 ? normalized : undefined;
  }
  if (value && typeof value === 'object') {
    const normalized = Object.values(value as Record<string, unknown>)
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');
    return normalized.length > 0 ? normalized : undefined;
  }
  return undefined;
}

function readNumberCollectionAtPath(
  source: Record<string, unknown>,
  path: string[]
): number[] | undefined {
  const value = readAtPath(source, path);
  if (!Array.isArray(value)) {
    return undefined;
  }
  const normalized: number[] = [];
  for (const entry of value) {
    if (typeof entry === 'number' && Number.isInteger(entry)) {
      normalized.push(entry);
      continue;
    }
    if (typeof entry === 'string' && /^\d+$/u.test(entry.trim())) {
      normalized.push(Number(entry.trim()));
    }
  }
  return normalized.length > 0 ? normalized : undefined;
}

function uniqueNumbers(values: number[]): number[] {
  const set = new Set<number>();
  for (const value of values) {
    if (Number.isInteger(value)) {
      set.add(value);
    }
  }
  return [...set].sort((left, right) => left - right);
}

function readAtPath(source: Record<string, unknown>, path: string[]): unknown {
  let cursor: unknown = source;
  for (const key of path) {
    if (!cursor || typeof cursor !== 'object') {
      return undefined;
    }
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}
