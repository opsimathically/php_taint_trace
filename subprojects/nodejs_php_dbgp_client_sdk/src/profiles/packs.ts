import type { CaptureProfile } from './types.js';

const CAPTURE_PROFILES: CaptureProfile[] = [
  {
    name: 'default',
    categories: ['default'],
    description: 'Balanced defaults for generic candidate triage.',
    traceAction: 'step_over',
    traceSteps: 1,
    watchExpressions: ['$cmd'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'rce',
    categories: ['rce', 'command', 'os_command'],
    description: 'Prioritize command-state variables around potential RCE sinks.',
    traceAction: 'step_over',
    traceSteps: 3,
    watchExpressions: ['$cmd', '$command', '$_GET["cmd"]'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'ssrf',
    categories: ['ssrf', 'network'],
    description: 'Prioritize outbound URL and transport context for SSRF.',
    traceAction: 'step_over',
    traceSteps: 3,
    watchExpressions: ['$url', '$target', '$_GET["url"]'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'sqli',
    categories: ['sqli', 'sql_injection'],
    description: 'Track SQL query construction and selected input keys.',
    traceAction: 'step_over',
    traceSteps: 3,
    watchExpressions: ['$sql', '$query', '$_GET["id"]'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'file',
    categories: ['file', 'lfi', 'path_traversal'],
    description: 'Track path construction state and target file variables.',
    traceAction: 'step_over',
    traceSteps: 3,
    watchExpressions: ['$path', '$filename', '$_GET["file"]'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'xss',
    categories: ['xss'],
    description: 'Track output buffer state around reflected/stored XSS sinks.',
    traceAction: 'step_over',
    traceSteps: 2,
    watchExpressions: ['$output', '$html', '$_GET["q"]'],
    snapshotContextIds: [0],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
  {
    name: 'idor',
    categories: ['idor', 'authorization'],
    description: 'Track principal/resource identifiers for access-control checks.',
    traceAction: 'step_over',
    traceSteps: 3,
    watchExpressions: ['$userId', '$ownerId', '$_GET["id"]'],
    snapshotContextIds: [0, 1],
    stopOnStatuses: ['stopping', 'stopped', 'detached', 'error'],
    autoCaptureExceptions: true,
  },
];

export function getCaptureProfileByName(name: string): CaptureProfile {
  const normalized = name.trim().toLowerCase();
  const exact = CAPTURE_PROFILES.find((profile) => profile.name === normalized);
  if (exact) {
    return exact;
  }

  return CAPTURE_PROFILES[0];
}

export function getCaptureProfileForCategory(category?: string): CaptureProfile {
  const normalized = (category ?? '').trim().toLowerCase();
  if (normalized === '') {
    return getCaptureProfileByName('default');
  }

  for (const profile of CAPTURE_PROFILES) {
    if (profile.categories.includes(normalized) || profile.name === normalized) {
      return profile;
    }
  }

  return getCaptureProfileByName('default');
}
