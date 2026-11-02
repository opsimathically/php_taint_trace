import type { DebugPolicyPack } from './types.js';

const POLICY_PACKS: DebugPolicyPack[] = [
  {
    name: 'default',
    categories: ['default'],
    traceSteps: 1,
    watchExpressions: ['$cmd'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'rce',
    categories: ['rce', 'command', 'os_command'],
    traceSteps: 2,
    watchExpressions: ['$cmd', '$command', '$_GET["cmd"]'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'ssrf',
    categories: ['ssrf', 'network'],
    traceSteps: 2,
    watchExpressions: ['$url', '$target', '$_GET["url"]'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'sqli',
    categories: ['sqli', 'sql_injection'],
    traceSteps: 2,
    watchExpressions: ['$sql', '$query', '$_GET["id"]'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'file',
    categories: ['file', 'lfi', 'path_traversal'],
    traceSteps: 2,
    watchExpressions: ['$path', '$filename', '$_GET["file"]'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'xss',
    categories: ['xss'],
    traceSteps: 1,
    watchExpressions: ['$output', '$html', '$_GET["q"]'],
    snapshotContextIds: [0],
    autoCaptureExceptions: true,
  },
  {
    name: 'idor',
    categories: ['idor', 'authorization'],
    traceSteps: 2,
    watchExpressions: ['$userId', '$ownerId', '$_GET["id"]'],
    snapshotContextIds: [0, 1],
    autoCaptureExceptions: true,
  },
];

export function getPolicyPackByName(name: string): DebugPolicyPack {
  const normalized = name.trim().toLowerCase();
  const exact = POLICY_PACKS.find((pack) => pack.name === normalized);
  if (exact) {
    return exact;
  }

  return POLICY_PACKS[0];
}

export function getPolicyPackForCategory(category?: string): DebugPolicyPack {
  const normalized = (category ?? '').trim().toLowerCase();
  if (normalized === '') {
    return getPolicyPackByName('default');
  }

  for (const pack of POLICY_PACKS) {
    if (pack.categories.includes(normalized) || pack.name === normalized) {
      return pack;
    }
  }

  return getPolicyPackByName('default');
}
