export interface ReplayGateProfile {
  name: string;
  categories: string[];
  comparePhase: 'pre' | 'post' | 'post_reset';
  maxDriftDetected: number;
  minOverallScore: number;
  minVariationScore: number;
  deterministicThresholds: {
    allowSnapshotDrift: boolean;
    maxExpressionDriftCount: number;
    allowedExpressionDrift: string[];
  };
}

const REPLAY_GATE_PROFILES: ReplayGateProfile[] = [
  {
    name: 'default',
    categories: ['default'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 1,
    minVariationScore: 1,
    deterministicThresholds: {
      allowSnapshotDrift: false,
      maxExpressionDriftCount: 0,
      allowedExpressionDrift: [],
    },
  },
  {
    name: 'rce',
    categories: ['rce', 'command', 'os_command'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 0.98,
    minVariationScore: 0.95,
    deterministicThresholds: {
      allowSnapshotDrift: false,
      maxExpressionDriftCount: 0,
      allowedExpressionDrift: [],
    },
  },
  {
    name: 'ssrf',
    categories: ['ssrf', 'network'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 0.97,
    minVariationScore: 0.94,
    deterministicThresholds: {
      allowSnapshotDrift: false,
      maxExpressionDriftCount: 0,
      allowedExpressionDrift: [],
    },
  },
  {
    name: 'sqli',
    categories: ['sqli', 'sql_injection'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 0.97,
    minVariationScore: 0.93,
    deterministicThresholds: {
      allowSnapshotDrift: false,
      maxExpressionDriftCount: 1,
      allowedExpressionDrift: ['$lastInsertId'],
    },
  },
  {
    name: 'file',
    categories: ['file', 'lfi', 'path_traversal'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 0.96,
    minVariationScore: 0.92,
    deterministicThresholds: {
      allowSnapshotDrift: true,
      maxExpressionDriftCount: 0,
      allowedExpressionDrift: [],
    },
  },
  {
    name: 'xss',
    categories: ['xss'],
    comparePhase: 'post',
    maxDriftDetected: 1,
    minOverallScore: 0.93,
    minVariationScore: 0.9,
    deterministicThresholds: {
      allowSnapshotDrift: true,
      maxExpressionDriftCount: 1,
      allowedExpressionDrift: ['$output_buffer'],
    },
  },
  {
    name: 'idor',
    categories: ['idor', 'authorization'],
    comparePhase: 'post_reset',
    maxDriftDetected: 0,
    minOverallScore: 0.96,
    minVariationScore: 0.93,
    deterministicThresholds: {
      allowSnapshotDrift: false,
      maxExpressionDriftCount: 1,
      allowedExpressionDrift: ['$requestId'],
    },
  },
];

export function getReplayGateProfileByName(name: string): ReplayGateProfile {
  const normalized = name.trim().toLowerCase();
  const exact = REPLAY_GATE_PROFILES.find((profile) => profile.name === normalized);
  if (exact) {
    return exact;
  }

  return REPLAY_GATE_PROFILES[0];
}

export function getReplayGateProfileForCategory(category?: string): ReplayGateProfile {
  const normalized = (category ?? '').trim().toLowerCase();
  if (normalized === '') {
    return getReplayGateProfileByName('default');
  }

  for (const profile of REPLAY_GATE_PROFILES) {
    if (profile.categories.includes(normalized) || profile.name === normalized) {
      return profile;
    }
  }

  return getReplayGateProfileByName('default');
}
