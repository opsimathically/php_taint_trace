import type { CandidateRecord } from '../bridge/types.js';
import type { CandidateTriggerResolverPlugin } from './types.js';

export function resolveCandidateTriggerCommand(
  template: string,
  candidate: CandidateRecord,
  plugins: CandidateTriggerResolverPlugin[] = []
): string {
  for (const plugin of plugins) {
    const resolved = plugin.resolve({ template, candidate });
    if (typeof resolved === 'string' && resolved.trim() !== '') {
      return resolved;
    }
  }

  return template
    .replaceAll('${candidateId}', shellEscape(candidate.candidateId))
    .replaceAll('${sinkCategory}', shellEscape(candidate.sinkCategory ?? ''))
    .replaceAll('${sinkName}', shellEscape(candidate.sinkName ?? ''))
    .replaceAll('${requestUri}', shellEscape(candidate.requestUri ?? ''))
    .replaceAll('${correlationId}', shellEscape(candidate.correlationId ?? candidate.candidateId))
    .replaceAll('${requestId}', shellEscape(candidate.requestId ?? ''))
    .replaceAll('${findingId}', shellEscape(candidate.findingId ?? ''));
}

export function shellEscape(value: string): string {
  const escaped = value.replaceAll("'", "'\"'\"'");
  return `'${escaped}'`;
}
