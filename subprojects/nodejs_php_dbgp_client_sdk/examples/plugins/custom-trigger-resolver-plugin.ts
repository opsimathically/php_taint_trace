import type { CandidateTriggerResolverPlugin } from '../../src/index.js';

const plugin: CandidateTriggerResolverPlugin = {
  name: 'custom-trigger-resolver',
  resolve(context) {
    const base = context.template.replaceAll('${candidateId}', context.candidate.candidateId);
    const mode = context.candidate.sinkCategory ?? 'unknown';
    return `${base} --header 'X-Debug-Candidate: ${context.candidate.candidateId}' --header 'X-Debug-Category: ${mode}'`;
  },
};

export default plugin;
