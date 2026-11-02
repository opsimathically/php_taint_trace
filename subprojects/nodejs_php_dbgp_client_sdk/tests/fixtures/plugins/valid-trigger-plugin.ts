import type { CandidateTriggerResolverPlugin } from '../../../src/index.js';

const plugin: CandidateTriggerResolverPlugin = {
  name: 'valid-trigger-plugin',
  resolve() {
    return "echo 'plugin-resolved'";
  },
};

export default plugin;
