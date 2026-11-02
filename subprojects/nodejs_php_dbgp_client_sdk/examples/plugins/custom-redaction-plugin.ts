import type { TranscriptRedactionPlugin } from '../../src/index.js';

const plugin: TranscriptRedactionPlugin = {
  name: 'custom-redaction',
  redact(context) {
    if (typeof context.value !== 'string') {
      return undefined;
    }

    if (context.value.includes('DBGPCMD=')) {
      return {
        handled: true,
        value: context.value.replace(/DBGPCMD=[^\s]*/gu, `DBGPCMD=${context.replacement}`),
      };
    }

    return undefined;
  },
};

export default plugin;
