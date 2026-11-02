import type { TranscriptRedactionPlugin } from '../../../src/index.js';

const plugin: TranscriptRedactionPlugin = {
  name: 'stream-redaction-plugin',
  redact(context) {
    if (typeof context.value !== 'string') {
      return undefined;
    }
    if (!context.value.includes('APIKEY=')) {
      return undefined;
    }

    return {
      handled: true,
      value: context.value.replace(/APIKEY=[A-Za-z0-9._-]+/gu, `APIKEY=${context.replacement}`),
    };
  },
};

export default plugin;
