import type { DbgpTranscriptEntry } from '../server/DbgpSession.js';
import type { TranscriptRedactionPlugin } from '../plugins/types.js';
import type { TranscriptRedactionOptions } from './types.js';

const DEFAULT_KEYS = [
  'password',
  'passwd',
  'token',
  'secret',
  'authorization',
  'cookie',
  'set-cookie',
  'ssh_password',
  'sudopassword',
];

const DEFAULT_PATTERNS = [
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gu,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*['"]?([A-Za-z0-9\-._~+/=]{8,})/giu,
];

export function redactTranscriptEntries(
  entries: ReadonlyArray<DbgpTranscriptEntry>,
  options: TranscriptRedactionOptions = {}
): DbgpTranscriptEntry[] {
  const replacement = options.replacement ?? '[REDACTED]';
  const keys = new Set((options.sensitiveKeys ?? DEFAULT_KEYS).map((value) => value.toLowerCase()));
  const patterns = options.sensitiveValuePatterns ?? DEFAULT_PATTERNS;
  const plugins = options.plugins ?? [];

  return entries.map((entry) => ({
    ...entry,
    payload: redactUnknown(entry.payload, {
      keys,
      patterns,
      plugins,
      replacement,
      path: '',
    }),
  }));
}

interface RedactContext {
  keys: Set<string>;
  patterns: RegExp[];
  plugins: TranscriptRedactionPlugin[];
  replacement: string;
  path: string;
  key?: string;
}

function redactUnknown(value: unknown, context: RedactContext): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    const plugin = applyPlugins(value, context);
    if (plugin.handled) {
      return plugin.value;
    }
    return redactString(value, context.patterns, context.replacement);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      redactUnknown(item, {
        ...context,
        path: `${context.path}[${index}]`,
        key: String(index),
      })
    );
  }

  if (typeof value === 'object') {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const [key, item] of Object.entries(input)) {
      const lowered = key.toLowerCase();
      const pathForKey = context.path ? `${context.path}.${key}` : key;

      const plugin = applyPlugins(item, {
        ...context,
        key,
        path: pathForKey,
      });
      if (plugin.handled) {
        output[key] = plugin.value;
        continue;
      }

      if (context.keys.has(lowered)) {
        output[key] = context.replacement;
        continue;
      }

      output[key] = redactUnknown(item, {
        ...context,
        path: pathForKey,
        key,
      });
    }

    return output;
  }

  return value;
}

function redactString(value: string, patterns: RegExp[], replacement: string): string {
  let result = value;
  for (const pattern of patterns) {
    result = result.replace(pattern, replacement);
  }

  return result;
}

function applyPlugins(value: unknown, context: RedactContext): { handled: boolean; value: unknown } {
  for (const plugin of context.plugins) {
    const outcome = plugin.redact({
      path: context.path,
      key: context.key,
      value,
      replacement: context.replacement,
    });
    if (outcome?.handled) {
      return { handled: true, value: outcome.value };
    }
  }

  return { handled: false, value };
}
