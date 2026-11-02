export interface DbgpCommandOptions {
  [key: string]: string | number | boolean | undefined;
}

export function buildCommandLine(
  command: string,
  transactionId: number,
  options: DbgpCommandOptions = {},
  data?: string
): string {
  const segments: string[] = [command, '-i', String(transactionId)];

  const keys = Object.keys(options).sort();
  for (const key of keys) {
    const raw = options[key];
    if (raw === undefined) {
      continue;
    }

    const normalizedKey = key.startsWith('-') ? key.slice(1) : key;
    const value = typeof raw === 'boolean' ? (raw ? '1' : '0') : String(raw);
    segments.push(`-${normalizedKey}`, value);
  }

  if (typeof data === 'string') {
    segments.push('--', Buffer.from(data, 'utf8').toString('base64'));
  }

  return segments.join(' ');
}
