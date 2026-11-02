import { createHash, createHmac } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';

export interface ReplayManifestEntryInput {
  kind: string;
  path: string;
}

export interface ReplayManifestEntry {
  kind: string;
  path: string;
  sha256: string;
  size: number;
}

export interface ReplayArtifactManifest {
  schema: 'dbgp-replay-manifest.v1';
  createdAt: string;
  entries: ReplayManifestEntry[];
  signature?: ReplayArtifactManifestSignature;
}

export interface ReplayArtifactManifestSignature {
  algorithm: 'hmac-sha256';
  digest: string;
  keyId?: string;
}

export interface ReplayArtifactManifestVerificationMismatch {
  kind: string;
  path: string;
  reason: 'missing' | 'sha256_mismatch' | 'size_mismatch';
  expected?: string | number;
  actual?: string | number;
}

export interface ReplayArtifactManifestVerificationResult {
  ok: boolean;
  checked: number;
  mismatches: ReplayArtifactManifestVerificationMismatch[];
  signature: {
    present: boolean;
    verified: boolean;
    error?: string;
  };
}

export function createReplayArtifactManifest(
  inputs: ReplayManifestEntryInput[],
  options?: {
    baseDir?: string;
    createdAt?: string;
    signature?: {
      hmacSecret: string;
      keyId?: string;
    };
  }
): ReplayArtifactManifest {
  const baseDir = options?.baseDir ? path.resolve(options.baseDir) : process.cwd();
  const createdAt = options?.createdAt ?? new Date().toISOString();
  const entries = inputs.map((entry) => buildEntry(entry, baseDir));
  const manifest: ReplayArtifactManifest = {
    schema: 'dbgp-replay-manifest.v1',
    createdAt,
    entries,
  };
  if (options?.signature?.hmacSecret) {
    manifest.signature = signReplayArtifactManifest(manifest, options.signature.hmacSecret, {
      keyId: options.signature.keyId,
    });
  }
  return manifest;
}

export function verifyReplayArtifactManifest(
  manifest: ReplayArtifactManifest,
  options?: {
    baseDir?: string;
    hmacSecret?: string;
  }
): ReplayArtifactManifestVerificationResult {
  const baseDir = options?.baseDir ? path.resolve(options.baseDir) : process.cwd();
  const mismatches: ReplayArtifactManifestVerificationMismatch[] = [];
  const signature = {
    present: Boolean(manifest.signature),
    verified: false,
    error: undefined as string | undefined,
  };

  for (const entry of manifest.entries) {
    const resolvedPath = resolveEntryPath(entry.path, baseDir);
    try {
      const content = readFileSync(resolvedPath);
      const stat = statSync(resolvedPath);
      const actualHash = computeSha256(content);
      if (actualHash !== entry.sha256) {
        mismatches.push({
          kind: entry.kind,
          path: entry.path,
          reason: 'sha256_mismatch',
          expected: entry.sha256,
          actual: actualHash,
        });
      }
      if (stat.size !== entry.size) {
        mismatches.push({
          kind: entry.kind,
          path: entry.path,
          reason: 'size_mismatch',
          expected: entry.size,
          actual: stat.size,
        });
      }
    } catch {
      mismatches.push({
        kind: entry.kind,
        path: entry.path,
        reason: 'missing',
      });
    }
  }

  if (manifest.signature) {
    if (!options?.hmacSecret) {
      signature.error = 'signature_present_but_no_secret_provided';
    } else {
      const expected = signReplayArtifactManifest(manifest, options.hmacSecret, {
        keyId: manifest.signature.keyId,
      }).digest;
      if (expected !== manifest.signature.digest) {
        signature.error = 'signature_digest_mismatch';
      } else {
        signature.verified = true;
      }
    }
  }

  return {
    ok: mismatches.length === 0 && (!signature.present || signature.verified),
    checked: manifest.entries.length,
    mismatches,
    signature,
  };
}

export function signReplayArtifactManifest(
  manifest: ReplayArtifactManifest,
  hmacSecret: string,
  options?: {
    keyId?: string;
  }
): ReplayArtifactManifestSignature {
  const payload = JSON.stringify({
    schema: manifest.schema,
    createdAt: manifest.createdAt,
    entries: manifest.entries,
  });
  const signatureDigest = createHmac('sha256', hmacSecret)
    .update(payload, 'utf8')
    .digest('hex');
  const signature: ReplayArtifactManifestSignature = {
    algorithm: 'hmac-sha256',
    digest: signatureDigest,
  };
  if (options?.keyId) {
    signature.keyId = options.keyId;
  }
  return signature;
}

function buildEntry(entry: ReplayManifestEntryInput, baseDir: string): ReplayManifestEntry {
  const resolvedPath = path.resolve(entry.path);
  const content = readFileSync(resolvedPath);
  const stat = statSync(resolvedPath);
  const relativePath = path.relative(baseDir, resolvedPath);
  return {
    kind: entry.kind,
    path: isSafeRelativePath(relativePath) ? normalizePath(relativePath) : normalizePath(resolvedPath),
    sha256: computeSha256(content),
    size: stat.size,
  };
}

function resolveEntryPath(entryPath: string, baseDir: string): string {
  if (path.isAbsolute(entryPath)) {
    return path.resolve(entryPath);
  }
  return path.resolve(baseDir, entryPath);
}

function computeSha256(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function isSafeRelativePath(value: string): boolean {
  return value !== '' && !value.startsWith('..');
}

function normalizePath(value: string): string {
  return value.split(path.sep).join('/');
}
