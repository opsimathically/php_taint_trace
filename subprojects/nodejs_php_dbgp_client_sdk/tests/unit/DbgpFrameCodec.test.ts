import { describe, expect, it } from 'vitest';
import { DbgpProtocolError } from '../../src/core/DbgpProtocolError.js';
import { DbgpFrameCodec } from '../../src/protocol/DbgpFrameCodec.js';

describe('DbgpFrameCodec', () => {
  it('parses frames across partial chunks', () => {
    const codec = new DbgpFrameCodec();
    const frame = DbgpFrameCodec.encode('<init appid="1" language="PHP" protocol_version="1.0" fileuri="file:///a.php"/>');

    const chunk1 = frame.subarray(0, 6);
    const chunk2 = frame.subarray(6);

    expect(codec.feed(chunk1)).toEqual([]);
    const frames = codec.feed(chunk2);
    expect(frames).toHaveLength(1);
    expect(frames[0]).toContain('<init');
  });

  it('throws on invalid length token', () => {
    const codec = new DbgpFrameCodec();
    expect(() => codec.feed(Buffer.from('bad\x00hello\x00', 'binary'))).toThrowError(DbgpProtocolError);
  });

  it('encodes payload with length and delimiters', () => {
    const payload = '<response transaction_id="1"></response>';
    const encoded = DbgpFrameCodec.encode(payload);
    const asText = encoded.toString('binary');
    expect(asText.startsWith(String(Buffer.byteLength(payload)))).toBe(true);
    expect(asText.endsWith('\x00')).toBe(true);
  });
});
