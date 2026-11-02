import { DbgpProtocolError } from '../core/DbgpProtocolError.js';

export class DbgpFrameCodec {
  private buffer = Buffer.alloc(0);

  feed(chunk: Buffer): string[] {
    if (chunk.length === 0) {
      return [];
    }

    this.buffer = Buffer.concat([this.buffer, chunk]);
    const frames: string[] = [];

    while (true) {
      const lengthSep = this.buffer.indexOf(0x00);
      if (lengthSep === -1) {
        break;
      }

      const lengthToken = this.buffer.subarray(0, lengthSep).toString('ascii').trim();
      if (!/^\d+$/.test(lengthToken)) {
        throw new DbgpProtocolError('FRAME_PARSE_ERROR', 'DBGp frame length is invalid.', {
          lengthToken,
        });
      }

      const payloadLength = Number.parseInt(lengthToken, 10);
      const frameTotal = lengthSep + 1 + payloadLength + 1;
      if (this.buffer.length < frameTotal) {
        break;
      }

      const payloadStart = lengthSep + 1;
      const payloadEnd = payloadStart + payloadLength;
      const trailingByte = this.buffer[payloadEnd];
      if (trailingByte !== 0x00) {
        throw new DbgpProtocolError('FRAME_PARSE_ERROR', 'DBGp frame trailing delimiter missing.', {
          payloadLength,
        });
      }

      const payload = this.buffer.subarray(payloadStart, payloadEnd).toString('utf8');
      frames.push(payload);
      this.buffer = this.buffer.subarray(frameTotal);
    }

    return frames;
  }

  static encode(payload: string): Buffer {
    const payloadBuffer = Buffer.from(payload, 'utf8');
    return Buffer.concat([
      Buffer.from(String(payloadBuffer.length), 'ascii'),
      Buffer.from([0x00]),
      payloadBuffer,
      Buffer.from([0x00]),
    ]);
  }
}
