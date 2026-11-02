import { describe, expect, it } from 'vitest';
import { DbgpProtocolError } from '../../src/core/DbgpProtocolError.js';
import { parseDbgpPacket } from '../../src/protocol/xml.js';

describe('parseDbgpPacket', () => {
  it('parses init packet with required attributes', () => {
    const packet = parseDbgpPacket(
      '<init appid="42" idekey="sdk" session="abc" language="PHP" protocol_version="1.0" fileuri="file:///var/www/index.php"><engine version="3.3.0" name="Xdebug"></engine></init>'
    );

    expect(packet.kind).toBe('init');
    if (packet.kind !== 'init') {
      throw new Error('Expected init packet');
    }
    expect(packet.packet.appId).toBe('42');
    expect(packet.packet.language).toBe('PHP');
    expect(packet.packet.engineName).toBe('Xdebug');
  });

  it('parses response with transaction and status', () => {
    const packet = parseDbgpPacket(
      '<response command="status" transaction_id="7" status="break" reason="ok"></response>'
    );

    expect(packet.kind).toBe('response');
    if (packet.kind !== 'response') {
      throw new Error('Expected response packet');
    }
    expect(packet.packet.transactionId).toBe(7);
    expect(packet.packet.status).toBe('break');
  });

  it('throws for malformed response without transaction id', () => {
    expect(() => parseDbgpPacket('<response command="status"></response>')).toThrowError(
      DbgpProtocolError
    );
  });
});
