import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';
import { DbgpProtocolError } from '../core/DbgpProtocolError.js';
import { buildCommandLine, type DbgpCommandOptions } from '../protocol/command.js';
import { DbgpFrameCodec } from '../protocol/DbgpFrameCodec.js';
import type {
  DbgpInitPacket,
  DbgpNotifyPacket,
  DbgpResponsePacket,
  DbgpSessionState,
  DbgpStreamPacket,
} from '../protocol/types.js';
import { parseDbgpPacket } from '../protocol/xml.js';

interface PendingCommand {
  readonly resolve: (packet: DbgpResponsePacket) => void;
  readonly reject: (error: Error) => void;
  readonly timeout: NodeJS.Timeout;
}

export interface DbgpTranscriptEntry {
  timestamp: string;
  direction: 'in' | 'out';
  type: 'command' | 'response' | 'stream' | 'notify' | 'init' | 'error';
  payload: unknown;
}

export interface DbgpSessionOptions {
  commandTimeoutMs?: number;
  strict?: boolean;
}

export class DbgpSession extends EventEmitter {
  private readonly socket: Socket;
  private readonly codec = new DbgpFrameCodec();
  private readonly strict: boolean;
  private readonly commandTimeoutMs: number;
  private readonly pending = new Map<number, PendingCommand>();
  private nextTransactionId = 1;
  private initPacket?: DbgpInitPacket;
  private state: DbgpSessionState = 'connecting';
  private readonly transcript: DbgpTranscriptEntry[] = [];

  readonly id: string;

  constructor(id: string, socket: Socket, options: DbgpSessionOptions = {}) {
    super();
    this.id = id;
    this.socket = socket;
    this.strict = options.strict ?? true;
    this.commandTimeoutMs = options.commandTimeoutMs ?? 5000;
    this.bindSocket();
  }

  getState(): DbgpSessionState {
    return this.state;
  }

  getInitPacket(): DbgpInitPacket | undefined {
    return this.initPacket;
  }

  getTranscript(): ReadonlyArray<DbgpTranscriptEntry> {
    return this.transcript;
  }

  clearTranscript(): void {
    this.transcript.length = 0;
  }

  async waitForInit(timeoutMs = 5000): Promise<DbgpInitPacket> {
    if (this.initPacket) {
      return this.initPacket;
    }

    return new Promise<DbgpInitPacket>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.off('init', onInit);
        reject(new DbgpProtocolError('COMMAND_TIMEOUT', 'Timed out waiting for DBGp init packet.'));
      }, timeoutMs);

      const onInit = (packet: DbgpInitPacket) => {
        clearTimeout(timeout);
        resolve(packet);
      };

      this.once('init', onInit);
    });
  }

  async sendCommand(
    command: string,
    options: DbgpCommandOptions = {},
    data?: string,
    timeoutMs = this.commandTimeoutMs
  ): Promise<DbgpResponsePacket> {
    if (this.state === 'detached' || this.state === 'closed') {
      throw new DbgpProtocolError('SESSION_CLOSED', 'Cannot send command on closed DBGp session.');
    }

    const transactionId = this.nextTransactionId++;
    const commandLine = buildCommandLine(command, transactionId, options, data);
    this.pushTranscript({
      direction: 'out',
      type: 'command',
      payload: { command, commandLine, transactionId, options },
    });

    return new Promise<DbgpResponsePacket>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(transactionId);
        reject(
          new DbgpProtocolError('COMMAND_TIMEOUT', 'DBGp command timed out.', {
            command,
            transactionId,
          })
        );
      }, timeoutMs);

      this.pending.set(transactionId, { resolve, reject, timeout });

      this.socket.write(`${commandLine}\u0000`, (error) => {
        if (!error) {
          return;
        }

        const pending = this.pending.get(transactionId);
        if (!pending) {
          return;
        }

        clearTimeout(pending.timeout);
        this.pending.delete(transactionId);
        pending.reject(
          new DbgpProtocolError('TRANSPORT_ERROR', 'Failed writing DBGp command to socket.', {
            command,
            transactionId,
            message: error.message,
          })
        );
      });
    });
  }

  close(): void {
    if (!this.socket.destroyed) {
      this.socket.destroy();
    }
  }

  private bindSocket(): void {
    this.socket.on('data', (chunk) => {
      try {
        const frames = this.codec.feed(chunk);
        for (const frame of frames) {
          this.handleFrame(frame);
        }
      } catch (error) {
        this.handleProtocolError(error);
      }
    });

    this.socket.on('error', (error) => {
      this.setState('error');
      this.emit('error', new DbgpProtocolError('TRANSPORT_ERROR', error.message));
    });

    this.socket.on('close', () => {
      this.rejectPending(new DbgpProtocolError('SESSION_CLOSED', 'DBGp session socket closed.'));
      this.setState('closed');
      this.emit('close');
    });
  }

  private handleFrame(frame: string): void {
    const parsed = parseDbgpPacket(frame);
    switch (parsed.kind) {
      case 'init':
        this.initPacket = parsed.packet;
        this.pushTranscript({ direction: 'in', type: 'init', payload: parsed.packet });
        this.setState('ready');
        this.emit('init', parsed.packet);
        break;
      case 'response':
        this.pushTranscript({ direction: 'in', type: 'response', payload: parsed.packet });
        this.handleResponse(parsed.packet);
        this.emit('response', parsed.packet);
        break;
      case 'stream':
        this.pushTranscript({ direction: 'in', type: 'stream', payload: parsed.packet });
        this.emit('stream', parsed.packet as DbgpStreamPacket);
        break;
      case 'notify':
        this.pushTranscript({ direction: 'in', type: 'notify', payload: parsed.packet });
        this.emit('notify', parsed.packet as DbgpNotifyPacket);
        break;
      default:
        if (this.strict) {
          throw new DbgpProtocolError('UNSUPPORTED_OPERATION', 'Unsupported DBGp packet kind.');
        }
    }
  }

  private handleResponse(packet: DbgpResponsePacket): void {
    if (packet.status === 'running' || packet.status === 'starting') {
      this.setState('busy');
    } else if (packet.status === 'stopping' || packet.status === 'stopped') {
      this.setState('detached');
    } else if (packet.status === 'break' || packet.status === 'interactive') {
      this.setState('ready');
    }

    const pending = this.pending.get(packet.transactionId);
    if (!pending) {
      return;
    }

    clearTimeout(pending.timeout);
    this.pending.delete(packet.transactionId);
    pending.resolve(packet);
  }

  private handleProtocolError(error: unknown): void {
    const normalized =
      error instanceof DbgpProtocolError
        ? error
        : new DbgpProtocolError('FRAME_PARSE_ERROR', 'Unhandled DBGp frame parse error.', {
            message: error instanceof Error ? error.message : String(error),
          });
    this.setState('error');
    this.pushTranscript({ direction: 'in', type: 'error', payload: normalized });
    this.emit('error', normalized);
    if (this.strict) {
      this.close();
    }
  }

  private setState(state: DbgpSessionState): void {
    if (this.state === state) {
      return;
    }

    this.state = state;
    this.emit('state', state);
  }

  private rejectPending(error: DbgpProtocolError): void {
    for (const [transactionId, pending] of this.pending.entries()) {
      clearTimeout(pending.timeout);
      this.pending.delete(transactionId);
      pending.reject(error);
    }
  }

  private pushTranscript(entry: Omit<DbgpTranscriptEntry, 'timestamp'>): void {
    this.transcript.push({
      timestamp: new Date().toISOString(),
      ...entry,
    });
  }
}
