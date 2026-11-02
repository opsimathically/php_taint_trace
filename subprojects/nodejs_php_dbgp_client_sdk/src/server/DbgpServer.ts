import { EventEmitter } from 'node:events';
import * as net from 'node:net';
import { DbgpProtocolError } from '../core/DbgpProtocolError.js';
import type { DbgpSessionOptions } from './DbgpSession.js';
import { DbgpSession } from './DbgpSession.js';

export interface DbgpServerOptions extends DbgpSessionOptions {
  host?: string;
  port?: number;
  backlog?: number;
}

export class DbgpServer extends EventEmitter {
  private readonly host: string;
  private readonly port: number;
  private readonly backlog?: number;
  private readonly sessionOptions: DbgpSessionOptions;
  private readonly sessions = new Map<string, DbgpSession>();
  private server?: net.Server;
  private counter = 0;

  constructor(options: DbgpServerOptions = {}) {
    super();
    this.host = options.host ?? '127.0.0.1';
    this.port = options.port ?? 9003;
    this.backlog = options.backlog;
    this.sessionOptions = {
      commandTimeoutMs: options.commandTimeoutMs,
      strict: options.strict,
    };
  }

  async start(): Promise<void> {
    if (this.server) {
      return;
    }

    this.server = net.createServer((socket) => {
      const id = `session-${++this.counter}`;
      const session = new DbgpSession(id, socket, this.sessionOptions);
      this.sessions.set(id, session);
      session.once('close', () => {
        this.sessions.delete(id);
        this.emit('sessionClosed', session);
      });
      session.on('error', (error) => {
        this.emit('sessionError', { sessionId: id, error });
      });
      this.emit('session', session);
    });

    this.server.on('error', (error) => {
      this.emit('error', new DbgpProtocolError('TRANSPORT_ERROR', error.message));
    });

    await new Promise<void>((resolve, reject) => {
      if (!this.server) {
        reject(new DbgpProtocolError('TRANSPORT_ERROR', 'Server instance not available.'));
        return;
      }

      this.server.once('listening', () => resolve());
      this.server.once('error', (error) => reject(error));
      this.server.listen(this.port, this.host, this.backlog);
    });
  }

  async stop(): Promise<void> {
    for (const session of this.sessions.values()) {
      session.close();
    }
    this.sessions.clear();

    if (!this.server) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      this.server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });

    this.server = undefined;
  }

  getSessions(): DbgpSession[] {
    return Array.from(this.sessions.values());
  }

  getSessionById(id: string): DbgpSession | undefined {
    return this.sessions.get(id);
  }

  getAddress(): net.AddressInfo | null {
    if (!this.server) {
      return null;
    }

    const address = this.server.address();
    if (!address || typeof address === 'string') {
      return null;
    }

    return address;
  }

  async waitForNextSession(timeoutMs = 30000): Promise<DbgpSession> {
    const existing = this.getSessions()[0];
    if (existing) {
      return existing;
    }

    return new Promise<DbgpSession>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.off('session', onSession);
        reject(new DbgpProtocolError('COMMAND_TIMEOUT', 'Timed out waiting for inbound DBGp session.'));
      }, timeoutMs);

      const onSession = (session: DbgpSession) => {
        clearTimeout(timeout);
        resolve(session);
      };

      this.once('session', onSession);
    });
  }
}
