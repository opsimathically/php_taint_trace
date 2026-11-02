export type DbgpSessionState = 'connecting' | 'ready' | 'busy' | 'detached' | 'closed' | 'error';

export interface DbgpInitPacket {
  appId: string;
  ideKey?: string;
  session?: string;
  thread?: string;
  parent?: string;
  language: string;
  protocolVersion: string;
  fileUri: string;
  engineName?: string;
  engineVersion?: string;
  rawXml: string;
  innerXml: string;
  attributes: Record<string, string>;
}

export interface DbgpPacketBase {
  rawXml: string;
  innerXml: string;
  attributes: Record<string, string>;
}

export interface DbgpErrorPayload {
  code?: string;
  message?: string;
}

export interface DbgpResponsePacket extends DbgpPacketBase {
  transactionId: number;
  command?: string;
  status?: string;
  reason?: string;
  error?: DbgpErrorPayload;
}

export interface DbgpStreamPacket extends DbgpPacketBase {
  type?: string;
  encoding?: string;
  payload: string;
}

export interface DbgpNotifyPacket extends DbgpPacketBase {
  name?: string;
}

export type DbgpParsedPacket =
  | { kind: 'init'; packet: DbgpInitPacket }
  | { kind: 'response'; packet: DbgpResponsePacket }
  | { kind: 'stream'; packet: DbgpStreamPacket }
  | { kind: 'notify'; packet: DbgpNotifyPacket };
