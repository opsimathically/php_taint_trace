export type DbgpProtocolErrorCode =
  | 'FRAME_PARSE_ERROR'
  | 'XML_PARSE_ERROR'
  | 'INVALID_INIT_PACKET'
  | 'INVALID_RESPONSE_PACKET'
  | 'SESSION_CLOSED'
  | 'COMMAND_TIMEOUT'
  | 'UNSUPPORTED_OPERATION'
  | 'TRANSPORT_ERROR';

export class DbgpProtocolError extends Error {
  readonly code: DbgpProtocolErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: DbgpProtocolErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'DbgpProtocolError';
    this.code = code;
    this.details = details;
  }
}
