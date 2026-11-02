# Protocol Architecture

## Overview
The SDK is structured in layered components:

1. `DbgpFrameCodec`  
   Handles DBGp framing (`length\0payload\0`) and incremental buffering.

2. XML Packet Parsing  
   `parseDbgpPacket()` parses root packet kinds:
   - `init`
   - `response`
   - `stream`
   - `notify`

3. `DbgpSession`  
   Manages one TCP connection/session:
   - state machine (`connecting|ready|busy|detached|closed|error`)
   - transaction id assignment
   - command send and response correlation
   - inbound/outbound transcript capture for forensic and replay diagnostics
   - timeout and transport error handling

4. `DbgpServer`  
   Listener that accepts inbound sessions and tracks active session objects.

5. `PhpDebugInspector`  
   High-level command abstraction for common debugger operations.

## Session Lifecycle
1. TCP accept.
2. Receive and validate `init` packet.
3. Session enters `ready`.
4. Commands sent with `-i <transaction_id>`.
5. Response packets matched to pending command promises.
6. On close/error: pending commands reject and session transitions terminally.

## Command Pipeline
- Builder: `buildCommandLine(command, tx, options, data?)`
- Wire format: command line terminated by null byte.
- Correlation key: integer transaction id.
- Timeout policy: per command (default 5000ms, configurable).

## Failure Modes
- Framing errors -> `FRAME_PARSE_ERROR`
- XML parse errors -> `XML_PARSE_ERROR`
- Invalid init/response packets -> typed protocol errors
- Write/read transport failures -> `TRANSPORT_ERROR`
- Missing response within timeout -> `COMMAND_TIMEOUT`
- Session closes with pending commands -> `SESSION_CLOSED`

## Strictness Policy
Strict mode is enabled by default:
- malformed protocol payloads become explicit errors
- session can be closed on unrecoverable protocol issues
- command-level response errors surface as exceptions in inspector methods
