import { DbgpProtocolError } from '../core/DbgpProtocolError.js';
import {
  DbgpInitPacket,
  DbgpNotifyPacket,
  DbgpParsedPacket,
  DbgpResponsePacket,
  DbgpStreamPacket,
} from './types.js';

interface RootNode {
  name: string;
  attributes: Record<string, string>;
  innerXml: string;
}

export function parseDbgpPacket(xml: string): DbgpParsedPacket {
  const root = parseRootNode(xml);
  switch (root.name) {
    case 'init':
      return { kind: 'init', packet: parseInitPacket(root, xml) };
    case 'response':
      return { kind: 'response', packet: parseResponsePacket(root, xml) };
    case 'stream':
      return { kind: 'stream', packet: parseStreamPacket(root, xml) };
    case 'notify':
      return { kind: 'notify', packet: parseNotifyPacket(root, xml) };
    default:
      throw new DbgpProtocolError('XML_PARSE_ERROR', `Unsupported DBGp root element: ${root.name}`, {
        root: root.name,
      });
  }
}

export function parseRootNode(xml: string): RootNode {
  const trimmed = xml.trim().replace(/^<\?xml[^>]*\?>\s*/i, '');

  const standard = /^<([A-Za-z0-9:_-]+)\b([^>]*)>([\s\S]*)<\/\1>\s*$/u.exec(trimmed);
  if (standard) {
    return {
      name: standard[1],
      attributes: parseAttributes(standard[2] ?? ''),
      innerXml: standard[3] ?? '',
    };
  }

  const selfClosing = /^<([A-Za-z0-9:_-]+)\b([^>]*)\/>\s*$/u.exec(trimmed);
  if (selfClosing) {
    return {
      name: selfClosing[1],
      attributes: parseAttributes(selfClosing[2] ?? ''),
      innerXml: '',
    };
  }

  throw new DbgpProtocolError('XML_PARSE_ERROR', 'Could not parse DBGp XML payload.', {
    payloadPreview: trimmed.slice(0, 240),
  });
}

export function parseAttributes(source: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const regex = /([A-Za-z0-9:_-]+)\s*=\s*"([^"]*)"/g;

  let match: RegExpExecArray | null;
  while ((match = regex.exec(source)) !== null) {
    attributes[match[1]] = decodeXmlEntities(match[2]);
  }

  return attributes;
}

function parseInitPacket(root: RootNode, rawXml: string): DbgpInitPacket {
  const required = ['appid', 'language', 'protocol_version', 'fileuri'] as const;
  for (const key of required) {
    if (!root.attributes[key]) {
      throw new DbgpProtocolError('INVALID_INIT_PACKET', `Missing required init attribute: ${key}`, {
        attributes: root.attributes,
      });
    }
  }

  const engine = firstTagAttributes(root.innerXml, 'engine');

  return {
    appId: root.attributes.appid,
    ideKey: root.attributes.idekey,
    session: root.attributes.session,
    thread: root.attributes.thread,
    parent: root.attributes.parent,
    language: root.attributes.language,
    protocolVersion: root.attributes.protocol_version,
    fileUri: root.attributes.fileuri,
    engineName: engine?.name,
    engineVersion: engine?.version,
    rawXml,
    innerXml: root.innerXml,
    attributes: root.attributes,
  };
}

function parseResponsePacket(root: RootNode, rawXml: string): DbgpResponsePacket {
  const txRaw = root.attributes.transaction_id;
  if (!txRaw || !/^\d+$/.test(txRaw)) {
    throw new DbgpProtocolError('INVALID_RESPONSE_PACKET', 'Response packet missing valid transaction_id.', {
      attributes: root.attributes,
    });
  }

  const errorPayload = parseErrorPayload(root.innerXml);

  return {
    rawXml,
    innerXml: root.innerXml,
    attributes: root.attributes,
    transactionId: Number.parseInt(txRaw, 10),
    command: root.attributes.command,
    status: root.attributes.status,
    reason: root.attributes.reason,
    error: errorPayload,
  };
}

function parseStreamPacket(root: RootNode, rawXml: string): DbgpStreamPacket {
  return {
    rawXml,
    innerXml: root.innerXml,
    attributes: root.attributes,
    type: root.attributes.type,
    encoding: root.attributes.encoding,
    payload: root.innerXml.trim(),
  };
}

function parseNotifyPacket(root: RootNode, rawXml: string): DbgpNotifyPacket {
  return {
    rawXml,
    innerXml: root.innerXml,
    attributes: root.attributes,
    name: root.attributes.name,
  };
}

function parseErrorPayload(innerXml: string): { code?: string; message?: string } | undefined {
  const errorTag = /<error\b([^>]*)>([\s\S]*?)<\/error>/u.exec(innerXml);
  if (!errorTag) {
    return undefined;
  }

  const errorAttributes = parseAttributes(errorTag[1] ?? '');
  const messageTag = /<message>([\s\S]*?)<\/message>/u.exec(errorTag[2] ?? '');

  return {
    code: errorAttributes.code,
    message: messageTag ? decodeXmlEntities(stripCdata(messageTag[1]).trim()) : undefined,
  };
}

function firstTagAttributes(xml: string, tagName: string): Record<string, string> | undefined {
  const match = new RegExp(`<${tagName}\\b([^>]*)>`, 'u').exec(xml);
  if (!match) {
    return undefined;
  }

  return parseAttributes(match[1] ?? '');
}

function stripCdata(value: string): string {
  return value.replace(/^<!\[CDATA\[/, '').replace(/\]\]>$/, '');
}

function decodeXmlEntities(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}
