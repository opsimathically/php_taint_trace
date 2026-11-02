import { parseAttributes, parseRootNode } from '../protocol/xml.js';
import type {
  DebugBreakpointInfo,
  DebugContextDescriptor,
  DebugFeatureInfo,
  DebugProperty,
  DebugStackFrame,
} from './types.js';

const STACK_TAG = /<stack\b([^>]*?)(?:\/>|>([\s\S]*?)<\/stack>)/gu;
const CONTEXT_TAG = /<context\b([^>]*?)\/>/gu;
const BREAKPOINT_TAG = /<breakpoint\b([^>]*?)(?:\/>|>([\s\S]*?)<\/breakpoint>)/gu;

export function parseStackFrames(xml: string): DebugStackFrame[] {
  const frames: DebugStackFrame[] = [];

  let match: RegExpExecArray | null;
  while ((match = STACK_TAG.exec(xml)) !== null) {
    const attributes = parseAttributes(match[1] ?? '');
    frames.push({
      level: toNumber(attributes.level) ?? 0,
      type: attributes.type,
      fileUri: attributes.filename ?? attributes.fileuri,
      lineno: toNumber(attributes.lineno),
      where: attributes.where,
      command: attributes.cmdbegin,
    });
  }

  return frames.sort((a, b) => a.level - b.level);
}

export function parseContextNames(xml: string): DebugContextDescriptor[] {
  const contexts: DebugContextDescriptor[] = [];

  let match: RegExpExecArray | null;
  while ((match = CONTEXT_TAG.exec(xml)) !== null) {
    const attributes = parseAttributes(match[1] ?? '');
    const id = toNumber(attributes.id);
    if (id === undefined || !attributes.name) {
      continue;
    }

    contexts.push({ id, name: attributes.name });
  }

  return contexts.sort((a, b) => a.id - b.id);
}

export function parseProperties(xml: string): DebugProperty[] {
  const tags = extractTopLevelPropertyTags(xml);
  return tags.map((tag) => parseProperty(tag));
}

export function parseEvalValue(xml: string): string | undefined {
  const properties = parseProperties(xml);
  return properties[0]?.value;
}

export function parseFeatureInfo(xml: string): DebugFeatureInfo | undefined {
  const root = parseRootNode(xml);
  if (root.name !== 'response') {
    return undefined;
  }

  if (!root.attributes.feature_name) {
    return undefined;
  }

  return {
    name: root.attributes.feature_name,
    supported: root.attributes.supported === '1',
    value: decodeInlineText(root.innerXml, root.attributes.encoding),
  };
}

export function parseSourceContent(xml: string): string | undefined {
  const root = parseRootNode(xml);
  if (root.name !== 'response') {
    return undefined;
  }

  return decodeInlineText(root.innerXml, root.attributes.encoding);
}

export function parseBreakpoints(xml: string): DebugBreakpointInfo[] {
  const points: DebugBreakpointInfo[] = [];
  let match: RegExpExecArray | null;

  while ((match = BREAKPOINT_TAG.exec(xml)) !== null) {
    const attributes = parseAttributes(match[1] ?? '');
    points.push({
      id: attributes.id,
      type: attributes.type,
      state: attributes.state,
      fileUri: attributes.filename ?? attributes.fileuri,
      line: toNumber(attributes.lineno),
      functionName: attributes.function,
      exception: attributes.exception,
      expression: decodeInlineText(match[2] ?? '', attributes.encoding),
      hitValue: toNumber(attributes.hit_value),
      hitCondition: attributes.hit_condition,
      hitCount: toNumber(attributes.hit_count),
    });
  }

  return points;
}

function parseProperty(propertyXml: string): DebugProperty {
  const openTag = /^<property\b([^>]*?)(\/?)>/u.exec(propertyXml);
  if (!openTag) {
    return {};
  }

  const attributes = parseAttributes(openTag[1] ?? '');
  const selfClosing = openTag[2] === '/';
  const contentStart = openTag[0].length;
  const contentEnd = selfClosing ? contentStart : propertyXml.lastIndexOf('</property>');
  const innerXml = contentEnd > contentStart ? propertyXml.slice(contentStart, contentEnd) : '';

  const nested = innerXml.includes('<property') ? parseProperties(innerXml) : [];
  const value = nested.length === 0 ? decodeValue(innerXml, attributes.encoding) : undefined;

  return {
    name: attributes.name,
    fullName: attributes.fullname,
    type: attributes.type,
    className: attributes.classname,
    encoding: attributes.encoding,
    facet: attributes.facet,
    size: toNumber(attributes.size),
    children: toNumber(attributes.children),
    numChildren: toNumber(attributes.numchildren),
    page: toNumber(attributes.page),
    pagesize: toNumber(attributes.pagesize),
    key: attributes.key,
    address: attributes.address,
    value,
    properties: nested.length === 0 ? undefined : nested,
  };
}

function extractTopLevelPropertyTags(xml: string): string[] {
  const tags: string[] = [];
  let index = 0;

  while (index < xml.length) {
    const start = xml.indexOf('<property', index);
    if (start === -1) {
      break;
    }

    const openEnd = findTagEnd(xml, start);
    if (openEnd === -1) {
      break;
    }

    const openTag = xml.slice(start, openEnd + 1);
    const selfClosing = /\/>\s*$/u.test(openTag);
    if (selfClosing) {
      tags.push(openTag);
      index = openEnd + 1;
      continue;
    }

    const closeEnd = findMatchingPropertyClose(xml, openEnd + 1);
    if (closeEnd === -1) {
      break;
    }

    const tag = xml.slice(start, closeEnd + '</property>'.length);
    tags.push(tag);
    index = closeEnd + '</property>'.length;
  }

  return tags;
}

function findTagEnd(xml: string, start: number): number {
  let inQuote = false;
  let quote = '';
  for (let i = start; i < xml.length; i += 1) {
    const char = xml[i];
    if ((char === '"' || char === "'") && (quote === '' || quote === char)) {
      if (inQuote) {
        inQuote = false;
        quote = '';
      } else {
        inQuote = true;
        quote = char;
      }
      continue;
    }

    if (!inQuote && char === '>') {
      return i;
    }
  }

  return -1;
}

function findMatchingPropertyClose(xml: string, from: number): number {
  let depth = 1;
  let index = from;

  while (index < xml.length) {
    const nextOpen = xml.indexOf('<property', index);
    const nextClose = xml.indexOf('</property>', index);
    if (nextClose === -1) {
      return -1;
    }

    if (nextOpen !== -1 && nextOpen < nextClose) {
      const openEnd = findTagEnd(xml, nextOpen);
      if (openEnd === -1) {
        return -1;
      }

      const openTag = xml.slice(nextOpen, openEnd + 1);
      if (!/\/>\s*$/u.test(openTag)) {
        depth += 1;
      }

      index = openEnd + 1;
      continue;
    }

    depth -= 1;
    if (depth === 0) {
      return nextClose;
    }
    index = nextClose + '</property>'.length;
  }

  return -1;
}

function decodeValue(raw: string, encoding?: string): string | undefined {
  return decodeInlineText(raw, encoding);
}

function stripCdata(value: string): string {
  return value.replace(/^<!\[CDATA\[/u, '').replace(/\]\]>$/u, '');
}

function decodeXmlEntities(value: string): string {
  return value
    .replace(/&quot;/gu, '"')
    .replace(/&apos;/gu, "'")
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&amp;/gu, '&');
}

function decodeInlineText(raw: string, encoding?: string): string | undefined {
  const trimmed = stripCdata(raw.trim());
  if (trimmed === '') {
    return undefined;
  }

  if (encoding === 'base64') {
    return Buffer.from(trimmed, 'base64').toString('utf8');
  }

  return decodeXmlEntities(trimmed);
}

function toNumber(value: string | undefined): number | undefined {
  if (!value || !/^-?\d+$/u.test(value)) {
    return undefined;
  }

  return Number.parseInt(value, 10);
}
