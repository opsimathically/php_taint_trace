export interface JsonSchemaDocument {
  type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
  required?: readonly string[];
  properties?: Record<string, JsonSchemaDocument>;
  items?: JsonSchemaDocument;
  enum?: readonly unknown[];
  const?: unknown;
  additionalProperties?: boolean;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
}

export function validateJsonSchema(
  schema: JsonSchemaDocument,
  value: unknown,
  path = '$'
): string[] {
  const errors: string[] = [];
  validate(schema, value, path, errors);
  return errors;
}

function validate(
  schema: JsonSchemaDocument,
  value: unknown,
  path: string,
  errors: string[]
): void {
  if (schema.const !== undefined && !isSameValue(schema.const, value)) {
    errors.push(`${path}: expected const value '${String(schema.const)}'.`);
    return;
  }

  if (schema.enum && !schema.enum.some((entry) => isSameValue(entry, value))) {
    errors.push(`${path}: expected value in enum ${JSON.stringify(schema.enum)}.`);
    return;
  }

  if (schema.type) {
    if (!matchesType(schema.type, value)) {
      errors.push(`${path}: expected type '${schema.type}'.`);
      return;
    }
  }

  if (schema.type === 'object' && value && typeof value === 'object' && !Array.isArray(value)) {
    validateObject(schema, value as Record<string, unknown>, path, errors);
  }

  if (schema.type === 'array' && Array.isArray(value)) {
    validateArray(schema, value, path, errors);
  }

  if (schema.type === 'string' && typeof value === 'string') {
    if (schema.pattern) {
      const regex = new RegExp(schema.pattern, 'u');
      if (!regex.test(value)) {
        errors.push(`${path}: string does not match pattern '${schema.pattern}'.`);
      }
    }
  }

  if ((schema.type === 'number' || schema.type === 'integer') && typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${path}: expected number >= ${schema.minimum}.`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${path}: expected number <= ${schema.maximum}.`);
    }
  }
}

function validateObject(
  schema: JsonSchemaDocument,
  value: Record<string, unknown>,
  path: string,
  errors: string[]
): void {
  const properties = schema.properties ?? {};
  const required = schema.required ?? [];

  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      errors.push(`${path}: missing required property '${key}'.`);
    }
  }

  for (const [key, child] of Object.entries(properties)) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      continue;
    }
    validate(child, value[key], `${path}.${key}`, errors);
  }

  if (schema.additionalProperties === false) {
    for (const key of Object.keys(value)) {
      if (!Object.prototype.hasOwnProperty.call(properties, key)) {
        errors.push(`${path}: unexpected property '${key}'.`);
      }
    }
  }
}

function validateArray(
  schema: JsonSchemaDocument,
  value: unknown[],
  path: string,
  errors: string[]
): void {
  if (schema.minItems !== undefined && value.length < schema.minItems) {
    errors.push(`${path}: expected at least ${schema.minItems} items.`);
  }
  if (schema.maxItems !== undefined && value.length > schema.maxItems) {
    errors.push(`${path}: expected at most ${schema.maxItems} items.`);
  }

  if (schema.items) {
    value.forEach((item, index) => {
      validate(schema.items as JsonSchemaDocument, item, `${path}[${index}]`, errors);
    });
  }
}

function matchesType(type: JsonSchemaDocument['type'], value: unknown): boolean {
  switch (type) {
    case 'object':
      return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      return true;
  }
}

function isSameValue(left: unknown, right: unknown): boolean {
  return Object.is(left, right);
}
