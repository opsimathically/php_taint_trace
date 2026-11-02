import { describe, expect, it } from 'vitest';
import { validateJsonSchema } from '../../src/schema/validator.js';

describe('json schema validator', () => {
  it('accepts valid payloads for basic object/array schema', () => {
    const schema = {
      type: 'object',
      required: ['ok', 'items'],
      properties: {
        ok: { type: 'boolean' },
        items: {
          type: 'array',
          minItems: 1,
          items: {
            type: 'object',
            required: ['id'],
            properties: {
              id: { type: 'string', pattern: '^item-' },
            },
          },
        },
      },
    } as const;

    const errors = validateJsonSchema(schema, {
      ok: true,
      items: [{ id: 'item-1' }],
    });
    expect(errors).toEqual([]);
  });

  it('returns useful errors for invalid payloads', () => {
    const schema = {
      type: 'object',
      required: ['count'],
      properties: {
        count: { type: 'integer', minimum: 1 },
      },
      additionalProperties: false,
    } as const;

    const errors = validateJsonSchema(schema, { count: 0, extra: true });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.join(' ')).toContain('expected number >= 1');
    expect(errors.join(' ')).toContain("unexpected property 'extra'");
  });
});
