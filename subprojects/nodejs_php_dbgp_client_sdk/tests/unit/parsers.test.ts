import { describe, expect, it } from 'vitest';
import {
  parseBreakpoints,
  parseFeatureInfo,
  parseSourceContent,
} from '../../src/inspector/parsers.js';

describe('inspector parsers', () => {
  it('parses feature_get response payload', () => {
    const parsed = parseFeatureInfo(
      '<response command="feature_get" transaction_id="1" feature_name="max_depth" supported="1">3</response>'
    );
    expect(parsed).toEqual({
      name: 'max_depth',
      supported: true,
      value: '3',
    });
  });

  it('parses source payload with base64 encoding', () => {
    const content = '<?php echo "ok";';
    const parsed = parseSourceContent(
      `<response command="source" transaction_id="1" encoding="base64">${Buffer.from(content, 'utf8').toString('base64')}</response>`
    );
    expect(parsed).toBe(content);
  });

  it('parses breakpoint list entries', () => {
    const parsed = parseBreakpoints(
      '<response command="breakpoint_list" transaction_id="1"><breakpoint id="bp-1" type="line" state="enabled" filename="file:///tmp/a.php" lineno="9"/></response>'
    );
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.id).toBe('bp-1');
    expect(parsed[0]?.line).toBe(9);
  });
});
