import { describe, expect, it } from 'vitest';
import { buildExpandedReplayPlan, validateReplayPlan } from '../../src/replay/matrix.js';

describe('replay matrix utilities', () => {
  it('expands matrix dimensions into deterministic variation ids', () => {
    const expanded = buildExpandedReplayPlan({
      variations: [{ id: 'base', mutations: [], evalExpressions: [] }],
      matrix: [
        { propertyName: '$cmd', values: ['id', 'whoami'] },
        { propertyName: '$mode', values: ['safe', 'unsafe'] },
      ],
    });

    expect(expanded.variations).toHaveLength(4);
    expect(expanded.variations.map((variation) => variation.id)).toEqual([
      'base__$cmd:id__$mode:safe',
      'base__$cmd:id__$mode:unsafe',
      'base__$cmd:whoami__$mode:safe',
      'base__$cmd:whoami__$mode:unsafe',
    ]);
  });

  it('validates broken replay plan contracts', () => {
    const errors = validateReplayPlan({
      variations: [{ id: '', mutations: [] }],
      matrix: [{ propertyName: '', values: [] }],
    });
    expect(errors.length).toBeGreaterThan(0);
  });
});
