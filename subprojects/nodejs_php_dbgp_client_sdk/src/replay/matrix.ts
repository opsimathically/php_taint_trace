import type { ReplayMutation, ReplayPlan, ReplayVariation } from '../inspector/types.js';

export function buildExpandedReplayPlan(plan: ReplayPlan): ReplayPlan {
  return {
    ...plan,
    variations: expandReplayVariations(plan),
  };
}

export function expandReplayVariations(plan: ReplayPlan): ReplayVariation[] {
  const seed = plan.variations.length > 0
    ? plan.variations
    : [{ id: 'matrix', mutations: [], evalExpressions: [], metadata: {} }];
  const matrix = plan.matrix ?? [];
  if (matrix.length === 0) {
    return seed;
  }

  return seed.flatMap((variation) => expandVariationMatrix(variation, matrix, 0, [], []));
}

export function validateReplayPlan(plan: ReplayPlan): string[] {
  const errors: string[] = [];
  if ((!plan.variations || plan.variations.length === 0) && (!plan.matrix || plan.matrix.length === 0)) {
    errors.push('Replay plan must define variations[] or matrix[].');
  }

  const variationIds = new Set<string>();
  for (const [index, variation] of (plan.variations ?? []).entries()) {
    if (!variation.id || variation.id.trim() === '') {
      errors.push(`Variation at index ${index} has an empty id.`);
      continue;
    }
    if (variationIds.has(variation.id)) {
      errors.push(`Duplicate variation id '${variation.id}'.`);
      continue;
    }
    variationIds.add(variation.id);
  }

  for (const [index, dimension] of (plan.matrix ?? []).entries()) {
    if (!dimension.propertyName || dimension.propertyName.trim() === '') {
      errors.push(`Matrix dimension at index ${index} has an empty propertyName.`);
    }
    if (!Array.isArray(dimension.values) || dimension.values.length === 0) {
      errors.push(`Matrix dimension '${dimension.propertyName || index}' has no values.`);
    }
  }

  return errors;
}

function expandVariationMatrix(
  variation: ReplayVariation,
  matrix: NonNullable<ReplayPlan['matrix']>,
  index: number,
  keyParts: string[],
  mutations: ReplayMutation[]
): ReplayVariation[] {
  if (index >= matrix.length) {
    const matrixSuffix = keyParts.length > 0 ? `__${keyParts.join('__')}` : '';
    return [
      {
        ...variation,
        id: `${variation.id}${matrixSuffix}`,
        mutations: [...(variation.mutations ?? []), ...mutations],
        metadata: {
          ...(variation.metadata ?? {}),
          matrix: keyParts.join(','),
        },
      },
    ];
  }

  const dimension = matrix[index];
  if (!dimension || !Array.isArray(dimension.values) || dimension.values.length === 0) {
    return expandVariationMatrix(variation, matrix, index + 1, keyParts, mutations);
  }

  const branch: ReplayVariation[] = [];
  for (const value of dimension.values) {
    const safeValue = value.replace(/[^A-Za-z0-9._-]/gu, '_');
    branch.push(
      ...expandVariationMatrix(
        variation,
        matrix,
        index + 1,
        [...keyParts, `${dimension.propertyName}:${safeValue}`],
        [
          ...mutations,
          {
            propertyName: dimension.propertyName,
            value,
            options: dimension.options,
          },
        ]
      )
    );
  }

  return branch;
}
