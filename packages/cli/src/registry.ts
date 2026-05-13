import type { Rule } from '@supacheck/rules';
import {
  createR01,
  createR02,
  createR03,
  createR04a,
  createR04b,
  createR05,
  createR06,
  createR07,
} from '@supacheck/rules';
import type { SupacheckConfig } from './config.js';

/**
 * Builds the list of enabled rules from the loaded config. As new rules land,
 * append them here and wire their per-rule config.
 */
export function buildRules(config: SupacheckConfig): Rule[] {
  const rules: Rule[] = [];

  if (config.rules.R01?.enabled !== false) {
    rules.push(
      createR01({
        allowlist: (config.rules.R01?.allowlist as string[] | undefined) ?? [],
      }),
    );
  }

  if (config.rules.R02?.enabled !== false) {
    rules.push(
      createR02({
        sensitiveTables:
          (config.rules.R02?.sensitive_tables as string[] | undefined) ?? [],
        chainMaxChars:
          (config.rules.R02?.chain_max_chars as number | undefined) ?? undefined,
      }),
    );
  }

  if (config.rules.R03?.enabled !== false) {
    rules.push(
      createR03({
        migrationsBaselineTimestamp:
          (config.rules.R03?.migrations_baseline_timestamp as string | undefined) ?? undefined,
      }),
    );
  }

  if (config.rules.R04a?.enabled !== false) {
    rules.push(
      createR04a({
        migrationsBaselineTimestamp:
          (config.rules.R04a?.migrations_baseline_timestamp as string | undefined) ?? undefined,
      }),
    );
  }

  if (config.rules.R04b?.enabled !== false) {
    rules.push(
      createR04b({
        migrationsBaselineTimestamp:
          (config.rules.R04b?.migrations_baseline_timestamp as string | undefined) ?? undefined,
      }),
    );
  }

  if (config.rules.R05?.enabled !== false) {
    rules.push(
      createR05({
        allowlist: (config.rules.R05?.allowlist as string[] | undefined) ?? [],
      }),
    );
  }

  if (config.rules.R06?.enabled !== false) {
    rules.push(
      createR06({
        migrationsBaselineTimestamp:
          (config.rules.R06?.migrations_baseline_timestamp as string | undefined) ?? undefined,
      }),
    );
  }

  if (config.rules.R07?.enabled !== false) {
    rules.push(
      createR07({
        migrationsBaselineTimestamp:
          (config.rules.R07?.migrations_baseline_timestamp as string | undefined) ?? undefined,
      }),
    );
  }

  return rules;
}
