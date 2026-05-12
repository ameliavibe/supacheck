export type RuleCategory =
  | 'rls-performance'
  | 'rls-correctness'
  | 'secdef-hygiene'
  | 'view-hygiene'
  | 'ssrf'
  | 'auth-cache-coherence'
  | 'data-exposure';

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ScannedFile {
  /** Path as the caller chooses to label it (absolute, relative, or fixture name). */
  path: string;
  contents: string;
}

export interface Finding {
  ruleId: string;
  file: string;
  /** 1-indexed line number. */
  line: number;
  /** 1-indexed column number when available. */
  column?: number;
  message: string;
  /** Optional excerpt of source for human-readable output. */
  context?: string;
  /**
   * Byte range [start, end) in the original file contents that points at the
   * exact span responsible for the finding. autoFix uses this as the patch
   * anchor so it does not have to re-parse.
   */
  range?: [number, number];
}

export interface FixPatch {
  file: string;
  /** [startByte, endByte] in the original file contents. End is exclusive. */
  range: [number, number];
  replacement: string;
}

export interface FixSuggestion {
  description: string;
  patches: FixPatch[];
  /**
   * true: the patch is a pure text transform that can be applied without review.
   * false: the patch is heuristic or LLM-assisted and requires human review.
   */
  deterministic: boolean;
}

export interface Rule {
  /** Stable identifier, e.g. "R03". */
  id: string;
  /** Kebab-case slug, e.g. "sql-bare-auth-uid". */
  slug: string;
  /** Human-readable rule name. */
  name: string;
  category: RuleCategory;
  severity: RuleSeverity;
  /**
   * Glob patterns that hint which files this rule cares about. The runner does
   * not filter on this; rules are expected to short-circuit inside scan() if
   * the file is out of scope. The patterns are metadata for the CLI walker.
   */
  filePatterns: string[];
  /**
   * true for rules that defend against pg_dump re-emitting your security posture
   * during a Supabase squash (R04a, R04b, R06, R07). Marketing groups them under
   * the squash-clobbers banner; code can fan out documentation links from this.
   */
  squashClobberFamily?: boolean;
  scan(file: ScannedFile): Finding[];
  /**
   * Optional cross-file scan. Called once with every file. Used by rules
   * that need to aggregate state across multiple files (state machines over
   * migration history, multi-file consistency checks). If present, the
   * runner calls scanAll instead of scan.
   */
  scanAll?(files: ScannedFile[]): Finding[];
  /**
   * Optional auto-fix. Returns null when this finding is not fixable
   * automatically (e.g. R02 select('*') needs schema inference).
   */
  autoFix?(file: ScannedFile, finding: Finding): FixSuggestion | null;
}
