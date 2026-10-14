import { Entry, fileKind, parseConfig } from './parser';
import { Context, Hit, normKey, RULES, Severity } from './rules';

export { Severity, SEVERITY_ORDER } from './rules';

export interface Range {
  line: number;
  startCol: number;
  endCol: number;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  cwe?: number;
  message: string;
  fix: string;
  /** Configuration key the finding refers to (absent for "setting missing" findings). */
  key?: string;
  range: Range;
  /** Range of the current value, present only when it can be safely replaced. */
  valueRange?: Range;
  suggestedValue?: string;
  addProperty?: { key: string; value: string };
}

export interface AnalyzeOptions {
  disabledRules?: string[];
}

const PROFILE_RE = /^(?:application|bootstrap)-(.+)\.(?:properties|ya?ml)$/i;
const PROD_PROFILES = new Set(['prod', 'production', 'live']);

export function profileOf(fileName: string): string | undefined {
  const base = fileName.split(/[\\/]/).pop() ?? fileName;
  return PROFILE_RE.exec(base)?.[1];
}

export function analyze(text: string, fileName: string, options: AnalyzeOptions = {}): Finding[] {
  const kind = fileKind(fileName);
  const entries = parseConfig(text, kind);
  const lines = text.split(/\r?\n/);
  const profile = profileOf(fileName);
  const disabled = new Set((options.disabledRules ?? []).map((r) => r.toUpperCase()));

  const ctx: Context = {
    entries,
    profile,
    checkAbsent: profile === undefined || PROD_PROFILES.has(profile.toLowerCase()),
    get: (key) => entries.find((e) => normKey(e.key) === key),
    withPrefix: (prefix) => entries.filter((e) => normKey(e.key).startsWith(prefix)),
  };

  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (disabled.has(rule.id)) continue;
    let hits: Hit[];
    try {
      hits = rule.check(ctx);
    } catch (err) {
      console.error(`[spring-boot-security] rule ${rule.id} failed`, err);
      continue;
    }
    for (const hit of hits) {
      const finding = toFinding(rule, hit, lines);
      if (!isSuppressed(lines, finding)) findings.push(finding);
    }
  }
  return findings.sort(
    (a, b) => a.range.line - b.range.line || a.range.startCol - b.range.startCol || a.ruleId.localeCompare(b.ruleId),
  );
}

function toFinding(rule: (typeof RULES)[number], hit: Hit, lines: string[]): Finding {
  const e: Entry | undefined = hit.entry;
  const range: Range = e
    ? { line: e.line, startCol: e.keyStart, endCol: Math.max(e.valueEnd, e.keyEnd) }
    : { line: 0, startCol: 0, endCol: Math.max(lines[0]?.length ?? 0, 1) };
  const canReplace = e && !e.multiline && e.valueEnd > e.valueStart;
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: hit.severity ?? rule.severity,
    category: rule.category,
    cwe: rule.cwe,
    message: hit.message,
    fix: hit.fix,
    key: e?.key,
    range,
    valueRange: canReplace ? { line: e.line, startCol: e.valueStart, endCol: e.valueEnd } : undefined,
    suggestedValue: canReplace ? hit.suggestedValue : undefined,
    addProperty: hit.addProperty,
  };
}

/** `# sbsec-ignore` or `# sbsec-ignore: SB-TLS-002, SB-WEB-002` on the same or previous line. */
function isSuppressed(lines: string[], f: Finding): boolean {
  for (const n of [f.range.line, f.range.line - 1]) {
    const m = /sbsec-ignore(?::\s*([A-Za-z0-9,\s-]+))?/i.exec(lines[n] ?? '');
    if (!m) continue;
    if (n !== f.range.line && !/^\s*[#!]/.test(lines[n])) continue; // previous line must be a comment line
    if (!m[1]) return true;
    if (m[1].toUpperCase().split(/[\s,]+/).includes(f.ruleId)) return true;
  }
  return false;
}
