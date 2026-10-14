import { Finding, Severity, SEVERITY_ORDER } from './analyzer';

export interface FileResult {
  uri: string;
  /** Workspace-relative path shown to the user. */
  label: string;
  findings: Finding[];
}

const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/** Renders `backticked` spans as <code>. Input is escaped first. */
const inline = (s: string) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');

const LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

export function countBySeverity(results: FileResult[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of results) for (const f of r.findings) counts[f.severity]++;
  return counts;
}

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.range.line - b.range.line;

export function renderReportHtml(results: FileResult[], nonce: string, cspSource: string, generated: Date): string {
  const withFindings = results.filter((r) => r.findings.length > 0).sort((a, b) => a.label.localeCompare(b.label));
  const counts = countBySeverity(results);
  const total = SEVERITY_ORDER.reduce((n, s) => n + counts[s], 0);

  const cards = SEVERITY_ORDER.map(
    (s) => `<button class="card ${s}" data-filter="${s}" aria-pressed="true" title="Toggle ${LABEL[s]} findings">
      <span class="num">${counts[s]}</span><span class="lbl">${LABEL[s]}</span></button>`,
  ).join('');

  const sections = withFindings
    .map((r) => {
      const rows = [...r.findings]
        .sort(bySeverity)
        .map((f) => {
          const cwe = f.cwe
            ? ` <a class="cwe" href="https://cwe.mitre.org/data/definitions/${f.cwe}.html">CWE-${f.cwe}</a>`
            : '';
          const sug = f.suggestedValue
            ? `<div class="sug">Suggested: <code>${esc(f.key ?? '')}=${esc(f.suggestedValue)}</code></div>`
            : f.addProperty
              ? `<div class="sug">Add: <code>${esc(f.addProperty.key)}=${esc(f.addProperty.value)}</code></div>`
              : '';
          return `<tr class="row ${f.severity}" data-sev="${f.severity}">
  <td><span class="badge ${f.severity}">${LABEL[f.severity]}</span></td>
  <td><div class="rule">${esc(f.title)}</div><div class="rid">${esc(f.ruleId)}${cwe}</div></td>
  <td><a href="#" class="goto" data-uri="${esc(r.uri)}" data-line="${f.range.line}">Line ${f.range.line + 1}</a>${f.key ? `<div class="key">${esc(f.key)}</div>` : ''}</td>
  <td>${inline(f.message)}</td>
  <td>${inline(f.fix)}${sug}</td>
</tr>`;
        })
        .join('\n');
      return `<section class="file"><h2>${esc(r.label)} <span class="count">${r.findings.length}</span></h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Problem</th><th>Recommended fix</th></tr></thead>
<tbody>${rows}</tbody></table></section>`;
    })
    .join('\n');

  const body =
    results.length === 0
      ? '<p class="empty">No Spring Boot configuration files (application*.properties / .yml) were found in the workspace.</p>'
      : total === 0
        ? `<p class="empty">No findings in ${results.length} configuration file${results.length === 1 ? '' : 's'}.</p>`
        : sections;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spring Boot Security Report</title>
<style nonce="${nonce}">
  :root { --critical:#b3261e; --high:#d9480f; --medium:#b58105; --low:#2b7de9; }
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 16px 24px; line-height: 1.45; }
  h1 { font-size: 1.5em; margin: 0 0 4px; }
  .meta { opacity: .7; margin-bottom: 16px; }
  .toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 16px; }
  .cards { display: flex; flex-wrap: wrap; gap: 8px; }
  .card { display: flex; flex-direction: column; align-items: center; min-width: 88px; padding: 8px 14px; border: 1px solid var(--vscode-panel-border); border-top-width: 4px; border-radius: 4px; background: var(--vscode-editorWidget-background); color: inherit; cursor: pointer; }
  .card[aria-pressed="false"] { opacity: .45; }
  .card .num { font-size: 1.6em; font-weight: 600; }
  .card.critical { border-top-color: var(--critical); } .card.high { border-top-color: var(--high); }
  .card.medium { border-top-color: var(--medium); } .card.low { border-top-color: var(--low); }
  input[type=search] { flex: 1; min-width: 180px; padding: 5px 8px; color: var(--vscode-input-foreground); background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); }
  .btn { padding: 5px 12px; color: var(--vscode-button-foreground); background: var(--vscode-button-background); border: 0; cursor: pointer; }
  .btn:hover { background: var(--vscode-button-hoverBackground); }
  .file { margin-bottom: 28px; }
  h2 { font-size: 1.1em; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; word-break: break-all; }
  .count { font-size: .8em; opacity: .7; font-weight: normal; margin-left: 6px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: .85em; opacity: .75; padding: 4px 8px; }
  td { vertical-align: top; padding: 8px; border-top: 1px solid var(--vscode-panel-border); }
  td:nth-child(1) { white-space: nowrap; } td:nth-child(3) { white-space: nowrap; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff; font-size: .85em; font-weight: 600; }
  .badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
  .badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
  .rule { font-weight: 600; } .rid, .key { font-size: .85em; opacity: .7; }
  .key { font-family: var(--vscode-editor-font-family); }
  code { font-family: var(--vscode-editor-font-family); background: var(--vscode-textCodeBlock-background); padding: 0 4px; border-radius: 3px; }
  .sug { margin-top: 6px; font-size: .9em; }
  a { color: var(--vscode-textLink-foreground); }
  .empty { padding: 24px 0; font-size: 1.1em; }
  .hidden { display: none; }
  @media (max-width: 900px) { table, thead, tbody, tr, td { display: block; } thead { display: none; } td { border: 0; padding: 2px 8px; } tr.row { border-top: 1px solid var(--vscode-panel-border); padding: 6px 0; } }
</style></head>
<body>
<h1>Spring Boot Security Report</h1>
<div class="meta">${total} finding${total === 1 ? '' : 's'} in ${withFindings.length} of ${results.length} file${results.length === 1 ? '' : 's'} &middot; generated ${esc(generated.toLocaleString())}</div>
<div class="toolbar">
  <div class="cards">${cards}</div>
  <input type="search" id="q" placeholder="Filter by file, rule, key or text" aria-label="Filter findings">
  <button class="btn" id="refresh">Rescan</button>
  <button class="btn" id="export">Export Markdown</button>
</div>
${body}
<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const active = new Set(['critical','high','medium','low']);
  const apply = () => {
    const q = document.getElementById('q').value.toLowerCase();
    document.querySelectorAll('tr.row').forEach(r => {
      const show = active.has(r.dataset.sev) && (!q || r.textContent.toLowerCase().includes(q) || r.closest('section').querySelector('h2').textContent.toLowerCase().includes(q));
      r.classList.toggle('hidden', !show);
    });
    document.querySelectorAll('section.file').forEach(s => s.classList.toggle('hidden', !s.querySelector('tr.row:not(.hidden)')));
  };
  document.querySelectorAll('.card').forEach(c => c.addEventListener('click', () => {
    const s = c.dataset.filter, on = !active.has(s);
    on ? active.add(s) : active.delete(s);
    c.setAttribute('aria-pressed', String(on));
    apply();
  }));
  document.getElementById('q').addEventListener('input', apply);
  document.getElementById('refresh').addEventListener('click', () => vscode.postMessage({ type: 'refresh' }));
  document.getElementById('export').addEventListener('click', () => vscode.postMessage({ type: 'export' }));
  document.addEventListener('click', e => {
    const a = e.target.closest && e.target.closest('a.goto');
    if (a) { e.preventDefault(); vscode.postMessage({ type: 'open', uri: a.dataset.uri, line: Number(a.dataset.line) }); }
  });
</script>
</body></html>`;
}

export function renderReportMarkdown(results: FileResult[], generated: Date): string {
  const counts = countBySeverity(results);
  const out: string[] = [
    '# Spring Boot Security Report',
    '',
    `Generated ${generated.toISOString()}`,
    '',
    '| Critical | High | Medium | Low |',
    '|---|---|---|---|',
    `| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} |`,
    '',
  ];
  for (const r of results.filter((x) => x.findings.length).sort((a, b) => a.label.localeCompare(b.label))) {
    out.push(`## ${r.label}`, '');
    for (const f of [...r.findings].sort(bySeverity)) {
      out.push(
        `### [${LABEL[f.severity]}] ${f.title} (${f.ruleId}${f.cwe ? `, CWE-${f.cwe}` : ''})`,
        '',
        `- **Location:** line ${f.range.line + 1}${f.key ? `, \`${f.key}\`` : ''}`,
        `- **Problem:** ${f.message}`,
        `- **Fix:** ${f.fix}`,
        '',
      );
    }
  }
  if (out.length <= 8) out.push('No findings.');
  return out.join('\n');
}
