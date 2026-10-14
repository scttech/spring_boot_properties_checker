import * as vscode from 'vscode';
import { analyze, Finding, Severity, SEVERITY_ORDER } from './analyzer';
import { FileResult, renderReportHtml, renderReportMarkdown } from './report';

const SOURCE = 'Spring Boot Security';
const EXCLUDE = '**/{node_modules,target,build,out,dist,.git,.gradle}/**';

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let panel: vscode.WebviewPanel | undefined;
/** Latest findings per document URI. */
const results = new Map<string, Finding[]>();
const timers = new Map<string, NodeJS.Timeout>();

const cfg = () => vscode.workspace.getConfiguration('springBootSecurity');

function isSpringConfig(doc: { uri: vscode.Uri; fileName: string }): boolean {
  if (doc.uri.scheme !== 'file' && doc.uri.scheme !== 'untitled') return false;
  const name = doc.fileName.split(/[\\/]/).pop() ?? '';
  try {
    return new RegExp(cfg().get<string>('fileNamePattern') ?? '', 'i').test(name);
  } catch {
    return false;
  }
}

function toDiagnosticSeverity(s: Severity): vscode.DiagnosticSeverity {
  return s === 'critical' || s === 'high'
    ? vscode.DiagnosticSeverity.Error
    : s === 'medium'
      ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;
}

const rangeOf = (r: { line: number; startCol: number; endCol: number }) =>
  new vscode.Range(r.line, r.startCol, r.line, r.endCol);

function findingsFor(text: string, fileName: string): Finding[] {
  const min = SEVERITY_ORDER.indexOf((cfg().get<string>('minimumSeverity') as Severity) ?? 'low');
  return analyze(text, fileName, { disabledRules: cfg().get<string[]>('disabledRules') ?? [] }).filter(
    (f) => SEVERITY_ORDER.indexOf(f.severity) <= min,
  );
}

function publish(uri: vscode.Uri, findings: Finding[]) {
  results.set(uri.toString(), findings);
  diagnostics.set(
    uri,
    findings.map((f) => {
      const d = new vscode.Diagnostic(
        rangeOf(f.range),
        `${f.title}: ${f.message}\nFix: ${f.fix}`,
        toDiagnosticSeverity(f.severity),
      );
      d.source = SOURCE;
      d.code = f.cwe
        ? { value: f.ruleId, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${f.cwe}.html`) }
        : f.ruleId;
      return d;
    }),
  );
}

function clear(uri: vscode.Uri) {
  results.delete(uri.toString());
  diagnostics.delete(uri);
}

function scanDocument(doc: vscode.TextDocument) {
  if (!cfg().get<boolean>('enable', true) || !isSpringConfig(doc)) {
    clear(doc.uri);
  } else {
    publish(doc.uri, findingsFor(doc.getText(), doc.fileName));
  }
  updateStatusBar();
}

function scheduleScan(doc: vscode.TextDocument) {
  const key = doc.uri.toString();
  clearTimeout(timers.get(key));
  timers.set(key, setTimeout(() => { timers.delete(key); scanDocument(doc); }, 300));
}

async function scanWorkspace(): Promise<void> {
  if (!cfg().get<boolean>('enable', true)) return;
  const files = await vscode.workspace.findFiles('**/*.{properties,yml,yaml}', EXCLUDE, 2000);
  const open = new Map(vscode.workspace.textDocuments.map((d) => [d.uri.toString(), d]));
  const seen = new Set<string>();
  for (const uri of files) {
    if (!isSpringConfig({ uri, fileName: uri.fsPath })) continue;
    seen.add(uri.toString());
    try {
      const doc = open.get(uri.toString());
      const text = doc ? doc.getText() : new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
      publish(uri, findingsFor(text, uri.fsPath));
    } catch (err) {
      console.error(`[spring-boot-security] failed to scan ${uri.fsPath}`, err);
    }
  }
  // Drop results for files that no longer exist or no longer match.
  for (const key of [...results.keys()]) {
    if (!seen.has(key) && !open.has(key)) clear(vscode.Uri.parse(key));
  }
  updateStatusBar();
}

function updateStatusBar() {
  const doc = vscode.window.activeTextEditor?.document;
  if (!doc || !cfg().get<boolean>('enable', true) || !isSpringConfig(doc)) {
    statusBar.hide();
    return;
  }
  const f = results.get(doc.uri.toString()) ?? [];
  const worst = SEVERITY_ORDER.find((s) => f.some((x) => x.severity === s));
  statusBar.text = f.length ? `$(shield) ${f.length} security issue${f.length === 1 ? '' : 's'}` : '$(shield) Security OK';
  statusBar.tooltip = f.length ? `Spring Boot Security: worst severity ${worst}. Click to open the report.` : 'No security findings. Click to open the report.';
  statusBar.backgroundColor =
    worst === 'critical' || worst === 'high' ? new vscode.ThemeColor('statusBarItem.errorBackground')
      : worst === 'medium' ? new vscode.ThemeColor('statusBarItem.warningBackground')
        : undefined;
  statusBar.show();
}

// ---------------------------------------------------------------- quick fixes

class FixProvider implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const findings = results.get(doc.uri.toString()) ?? [];
    const actions: vscode.CodeAction[] = [];
    const isProps = !/\.ya?ml$/i.test(doc.fileName);

    for (const d of ctx.diagnostics) {
      if (d.source !== SOURCE) continue;
      const id = typeof d.code === 'object' ? String(d.code.value) : String(d.code);
      const f = findings.find((x) => x.ruleId === id && x.range.line === d.range.start.line && x.range.startCol === d.range.start.character);
      if (!f) continue;

      if (f.suggestedValue !== undefined && f.valueRange) {
        const a = new vscode.CodeAction(`Set value to ${f.suggestedValue}`, vscode.CodeActionKind.QuickFix);
        a.diagnostics = [d];
        a.isPreferred = true;
        a.edit = new vscode.WorkspaceEdit();
        a.edit.replace(doc.uri, rangeOf(f.valueRange), f.suggestedValue);
        actions.push(a);
      }
      if (f.addProperty && isProps) {
        const a = new vscode.CodeAction(`Add ${f.addProperty.key}=${f.addProperty.value}`, vscode.CodeActionKind.QuickFix);
        a.diagnostics = [d];
        a.isPreferred = true;
        a.edit = new vscode.WorkspaceEdit();
        const last = doc.lineAt(doc.lineCount - 1);
        const prefix = last.text.length ? doc.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n' : '';
        a.edit.insert(doc.uri, last.range.end, `${prefix}${f.addProperty.key}=${f.addProperty.value}\n`);
        actions.push(a);
      }
      const ignore = new vscode.CodeAction(`Suppress ${f.ruleId} for this line`, vscode.CodeActionKind.QuickFix);
      ignore.diagnostics = [d];
      ignore.edit = new vscode.WorkspaceEdit();
      const indent = /^\s*/.exec(doc.lineAt(f.range.line).text)?.[0] ?? '';
      ignore.edit.insert(doc.uri, new vscode.Position(f.range.line, 0), `${indent}# sbsec-ignore: ${f.ruleId}${doc.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n'}`);
      actions.push(ignore);
    }
    return actions;
  }
}

// ---------------------------------------------------------------- report

function collectResults(): FileResult[] {
  return [...results.entries()].map(([uri, findings]) => ({
    uri,
    label: vscode.workspace.asRelativePath(vscode.Uri.parse(uri), true),
    findings,
  }));
}

async function showReport(context: vscode.ExtensionContext) {
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Scanning Spring Boot configuration' }, scanWorkspace);
  if (!panel) {
    panel = vscode.window.createWebviewPanel('springBootSecurityReport', 'Spring Boot Security Report', vscode.ViewColumn.Beside, { enableScripts: true });
    panel.onDidDispose(() => (panel = undefined), null, context.subscriptions);
    panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === 'refresh') {
        await scanWorkspace();
        renderPanel();
      } else if (msg.type === 'open') {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(String(msg.uri)));
        const line = Math.max(0, Number(msg.line) || 0);
        await vscode.window.showTextDocument(doc, { selection: new vscode.Range(line, 0, line, 0), viewColumn: vscode.ViewColumn.One });
      } else if (msg.type === 'export') {
        await exportMarkdown();
      }
    }, null, context.subscriptions);
  }
  renderPanel();
  panel.reveal(undefined, true);
}

function renderPanel() {
  if (!panel) return;
  const nonce = Array.from({ length: 24 }, () => Math.floor(Math.random() * 36).toString(36)).join('');
  panel.webview.html = renderReportHtml(collectResults(), nonce, panel.webview.cspSource, new Date());
}

async function exportMarkdown() {
  const folder = vscode.workspace.workspaceFolders?.[0]?.uri;
  const target = await vscode.window.showSaveDialog({
    defaultUri: folder ? vscode.Uri.joinPath(folder, 'spring-boot-security-report.md') : undefined,
    filters: { Markdown: ['md'] },
  });
  if (!target) return;
  await vscode.workspace.fs.writeFile(target, new TextEncoder().encode(renderReportMarkdown(collectResults(), new Date())));
  vscode.window.showInformationMessage(`Report saved to ${vscode.workspace.asRelativePath(target)}`);
}

// ---------------------------------------------------------------- activation

export function activate(context: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection('spring-boot-security');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  statusBar.command = 'springBootSecurity.showReport';

  context.subscriptions.push(
    diagnostics,
    statusBar,
    vscode.commands.registerCommand('springBootSecurity.showReport', () => showReport(context)),
    vscode.commands.registerCommand('springBootSecurity.scanWorkspace', async () => {
      await scanWorkspace();
      renderPanel();
    }),
    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, new FixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidOpenTextDocument(scanDocument),
    vscode.workspace.onDidChangeTextDocument((e) => { if (isSpringConfig(e.document)) scheduleScan(e.document); }),
    vscode.workspace.onDidSaveTextDocument((d) => { scanDocument(d); renderPanel(); }),
    vscode.workspace.onDidCloseTextDocument((d) => {
      // Keep findings for files that still exist on disk so the report stays complete.
      if (d.isUntitled) clear(d.uri);
    }),
    vscode.workspace.onDidDeleteFiles((e) => e.files.forEach(clear)),
    vscode.window.onDidChangeActiveTextEditor(updateStatusBar),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('springBootSecurity')) return;
      diagnostics.clear();
      results.clear();
      void scanWorkspace();
      vscode.workspace.textDocuments.forEach(scanDocument);
    }),
  );

  vscode.workspace.textDocuments.forEach(scanDocument);
  if (cfg().get<boolean>('scanWorkspaceOnStartup', true)) void scanWorkspace();
}

export function deactivate() {
  timers.forEach(clearTimeout);
}
