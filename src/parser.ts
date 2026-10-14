import { LineCounter, isMap, isScalar, isSeq, parseAllDocuments } from 'yaml';

/** A single flattened configuration entry. All positions are 0-based. */
export interface Entry {
  /** Dotted key, e.g. `spring.datasource.password` or `management.endpoints.web.exposure.include[0]`. */
  key: string;
  value: string;
  line: number;
  keyStart: number;
  keyEnd: number;
  valueStart: number;
  valueEnd: number;
  /** True when the value spans several physical lines (not safe to rewrite automatically). */
  multiline: boolean;
}

export type FileKind = 'properties' | 'yaml';

export function fileKind(fileName: string): FileKind {
  return /\.ya?ml$/i.test(fileName) ? 'yaml' : 'properties';
}

export function parseConfig(text: string, kind: FileKind): Entry[] {
  return kind === 'yaml' ? parseYaml(text) : parseProperties(text);
}

const isWs = (c: string | undefined) => c === ' ' || c === '\t' || c === '\f';

export function parseProperties(text: string): Entry[] {
  const lines = text.split(/\r?\n/);
  const out: Entry[] = [];
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n];
    let i = 0;
    while (isWs(line[i])) i++;
    if (i >= line.length || line[i] === '#' || line[i] === '!') continue;

    const keyStart = i;
    while (i < line.length) {
      const c = line[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '=' || c === ':' || isWs(c)) break;
      i++;
    }
    const keyEnd = Math.min(i, line.length);
    while (isWs(line[i])) i++;
    if (line[i] === '=' || line[i] === ':') {
      i++;
      while (isWs(line[i])) i++;
    }
    const valueStart = Math.min(i, line.length);
    const startLine = n;
    const firstPart = line.slice(valueStart).trimEnd();
    const valueEnd = valueStart + firstPart.length;
    let value = firstPart;
    let multiline = false;

    // Continuation lines: an odd number of trailing backslashes.
    while (/(^|[^\\])(\\\\)*\\$/.test(value) && n + 1 < lines.length) {
      multiline = true;
      value = value.slice(0, -1) + lines[++n].replace(/^\s+/, '').trimEnd();
    }
    if (multiline) value = value.replace(/\\$/, '');

    out.push({
      key: line.slice(keyStart, keyEnd),
      value,
      line: startLine,
      keyStart,
      keyEnd,
      valueStart,
      valueEnd,
      multiline,
    });
  }
  return out;
}

export function parseYaml(text: string): Entry[] {
  const out: Entry[] = [];
  const lc = new LineCounter();
  let docs;
  try {
    docs = parseAllDocuments(text, { lineCounter: lc });
  } catch {
    return out;
  }
  const docList = Array.isArray(docs) ? docs : [docs];

  const emit = (path: string, node: any, keyNode: any) => {
    const raw = node?.value;
    if (raw !== null && raw !== undefined && typeof raw === 'object') return;
    const value = raw === null || raw === undefined ? '' : String(raw);
    const kr: [number, number, number] = keyNode?.range ?? [0, 0, 0];
    const k0 = lc.linePos(kr[0]);
    const k1 = lc.linePos(kr[1]);
    let valueStart: number, valueEnd: number, multiline = false;
    if (node?.range && value !== '') {
      const v0 = lc.linePos(node.range[0]);
      const v1 = lc.linePos(node.range[1]);
      multiline = v0.line !== v1.line;
      valueStart = v0.col - 1;
      valueEnd = multiline ? valueStart : v1.col - 1;
      out.push({
        key: path, value, line: v0.line - 1,
        keyStart: k0.col - 1, keyEnd: k1.col - 1, valueStart, valueEnd, multiline,
      });
      // Anchor on the key's line when the value sits on the same line, which is the usual case.
      if (!multiline && v0.line === k0.line) out[out.length - 1].line = k0.line - 1;
      return;
    }
    out.push({
      key: path, value, line: k0.line - 1,
      keyStart: k0.col - 1, keyEnd: k1.col - 1,
      valueStart: k1.col, valueEnd: k1.col, multiline: false,
    });
  };

  const walk = (node: any, path: string, keyNode: any) => {
    if (isMap(node)) {
      for (const pair of node.items) {
        const k = isScalar(pair.key) ? String((pair.key as any).value) : String(pair.key);
        walk(pair.value, path ? `${path}.${k}` : k, pair.key);
      }
    } else if (isSeq(node)) {
      node.items.forEach((item, idx) => walk(item, `${path}[${idx}]`, keyNode));
    } else if (isScalar(node) || node === null || node === undefined) {
      if (path) emit(path, node, keyNode);
    }
  };

  for (const doc of docList) walk(doc.contents, '', null);
  return out;
}
