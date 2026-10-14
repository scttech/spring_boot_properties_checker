import { Entry } from './parser';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export interface Context {
  entries: Entry[];
  /** Spring profile taken from the file name (application-prod.yml -> "prod"), if any. */
  profile?: string;
  /** True for the base file or a production profile - where "setting is missing" checks make sense. */
  checkAbsent: boolean;
  /** First entry whose normalized key equals `key`. */
  get(key: string): Entry | undefined;
  /** All entries whose normalized key starts with `prefix`. */
  withPrefix(prefix: string): Entry[];
}

export interface Hit {
  /** Entry the finding is attached to. Omit for "setting missing" findings (anchored on line 1). */
  entry?: Entry;
  message: string;
  fix: string;
  severity?: Severity;
  /** Value that resolves the finding; enables a quick fix that replaces the current value. */
  suggestedValue?: string;
  /** Property that resolves a "missing" finding; enables a quick fix in .properties files. */
  addProperty?: { key: string; value: string };
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  /** CWE number, used for the reference link. */
  cwe?: number;
  check(ctx: Context): Hit[];
}

// ---------------------------------------------------------------- helpers

/** Spring relaxed binding: case, dashes and underscores are insignificant. */
export const normKey = (k: string) => k.toLowerCase().replace(/[-_]/g, '');
const normVal = (v: string) => v.trim().toLowerCase().replace(/[-_]/g, '');
const isTrue = (v: string) => v.trim().toLowerCase() === 'true';
const isFalse = (v: string) => v.trim().toLowerCase() === 'false';
const isPlaceholder = (v: string) => /^\$\{[^}]*\}$/.test(v.trim());
const isEncrypted = (v: string) => /^ENC\(.*\)$/.test(v.trim()) || v.trim().startsWith('{cipher}');
const lastSegment = (nk: string) => nk.replace(/\[\d+\]/g, '').split('.').pop() ?? nk;

export function envName(key: string): string {
  return key.replace(/\[(\d+)\]/g, '_$1').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '').toUpperCase();
}

interface KvOptions {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cwe?: number;
  /** Matched against the normalized key. */
  keys: RegExp;
  /** Receives the raw value; return true to flag. Placeholders are skipped automatically. */
  test: (value: string, entry: Entry) => boolean;
  message: (e: Entry) => string;
  fix: string | ((e: Entry) => string);
  suggested?: string | ((e: Entry) => string | undefined);
  severityOf?: (value: string, entry: Entry) => Severity;
}

/** A rule that flags individual entries by key + value. */
function kv(o: KvOptions): Rule {
  return {
    id: o.id, title: o.title, severity: o.severity, category: o.category, cwe: o.cwe,
    check(ctx) {
      const hits: Hit[] = [];
      for (const e of ctx.entries) {
        if (!o.keys.test(normKey(e.key))) continue;
        if (isPlaceholder(e.value) || !o.test(e.value, e)) continue;
        hits.push({
          entry: e,
          message: o.message(e),
          fix: typeof o.fix === 'function' ? o.fix(e) : o.fix,
          severity: o.severityOf?.(e.value, e),
          suggestedValue: typeof o.suggested === 'function' ? o.suggested(e) : o.suggested,
        });
      }
      return hits;
    },
  };
}

const first = (ctx: Context, prefix: string) => ctx.withPrefix(prefix)[0];

// ---------------------------------------------------------------- secrets

const SECRET_NAME =
  /(password|passwd|passphrase|pwd|secret|secretkey|apikey|accesskey|privatekey|signingkey|encryptionkey|token|credentials?)$/;
const SECRET_KEY_PAIR = /(^|\.)(encrypt|jwt|signing|secret|api|private|access|auth)\.key$/;
const WEAK_VALUES =
  /^(password|passwd|pass|admin|root|secret|changeme|change-me|123456|12345678|test|default|letmein|qwerty|welcome|guest|user|sa|postgres|mysql)$/i;

const TOKEN_PATTERNS: [string, RegExp][] = [
  ['an AWS access key ID', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['a private key', /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/],
  ['a GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['a Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ['a Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['a Stripe live key', /\b[sr]k_live_[0-9a-zA-Z]{16,}/],
  ['a JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/],
];

export function isSecretKey(key: string): boolean {
  const nk = normKey(key);
  return SECRET_NAME.test(lastSegment(nk)) || SECRET_KEY_PAIR.test(nk.replace(/\[\d+\]/g, ''));
}

const hardcodedSecret: Rule = {
  id: 'SB-SEC-001',
  title: 'Hardcoded secret',
  severity: 'high',
  category: 'Secrets',
  cwe: 798,
  check(ctx) {
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      const v = e.value.trim();
      if (!v || isPlaceholder(v) || isEncrypted(v)) continue;
      const env = `\${${envName(e.key)}}`;
      const fix = `Do not commit secrets. Read it from the environment or a secret store, e.g. \`${e.key}=${env}\`, ` +
        `and supply the value via an environment variable, Kubernetes/Docker secret, Vault, or Spring Cloud Config ({cipher}/ENC()).`;

      const token = TOKEN_PATTERNS.find(([, re]) => re.test(v));
      if (token) {
        hits.push({
          entry: e, severity: 'critical', suggestedValue: env,
          message: `\`${e.key}\` contains ${token[0]}. Treat it as compromised and rotate it.`,
          fix: `Rotate the credential now (it is in source control history), then ${fix.charAt(0).toLowerCase()}${fix.slice(1)}`,
        });
      } else if (isSecretKey(e.key)) {
        const weak = WEAK_VALUES.test(v);
        hits.push({
          entry: e, severity: weak ? 'critical' : 'high', suggestedValue: env,
          message: weak
            ? `\`${e.key}\` is hardcoded to a well-known default value.`
            : `\`${e.key}\` is hardcoded in the configuration file.`,
          fix,
        });
      }
    }
    return hits;
  },
};

const placeholderDefault: Rule = {
  id: 'SB-SEC-002',
  title: 'Secret placeholder has a hardcoded fallback',
  severity: 'medium',
  category: 'Secrets',
  cwe: 798,
  check(ctx) {
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      if (!isSecretKey(e.key)) continue;
      const m = /^\$\{([^:}]+):([^}]+)\}$/.exec(e.value.trim());
      if (!m) continue;
      hits.push({
        entry: e,
        message: `\`${e.key}\` falls back to a hardcoded value when \`${m[1]}\` is not set, so a missing variable silently runs with a known secret.`,
        fix: `Remove the default so startup fails fast when the variable is missing: \`${e.key}=\${${m[1]}}\`.`,
        suggestedValue: `\${${m[1]}}`,
      });
    }
    return hits;
  },
};

const credentialsInUrl: Rule = {
  id: 'SB-SEC-003',
  title: 'Credentials embedded in a URL',
  severity: 'high',
  category: 'Secrets',
  cwe: 522,
  check(ctx) {
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      const v = e.value;
      const userinfo = /^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:([^/\s@]+)@/i.exec(v);
      const param = /[?;&](?:password|pwd|passwd)=([^&;\s]+)/i.exec(v);
      const secret = userinfo?.[1] ?? param?.[1];
      if (!secret || secret.startsWith('${') || secret.startsWith('{cipher}')) continue;
      hits.push({
        entry: e,
        message: `\`${e.key}\` embeds a username/password in the URL.`,
        fix: 'Remove the credentials from the URL and set them through separate properties (e.g. `spring.datasource.username` / `password`) that read from environment variables.',
      });
    }
    return hits;
  },
};

const emptyPassword: Rule = {
  id: 'SB-SEC-004',
  title: 'Empty password',
  severity: 'medium',
  category: 'Secrets',
  cwe: 258,
  check(ctx) {
    return ctx.entries
      .filter((e) => e.value.trim() === '' && /(password|passwd|pwd)$/.test(lastSegment(normKey(e.key))))
      .map((e) => ({
        entry: e,
        message: `\`${e.key}\` is empty. A blank password is not acceptable in production.`,
        fix: `Set a strong password supplied from the environment: \`${e.key}=\${${envName(e.key)}}\`.`,
        suggestedValue: `\${${envName(e.key)}}`,
      }));
  },
};

const defaultDbUser: Rule = {
  id: 'SB-SEC-005',
  title: 'Default or administrative database user',
  severity: 'medium',
  category: 'Secrets',
  cwe: 250,
  check(ctx) {
    return ctx.entries
      .filter((e) => /^spring\.(datasource|r2dbc)\.username$/.test(normKey(e.key)) &&
        /^(root|sa|admin|postgres|sys|system|sysdba)$/i.test(e.value.trim()))
      .map((e) => ({
        entry: e,
        message: `\`${e.key}\` uses the privileged/default account "${e.value.trim()}".`,
        fix: 'Create a dedicated least-privilege database account for the application and supply its name from the environment.',
      }));
  },
};

// ---------------------------------------------------------------- transport security

const sslDisabled = kv({
  id: 'SB-TLS-001', title: 'TLS explicitly disabled', severity: 'high', category: 'Transport security', cwe: 319,
  keys: /^server\.ssl\.enabled$/, test: isFalse,
  message: () => '`server.ssl.enabled=false` serves all traffic over plain HTTP.',
  fix: 'Enable TLS (`server.ssl.enabled=true` with a key store or `server.ssl.bundle`), or terminate TLS at a trusted proxy and document that decision.',
  suggested: 'true',
});

const sslNotConfigured: Rule = {
  id: 'SB-TLS-002', title: 'TLS not configured', severity: 'medium', category: 'Transport security', cwe: 319,
  check(ctx) {
    if (!ctx.checkAbsent || ctx.entries.length === 0) return [];
    if (ctx.withPrefix('server.ssl.').length > 0) return [];
    return [{
      message: 'No `server.ssl.*` settings found, so the embedded server will listen over plain HTTP.',
      fix: 'Configure TLS (`server.ssl.enabled=true`, `server.ssl.bundle=...` or key-store settings). If TLS is terminated by a load balancer/ingress, suppress this finding with `# sbsec-ignore: SB-TLS-002`.',
      addProperty: { key: 'server.ssl.enabled', value: 'true' },
    }];
  },
};

const sslEnabledImplicit: Rule = {
  id: 'SB-TLS-010', title: 'server.ssl.enabled not stated explicitly', severity: 'low', category: 'Transport security', cwe: 1188,
  check(ctx) {
    if (!ctx.checkAbsent || ctx.get('server.ssl.enabled')) return [];
    const ssl = ctx.withPrefix('server.ssl.');
    if (ssl.length === 0) return [];
    return [{
      entry: ssl[0],
      message: '`server.ssl.*` settings are present but `server.ssl.enabled` is not set. Spring Boot defaults it to `true`, so this may not be necessary, but stating it explicitly makes the intent clear to reviewers and protects against a changed default or an override in another profile.',
      fix: 'For clarity, add `server.ssl.enabled=true`.',
      addProperty: { key: 'server.ssl.enabled', value: 'true' },
    }];
  },
};

const tlsUnspecified: Rule = {
  id: 'SB-TLS-003', title: 'TLS protocol versions not specified', severity: 'medium', category: 'Transport security', cwe: 326,
  check(ctx) {
    const enabled = ctx.get('server.ssl.enabled');
    if (enabled && isFalse(enabled.value)) return [];
    const configured = enabled ? isTrue(enabled.value)
      : ctx.withPrefix('server.ssl.').some((e) => /^server\.ssl\.(keystore|bundle|certificate)/.test(normKey(e.key)));
    if (!configured || ctx.get('server.ssl.enabledprotocols') || ctx.withPrefix('server.ssl.enabledprotocols[').length) return [];
    return [{
      entry: enabled ?? first(ctx, 'server.ssl.'),
      message: 'TLS is enabled but `server.ssl.enabled-protocols` is not set, so the JVM defaults decide which protocol versions are accepted.',
      fix: 'Pin modern protocol versions: `server.ssl.enabled-protocols=TLSv1.3,TLSv1.2`.',
      addProperty: { key: 'server.ssl.enabled-protocols', value: 'TLSv1.3,TLSv1.2' },
    }];
  },
};

const WEAK_PROTOCOL = /\b(SSLv?[23]|TLSv?1(\.[01])?)(?![.\d])/i;
const weakProtocol = kv({
  id: 'SB-TLS-004', title: 'Deprecated TLS/SSL protocol', severity: 'high', category: 'Transport security', cwe: 327,
  keys: /(ssl\.(enabledprotocols|protocols?)(\[\d+\])?$|^spring\.kafka\.ssl\.protocol$)/,
  test: (v) => WEAK_PROTOCOL.test(v),
  message: (e) => `\`${e.key}\` allows SSLv2/SSLv3/TLS 1.0/TLS 1.1, which are broken or deprecated.`,
  fix: 'Allow only TLS 1.2 and 1.3: `TLSv1.3,TLSv1.2`.',
  suggested: 'TLSv1.3,TLSv1.2',
});

const weakCipher = kv({
  id: 'SB-TLS-005', title: 'Weak TLS cipher suite', severity: 'high', category: 'Transport security', cwe: 327,
  keys: /(^|\.)ssl\.ciphers(\[\d+\])?$/,
  test: (v) => /(RC4|(^|[_,\s-])DES([_,\s-]|$)|3DES|NULL|EXPORT|MD5|ANON)/i.test(v),
  message: (e) => `\`${e.key}\` enables weak cipher suites (RC4/DES/3DES/NULL/EXPORT/MD5/anonymous).`,
  fix: 'Remove the property to use the JVM defaults, or list only AEAD suites such as `TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.',
});

const TRUE_DISABLES = /(trustall|insecure|skipssl|skiptls|disablessl|disabletls|disablehostname|disablecertvalid|trustselfsigned)/;
const FALSE_DISABLES = /(verifyhostname|hostnameverif|checkserveridentity|verifyservercert|sslverify|verifycert|validatecert)/;
const certValidationOff = kv({
  id: 'SB-TLS-006', title: 'Certificate / hostname validation disabled', severity: 'high', category: 'Transport security', cwe: 295,
  keys: new RegExp(`${TRUE_DISABLES.source}|${FALSE_DISABLES.source}`),
  test: (v, e) => {
    const nk = normKey(e.key);
    return (TRUE_DISABLES.test(nk) && isTrue(v)) || (FALSE_DISABLES.test(nk) && isFalse(v));
  },
  message: (e) => `\`${e.key}\` turns off certificate or hostname verification, allowing man-in-the-middle attacks.`,
  fix: 'Remove the property or invert it so certificates and hostnames are verified. Import private CAs into a trust store instead of trusting everything.',
  suggested: undefined,
});

const clientTlsOff: Rule = {
  id: 'SB-TLS-007', title: 'Encryption disabled for an outbound connection', severity: 'medium', category: 'Transport security', cwe: 319,
  check(ctx) {
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      const nk = normKey(e.key);
      const v = e.value;
      if (isPlaceholder(v)) continue;
      let why: string | undefined;
      let suggested: string | undefined;
      let severity: Severity | undefined;
      if (nk !== 'server.ssl.enabled' && /\.ssl\.enabled$/.test(nk) && isFalse(v)) { why = 'SSL/TLS is disabled'; suggested = 'true'; }
      else if (/^spring\.(data\.)?redis\.ssl$/.test(nk) && isFalse(v)) { why = 'SSL/TLS is disabled'; suggested = 'true'; }
      else if (/security\.protocol$/.test(nk) && /^plaintext$/i.test(v.trim())) { why = 'the Kafka security protocol is PLAINTEXT'; suggested = 'SSL'; }
      else if (/starttls\.(enable|required)$/.test(nk) && isFalse(v)) { why = 'STARTTLS is disabled'; suggested = 'true'; }
      else if (/mail\.smtp\.ssl\.trust$/.test(nk) && v.trim() === '*') { why = 'the SMTP server certificate is trusted unconditionally'; severity = 'high'; }
      if (why) {
        hits.push({
          entry: e, severity,
          message: `\`${e.key}\`: ${why}, so data travels unencrypted or unauthenticated.`,
          fix: suggested ? `Set \`${e.key}=${suggested}\` and configure trust/key material for the remote service.` : 'Trust only the specific host or a private CA in a trust store.',
          suggestedValue: suggested,
        });
      }
    }
    return hits;
  },
};

const jdbcInsecure: Rule = {
  id: 'SB-TLS-008', title: 'Database connection without verified TLS', severity: 'medium', category: 'Transport security', cwe: 319,
  check(ctx) {
    const patterns: [RegExp, string][] = [
      [/[?;&]useSSL=false/i, 'useSSL=false'],
      [/[?;&]sslmode=(disable|allow|prefer)/i, 'sslmode=disable/allow/prefer'],
      [/[?;&]ssl=false/i, 'ssl=false'],
      [/[?;&]tls=false/i, 'tls=false'],
      [/[?;&]encrypt=false/i, 'encrypt=false'],
      [/[?;&]verifyServerCertificate=false/i, 'verifyServerCertificate=false'],
      [/[?;&]trustServerCertificate=true/i, 'trustServerCertificate=true'],
      [/[?;&]tlsAllowInvalid(Certificates|Hostnames)=true/i, 'tlsAllowInvalid*=true'],
      [/[?;&]allowPublicKeyRetrieval=true/i, 'allowPublicKeyRetrieval=true'],
    ];
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      if (!/^(jdbc:|mongodb(\+srv)?:|r2dbc:|redis:|amqp:)/i.test(e.value.trim())) continue;
      const found = patterns.filter(([re]) => re.test(e.value)).map(([, label]) => label);
      if (found.length) {
        hits.push({
          entry: e,
          message: `\`${e.key}\` connects without verified TLS (${found.join(', ')}).`,
          fix: 'Require encryption and certificate verification in the connection URL (e.g. `sslmode=verify-full`, `useSSL=true&requireSSL=true`, `encrypt=true;trustServerCertificate=false`) and trust the database CA.',
        });
      }
    }
    return hits;
  },
};

const plainHttp: Rule = {
  id: 'SB-TLS-009', title: 'Plaintext endpoint URL', severity: 'low', category: 'Transport security', cwe: 319,
  check(ctx) {
    const local = /^(localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i;
    const hits: Hit[] = [];
    for (const e of ctx.entries) {
      const re = /(?:^|[,\s])((?:http|ws|ldap|ftp):\/\/)(?:[^/@\s]*@)?([^/:,\s]+)/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(e.value))) {
        if (m[2].startsWith('$') || local.test(m[2])) continue;
        const scheme = m[1].toLowerCase();
        const secure = scheme === 'http://' ? 'https://' : scheme === 'ws://' ? 'wss://' : scheme === 'ldap://' ? 'ldaps://' : 'sftp://';
        hits.push({
          entry: e,
          severity: /(eureka|config|issuer|jwk|ldap|oauth|auth|uri|url)/.test(normKey(e.key)) ? 'medium' : 'low',
          message: `\`${e.key}\` points to \`${scheme}${m[2]}\`, which is not encrypted.`,
          fix: `Use \`${secure}\` for non-local endpoints.`,
          suggestedValue: e.multiline ? undefined : e.value.replace(new RegExp(`^${scheme}`, 'i'), secure),
        });
        break;
      }
    }
    return hits;
  },
};

// ---------------------------------------------------------------- error disclosure

const stacktraceExposed = kv({
  id: 'SB-ERR-001', title: 'Stack traces returned to clients', severity: 'high', category: 'Information disclosure', cwe: 209,
  keys: /^server\.error\.includestacktrace$/,
  test: (v) => ['always', 'onparam', 'ontracetrace'].includes(normVal(v)),
  severityOf: (v) => (normVal(v) === 'always' ? 'high' : 'medium'),
  message: (e) => `\`${e.key}=${e.value.trim()}\` exposes stack traces (internal class names, paths, library versions) in error responses.`,
  fix: 'Set `server.error.include-stacktrace=never` and log exceptions server-side instead.',
  suggested: 'never',
});

const errorDetailExposed = kv({
  id: 'SB-ERR-002', title: 'Exception details returned to clients', severity: 'medium', category: 'Information disclosure', cwe: 209,
  keys: /^server\.error\.(includemessage|includebindingerrors|includeexception)$/,
  test: (v, e) => (/exception$/.test(normKey(e.key)) ? isTrue(v) : ['always', 'onparam'].includes(normVal(v))),
  message: (e) => `\`${e.key}=${e.value.trim()}\` leaks exception or validation details in error responses.`,
  fix: (e) => (/exception$/.test(normKey(e.key)) ? 'Set `false`.' : 'Set `never`.'),
  suggested: (e) => (/exception$/.test(normKey(e.key)) ? 'false' : 'never'),
});

const stacktraceNotExplicit: Rule = {
  id: 'SB-ERR-003', title: 'Stack trace exposure not explicitly disabled', severity: 'low', category: 'Information disclosure', cwe: 209,
  check(ctx) {
    if (!ctx.checkAbsent || ctx.entries.length === 0 || ctx.get('server.error.includestacktrace')) return [];
    return [{
      message: '`server.error.include-stacktrace` is not set. Newer Spring Boot versions default to `never`, but older ones and some overrides do not.',
      fix: 'Pin it explicitly: `server.error.include-stacktrace=never`.',
      addProperty: { key: 'server.error.include-stacktrace', value: 'never' },
    }];
  },
};

// ---------------------------------------------------------------- actuator

const HIGH_ENDPOINTS = ['env', 'heapdump', 'threaddump', 'shutdown', 'jolokia', 'logfile', 'configprops', 'loggers'];
const MED_ENDPOINTS = ['beans', 'mappings', 'httptrace', 'httpexchanges', 'sessions', 'caches', 'auditevents', 'conditions', 'scheduledtasks', 'flyway', 'liquibase', 'quartz'];

const actuatorExposure: Rule = {
  id: 'SB-ACT-001', title: 'Sensitive actuator endpoints exposed', severity: 'high', category: 'Actuator', cwe: 200,
  check(ctx) {
    const hits: Hit[] = [];
    const entries = ctx.entries.filter((e) => /^management\.endpoints\.web\.exposure\.include(\[\d+\])?$/.test(normKey(e.key)));
    if (entries.length === 0) return hits;
    const names = entries.flatMap((e) => e.value.split(',').map((s) => s.trim().toLowerCase())).filter(Boolean);
    const target = entries[0];
    if (names.includes('*')) {
      hits.push({
        entry: target, severity: 'high',
        message: '`management.endpoints.web.exposure.include=*` exposes every actuator endpoint, including `env`, `heapdump` and `configprops`.',
        fix: 'Expose only what you need and secure the rest: `management.endpoints.web.exposure.include=health,info`. Put actuator on a separate management port behind authentication.',
        suggestedValue: entries.length === 1 ? 'health,info' : undefined,
      });
      return hits;
    }
    const high = names.filter((n) => HIGH_ENDPOINTS.includes(n));
    const med = names.filter((n) => MED_ENDPOINTS.includes(n));
    if (high.length || med.length) {
      hits.push({
        entry: target, severity: high.length ? 'high' : 'medium',
        message: `Exposed actuator endpoints reveal internals or allow control: ${[...high, ...med].join(', ')}.`,
        fix: 'Remove sensitive endpoints from the exposure list and require authentication (e.g. `management.endpoints.web.exposure.include=health,info`).',
      });
    }
    return hits;
  },
};

const healthDetails = kv({
  id: 'SB-ACT-002', title: 'Health details visible to everyone', severity: 'medium', category: 'Actuator', cwe: 200,
  keys: /^management\.endpoint\.health\.show(details|components)$/,
  test: (v) => normVal(v) === 'always',
  message: (e) => `\`${e.key}=always\` shows component details (database, disk, brokers) to unauthenticated callers.`,
  fix: 'Use `when-authorized` (and restrict roles with `management.endpoint.health.roles`) or `never`.',
  suggested: 'when-authorized',
});

const dangerousEndpointEnabled = kv({
  id: 'SB-ACT-003', title: 'Dangerous actuator endpoint enabled', severity: 'high', category: 'Actuator', cwe: 749,
  keys: /^management\.endpoint\.(shutdown|env|configprops|heapdump|jolokia)\.(enabled|access|showvalues)$/,
  test: (v, e) => (/showvalues$/.test(normKey(e.key)) ? normVal(v) === 'always' : /access$/.test(normKey(e.key)) ? normVal(v) === 'unrestricted' : isTrue(v)),
  message: (e) => `\`${e.key}=${e.value.trim()}\` turns on an endpoint that can leak secrets or stop the application.`,
  fix: (e) => (/showvalues$/.test(normKey(e.key)) ? 'Use `when-authorized` or `never`.' : 'Disable it (`enabled=false` / `access=none`) unless it is behind strong authentication.'),
  suggested: (e) => (/showvalues$/.test(normKey(e.key)) ? 'when-authorized' : /access$/.test(normKey(e.key)) ? 'none' : 'false'),
});

const securityDisabled = kv({
  id: 'SB-ACT-004', title: 'Security switched off', severity: 'high', category: 'Actuator', cwe: 306,
  keys: /^(management\.security\.enabled|security\.basic\.enabled|security\.enablecsrf)$/,
  test: isFalse,
  message: (e) => `\`${e.key}=false\` disables authentication/CSRF protection.`,
  fix: 'Remove the property and secure endpoints with Spring Security.',
  suggested: 'true',
});

// ---------------------------------------------------------------- debug / dev features

const debugEnabled = kv({
  id: 'SB-DBG-001', title: 'Debug or trace mode enabled', severity: 'medium', category: 'Debugging', cwe: 489,
  keys: /^(debug|trace)$/, test: isTrue,
  message: (e) => `\`${e.key}=true\` enables verbose framework diagnostics.`,
  fix: 'Remove it from production configuration.',
  suggested: 'false',
});

const verboseLogging = kv({
  id: 'SB-DBG-002', title: 'Verbose logging may leak sensitive data', severity: 'medium', category: 'Debugging', cwe: 532,
  keys: /^logging\.level\.(root|org\.springframework\.(security|web)|org\.hibernate\.(sql|type.*)|org\.apache\.http(\.wire)?|org\.apache\.hc.*)$/,
  test: (v) => ['debug', 'trace', 'all'].includes(v.trim().toLowerCase()),
  message: (e) => `\`${e.key}=${e.value.trim()}\` logs request details, SQL parameters or security decisions that can contain credentials and personal data.`,
  fix: 'Use `INFO` or `WARN` in production; raise levels temporarily and only per-package when troubleshooting.',
  suggested: 'WARN',
});

const requestDetails = kv({
  id: 'SB-DBG-003', title: 'Request details logged', severity: 'medium', category: 'Debugging', cwe: 532,
  keys: /^spring\.mvc\.logrequestdetails$/, test: isTrue,
  message: () => '`spring.mvc.log-request-details=true` writes headers and parameters (tokens, cookies) to the log.',
  fix: 'Disable it in production.',
  suggested: 'false',
});

const showSql = kv({
  id: 'SB-DBG-004', title: 'SQL statements logged', severity: 'low', category: 'Debugging', cwe: 532,
  keys: /^spring\.jpa\.(showsql|properties\.hibernate\.showsql)$/, test: isTrue,
  message: (e) => `\`${e.key}=true\` prints SQL to stdout, bypassing the logging configuration.`,
  fix: 'Disable it and use a logger with an appropriate level if needed.',
  suggested: 'false',
});

const h2Console = kv({
  id: 'SB-DBG-005', title: 'H2 web console enabled', severity: 'high', category: 'Debugging', cwe: 489,
  keys: /^spring\.h2\.console\.(enabled|settings\.weballowothers)$/, test: isTrue,
  severityOf: (_v, e) => (/weballowothers$/.test(normKey(e.key)) ? 'critical' : 'high'),
  message: (e) => (/weballowothers$/.test(normKey(e.key))
    ? '`web-allow-others=true` lets remote hosts reach the H2 console, which allows remote code execution.'
    : '`spring.h2.console.enabled=true` exposes a database admin UI.'),
  fix: 'Disable the H2 console outside local development.',
  suggested: 'false',
});

const ddlAuto = kv({
  id: 'SB-DBG-006', title: 'Schema auto-generation enabled', severity: 'medium', category: 'Debugging', cwe: 1188,
  keys: /^spring\.jpa\.(hibernate\.ddlauto|properties\.hibernate\.hbm2ddl\.auto)$/,
  test: (v) => ['create', 'createdrop', 'update'].includes(normVal(v)),
  severityOf: (v) => (['create', 'createdrop'].includes(normVal(v)) ? 'high' : 'medium'),
  message: (e) => `\`${e.key}=${e.value.trim()}\` lets Hibernate alter${/create/i.test(e.value) ? ' or drop' : ''} the production schema at startup.`,
  fix: 'Use `validate` or `none` and manage schema changes with Flyway or Liquibase migrations.',
  suggested: 'validate',
});

const apiExplorers = kv({
  id: 'SB-DBG-007', title: 'API explorer / documentation exposed', severity: 'low', category: 'Debugging', cwe: 200,
  keys: /^(spring\.graphql\.graphiql\.enabled|springdoc\.(swaggerui|apidocs)\.enabled)$/, test: isTrue,
  message: (e) => `\`${e.key}=true\` publishes an interactive API explorer or API schema.`,
  fix: 'Disable it in production or restrict it to authenticated administrators.',
  suggested: 'false',
});

// ---------------------------------------------------------------- web / session

const cookieNotSecure = kv({
  id: 'SB-WEB-001', title: 'Session cookie not marked Secure', severity: 'medium', category: 'Web & session', cwe: 614,
  keys: /^server\.servlet\.session\.cookie\.secure$/, test: isFalse,
  message: () => 'The session cookie can be sent over plain HTTP.',
  fix: 'Set `server.servlet.session.cookie.secure=true`.',
  suggested: 'true',
});

const cookieSecureUnset: Rule = {
  id: 'SB-WEB-002', title: 'Session cookie Secure flag not set', severity: 'low', category: 'Web & session', cwe: 614,
  check(ctx) {
    if (!ctx.checkAbsent || ctx.entries.length === 0 || ctx.get('server.servlet.session.cookie.secure')) return [];
    return [{
      message: '`server.servlet.session.cookie.secure` is not set; the session cookie may be sent over HTTP.',
      fix: 'Set `server.servlet.session.cookie.secure=true`.',
      addProperty: { key: 'server.servlet.session.cookie.secure', value: 'true' },
    }];
  },
};

const cookieHttpOnly = kv({
  id: 'SB-WEB-003', title: 'Session cookie readable by scripts', severity: 'medium', category: 'Web & session', cwe: 1004,
  keys: /^server\.servlet\.session\.cookie\.httponly$/, test: isFalse,
  message: () => '`http-only=false` lets JavaScript read the session cookie, making XSS far more damaging.',
  fix: 'Set `server.servlet.session.cookie.http-only=true`.',
  suggested: 'true',
});

const cookieSameSite = kv({
  id: 'SB-WEB-004', title: 'Session cookie SameSite=None', severity: 'low', category: 'Web & session', cwe: 1275,
  keys: /^server\.servlet\.session\.cookie\.samesite$/, test: (v) => normVal(v) === 'none',
  message: () => '`same-site=none` sends the session cookie on cross-site requests, enabling CSRF.',
  fix: 'Use `lax` (or `strict`) unless cross-site embedding is required.',
  suggested: 'lax',
});

const urlSessions = kv({
  id: 'SB-WEB-005', title: 'Session ID allowed in URL', severity: 'medium', category: 'Web & session', cwe: 598,
  keys: /^server\.servlet\.session\.trackingmodes(\[\d+\])?$/, test: (v) => /(^|,)\s*url\s*(,|$)/i.test(v),
  message: () => 'URL session tracking leaks session IDs through logs, referrers and browser history.',
  fix: 'Use `server.servlet.session.tracking-modes=cookie`.',
  suggested: 'cookie',
});

const corsWildcard = kv({
  id: 'SB-WEB-006', title: 'CORS allows any origin', severity: 'medium', category: 'Web & session', cwe: 942,
  keys: /allowedorigin(s|patterns)(\[\d+\])?$/, test: (v) => v.split(',').some((s) => s.trim() === '*'),
  message: (e) => `\`${e.key}\` allows requests from any origin.`,
  fix: 'List the exact origins that need access, e.g. `https://app.example.com`.',
});

// ---------------------------------------------------------------- crypto

const weakAlgorithm = kv({
  id: 'SB-CRY-001', title: 'Weak cryptographic algorithm', severity: 'medium', category: 'Cryptography', cwe: 327,
  keys: /^(?!server\.ssl).*(algorithm|digest|hashalgorithm|cipher)$/,
  test: (v) => /(^|[^a-z0-9])(md5|sha-?1|des|rc4|md2)([^a-z0-9]|$)|pbewithmd5|withdes/i.test(v),
  message: (e) => `\`${e.key}=${e.value.trim()}\` uses a broken or weak algorithm.`,
  fix: 'Use a modern algorithm such as AES-256-GCM, SHA-256+ or PBEWITHHMACSHA512ANDAES_256.',
});

export const RULES: Rule[] = [
  hardcodedSecret, placeholderDefault, credentialsInUrl, emptyPassword, defaultDbUser,
  sslDisabled, sslNotConfigured, sslEnabledImplicit, tlsUnspecified, weakProtocol, weakCipher, certValidationOff, clientTlsOff, jdbcInsecure, plainHttp,
  stacktraceExposed, errorDetailExposed, stacktraceNotExplicit,
  actuatorExposure, healthDetails, dangerousEndpointEnabled, securityDisabled,
  debugEnabled, verboseLogging, requestDetails, showSql, h2Console, ddlAuto, apiExplorers,
  cookieNotSecure, cookieSecureUnset, cookieHttpOnly, cookieSameSite, urlSessions, corsWildcard,
  weakAlgorithm,
];
