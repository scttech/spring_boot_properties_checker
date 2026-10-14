<p align="center"><img src="images/icon.png" alt="Spring Boot Security Checker" width="160"></p>

# Spring Boot Security Checker

Flags production security problems in Spring Boot `application*.properties`, `application*.yml/.yaml` and `bootstrap*` files as you edit them, and produces a findings report.

## What it checks (36 rules)

| Category | Examples |
|---|---|
| Secrets | hardcoded passwords/tokens/API keys (prefer `${ENV_VAR}`), well-known default passwords, cloud keys/private keys/JWTs, credentials in URLs, secret placeholders with a hardcoded fallback, empty passwords, `root`/`sa` DB users |
| Transport security | `server.ssl.enabled=false`, TLS not configured, `enabled-protocols` missing, SSLv3/TLS 1.0/1.1, weak ciphers, disabled certificate/hostname verification, `useSSL=false` / `sslmode=disable` in JDBC URLs, plaintext `http://` endpoints |
| Information disclosure | `server.error.include-stacktrace=always/on_param`, exposed exception/message/binding details, stack-trace setting not pinned |
| Actuator | `exposure.include=*`, `env`/`heapdump`/`shutdown`… exposed, `show-details=always`, security disabled |
| Debugging | `debug=true`, `DEBUG`/`TRACE` logging, `show-sql`, H2 console, `ddl-auto=create/update`, GraphiQL/Swagger |
| Web & session | cookie `Secure`/`HttpOnly`/`SameSite`, URL session tracking, CORS `*` |
| Cryptography | MD5/SHA-1/DES/RC4 algorithms |

Property names follow Spring relaxed binding (`include-stacktrace`, `includeStacktrace`, `INCLUDE_STACKTRACE`).
"Setting is missing" checks (e.g. no `server.ssl.*`) run only on the base `application.*` file and `prod`/`production` profile files.

## Install

Build the package (`npm install && npm run package`), then install the generated `.vsix`:

```
code --install-extension spring-boot-security-checker-0.1.0.vsix --force
```

Or in VS Code: Extensions view → `...` menu → *Install from VSIX...*. Reload the window afterwards. `--force` replaces an already-installed copy of the same version.

## Usage

* Findings show as squiggles and in the Problems panel; hover for the recommended fix.
* **Quick fixes** (`Ctrl+.`): set a safe value, replace a secret with `${ENV_VAR}`, add a missing property (.properties), or suppress.
* **Report**: command palette → *Spring Boot Security: Show Report* (or click the status bar item). Filter by severity or text, click a row to jump to the line, export to Markdown.
* Suppress a finding with a comment on the line above: `# sbsec-ignore: SB-TLS-002` (omit the ID to suppress everything on that line).
* Secret values are never shown in diagnostics or the report; only the key name is.

## Settings

`springBootSecurity.enable`, `.minimumSeverity`, `.disabledRules`, `.fileNamePattern`, `.scanWorkspaceOnStartup`.

## Development

```
npm install
npm test          # rule tests
npm run build
# press F5 to launch an Extension Development Host on ./samples
npm run package   # builds a .vsix
```

Rules live in `src/rules.ts`; each is a small function over the flattened key/value entries.
