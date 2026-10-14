import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/analyzer';

const ids = (text: string, file = 'application-dev.properties') => analyze(text, file).map((f) => f.ruleId);

test('hardcoded secrets are flagged, placeholders and ENC() are not', () => {
  assert.deepEqual(ids('spring.datasource.password=Sup3rS3cret!'), ['SB-SEC-001']);
  assert.deepEqual(ids('spring.datasource.password=${DB_PASSWORD}'), []);
  assert.deepEqual(ids('spring.datasource.password=ENC(abc123)'), []);
  assert.deepEqual(ids('spring.security.oauth2.client.provider.x.token-uri=https://x/token'), []);
});

test('well-known passwords are critical; fallbacks in placeholders are flagged', () => {
  assert.equal(analyze('jwt.secret=changeme', 'application-dev.properties')[0].severity, 'critical');
  assert.deepEqual(ids('app.api-key=${API_KEY:abc123}'), ['SB-SEC-002']);
});

test('token patterns and URL credentials', () => {
  const f = analyze('aws.id=AKIAABCDEFGHIJKLMNOP', 'application-dev.properties');
  assert.equal(f[0].severity, 'critical');
  assert.deepEqual(ids('spring.datasource.url=jdbc:mysql://h/db?user=a&password=pw&useSSL=false'), ['SB-SEC-003', 'SB-TLS-008']);
  assert.deepEqual(ids('x.url=https://bob:pw@example.com/a'), ['SB-SEC-003']);
});

test('TLS: disabled, weak protocols, unspecified', () => {
  assert.deepEqual(ids('server.ssl.enabled=false'), ['SB-TLS-001']);
  assert.deepEqual(ids('server.ssl.enabled=true\nserver.ssl.key-store=a.p12', 'application-dev.properties'), ['SB-TLS-003']);
  assert.deepEqual(ids('server.ssl.enabled=true\nserver.ssl.enabled-protocols=TLSv1.2,TLSv1.3'), []);
  assert.deepEqual(ids('server.ssl.enabled=true\nserver.ssl.enabled-protocols=TLSv1,TLSv1.2'), ['SB-TLS-004']);
  assert.deepEqual(ids('server.ssl.enabled=true\nserver.ssl.enabled-protocols=TLSv1.1'), ['SB-TLS-004']);
  assert.deepEqual(ids('server.ssl.enabled=true\nserver.ssl.enabled-protocols=TLSv1.3\nserver.ssl.ciphers=TLS_RSA_WITH_RC4_128_SHA'), ['SB-TLS-005']);
});

test('missing-setting checks only apply to base and prod files', () => {
  const base = ids('server.port=8443', 'application.properties');
  assert.ok(base.includes('SB-TLS-002') && base.includes('SB-ERR-003') && base.includes('SB-WEB-002'));
  assert.deepEqual(ids('server.port=8443', 'application-dev.properties'), []);
  assert.ok(ids('server:\n  port: 8443', 'application-prod.yml').includes('SB-TLS-002'));
});

test('stack traces and error details', () => {
  const [f] = analyze('server.error.include-stacktrace=always', 'application-dev.properties');
  assert.equal(f.ruleId, 'SB-ERR-001');
  assert.equal(f.severity, 'high');
  assert.equal(f.suggestedValue, 'never');
  assert.equal(analyze('server.error.include-stacktrace=on_param', 'application-dev.properties')[0].severity, 'medium');
  assert.deepEqual(ids('server.error.include-stacktrace=never'), []);
  assert.deepEqual(ids('server.error.include-message=always'), ['SB-ERR-002']);
});

test('relaxed binding: case, dashes and underscores', () => {
  assert.deepEqual(ids('SERVER.ERROR.INCLUDE_STACKTRACE=ALWAYS'), ['SB-ERR-001']);
});

test('actuator', () => {
  assert.deepEqual(ids('management.endpoints.web.exposure.include=*'), ['SB-ACT-001']);
  assert.deepEqual(ids('management.endpoints.web.exposure.include=health,info'), []);
  assert.deepEqual(ids('management.endpoints.web.exposure.include=health,env'), ['SB-ACT-001']);
  assert.deepEqual(ids('management.endpoint.health.show-details=always'), ['SB-ACT-002']);
  assert.deepEqual(ids('management.endpoint.shutdown.enabled=true'), ['SB-ACT-003']);
});

test('debug and dev features', () => {
  assert.deepEqual(ids('debug=true'), ['SB-DBG-001']);
  assert.deepEqual(ids('logging.level.root=DEBUG'), ['SB-DBG-002']);
  assert.deepEqual(ids('logging.level.com.acme=DEBUG'), []);
  assert.deepEqual(ids('spring.h2.console.enabled=true'), ['SB-DBG-005']);
  assert.equal(analyze('spring.h2.console.settings.web-allow-others=true', 'application-dev.properties')[0].severity, 'critical');
  assert.deepEqual(ids('spring.jpa.hibernate.ddl-auto=create-drop'), ['SB-DBG-006']);
  assert.deepEqual(ids('spring.jpa.hibernate.ddl-auto=validate'), []);
});

test('web/session/cors', () => {
  assert.deepEqual(ids('server.servlet.session.cookie.secure=false'), ['SB-WEB-001']);
  assert.deepEqual(ids('server.servlet.session.cookie.http-only=false'), ['SB-WEB-003']);
  assert.deepEqual(ids('management.endpoints.web.cors.allowed-origins=*'), ['SB-WEB-006']);
});

test('plaintext http endpoints ignore localhost', () => {
  assert.deepEqual(ids('eureka.client.service-url.defaultZone=http://eureka.corp:8761/eureka'), ['SB-TLS-009']);
  assert.deepEqual(ids('eureka.client.service-url.defaultZone=http://localhost:8761/eureka'), []);
});

test('sbsec-ignore suppresses findings', () => {
  assert.deepEqual(ids('# sbsec-ignore: SB-ERR-001\nserver.error.include-stacktrace=always'), []);
  assert.deepEqual(ids('# sbsec-ignore: SB-TLS-001\nserver.error.include-stacktrace=always'), ['SB-ERR-001']);
  assert.deepEqual(analyze('# sbsec-ignore\nserver.port=1', 'application.properties'), []);
});

test('disabled rules option', () => {
  assert.deepEqual(analyze('debug=true', 'application-dev.properties', { disabledRules: ['sb-dbg-001'] }), []);
});

test('properties ranges and continuation lines', () => {
  const [f] = analyze('# c\nspring.datasource.password = abc', 'application-dev.properties');
  assert.equal(f.range.line, 1);
  assert.deepEqual(f.valueRange, { line: 1, startCol: 29, endCol: 32 });
  const [g] = analyze('spring.datasource.password=ab\\\ncd', 'application-dev.properties');
  assert.equal(g.range.line, 0);
  assert.equal(g.valueRange, undefined);
});

test('yaml: nesting, lists, multi-doc, positions', () => {
  const yml = [
    'server:',
    '  error:',
    '    include-stacktrace: always',
    'management:',
    '  endpoints:',
    '    web:',
    '      exposure:',
    '        include:',
    '          - health',
    '          - env',
    '---',
    'spring:',
    '  datasource:',
    '    password: "hunter2"',
    '    username:',
  ].join('\n');
  const f = analyze(yml, 'application-dev.yml');
  assert.deepEqual(f.map((x) => x.ruleId).sort(), ['SB-ACT-001', 'SB-ERR-001', 'SB-SEC-001']);
  const st = f.find((x) => x.ruleId === 'SB-ERR-001')!;
  assert.equal(st.range.line, 2);
  assert.deepEqual(st.valueRange, { line: 2, startCol: 24, endCol: 30 });
  const pw = f.find((x) => x.ruleId === 'SB-SEC-001')!;
  assert.equal(pw.range.line, 13);
  assert.deepEqual(pw.valueRange, { line: 13, startCol: 14, endCol: 23 });
  assert.equal(pw.suggestedValue, '${SPRING_DATASOURCE_PASSWORD}');
});

test('yaml: invalid input does not throw', () => {
  assert.doesNotThrow(() => analyze('a: [1, 2\n  b: : :', 'application.yml'));
});

test('server.ssl.enabled left implicit is a low-severity note', () => {
  const f = analyze('server.ssl.key-store=a.p12\nserver.ssl.enabled-protocols=TLSv1.3', 'application.properties')
    .filter((x) => x.ruleId === 'SB-TLS-010');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'low');
  assert.equal(f[0].addProperty?.key, 'server.ssl.enabled');
  assert.ok(!ids('server.ssl.enabled=true\nserver.ssl.enabled-protocols=TLSv1.3', 'application.properties').includes('SB-TLS-010'));
  assert.ok(!ids('server.ssl.key-store=a.p12', 'application-dev.properties').includes('SB-TLS-010'));
});
