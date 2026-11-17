import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze, extractUrls, analyzeText } from '../docs/core.js';

const brands = JSON.parse(readFileSync(new URL('../docs/brands.json', import.meta.url))).brands;
const run = (sender, extra = '', headers = '', threats = new Set(), links = '') =>
  analyze({ sender, extra, headers, brands, threats, links });
const has = (r, level, frag) => r.findings.some((f) => f.level === level && f.text.includes(frag));

test('dominio ufficiale', () => {
  assert.equal(run('avvisi@inps.it').level, 'ok');
  assert.equal(run('noreply@comunicazioni.inps.it').level, 'ok');
});
test('dominio che contiene il brand', () => {
  assert.equal(run('info@inps-rimborsi.it').level, 'danger');
  assert.equal(run('a@inps.it.evil.com').level, 'danger');
  assert.equal(run('a@mediaw0rld.it').level, 'danger');
});
test('nome mostrato falso su dominio libero', () => {
  assert.equal(run('INPS <rimborsi@gmail.com>').level, 'danger');
});
test('sosia', () => {
  assert.equal(run('a@inpss.it').level, 'warn');
  assert.ok(['warn', 'danger'].includes(run('a@xn--inps-9ra.it').level));
});
test('spoofing su dominio ufficiale', () => {
  const h = 'Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail\nFrom: MediaWorld <a@mediaworld.it>';
  assert.equal(run('a@mediaworld.it', '', h).level, 'danger');
});
test('autenticazione valida su dominio ufficiale', () => {
  const h = 'Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\nFrom: a@paypal.com';
  assert.equal(run('a@paypal.com', '', h).level, 'ok');
});
test('brand sconosciuto', () => {
  assert.equal(run('mario@gmail.com').level, 'unknown');
});
test('feed minacce', () => {
  assert.equal(run('x@sub.random-site.xyz', '', '', new Set(['random-site.xyz'])).level, 'danger');
});
test('indirizzo non valido', () => {
  assert.equal(run('non un indirizzo').level, 'unknown');
});

// ---- novita' ----
test('link: trucco del nome@', () => {
  const r = run('avvisi@inps.it', '', '', new Set(), 'https://inps.it@evil.example/login');
  assert.equal(r.level, 'danger');
  assert.ok(has(r, 'danger', 'nome@'));
});
test('link: dominio che imita il brand', () => {
  const r = run('mario@gmail.com', '', '', new Set(), 'https://inps-rimborsi.example.com/x');
  assert.equal(r.level, 'danger');
});
test('link: accorciatore, IP, http', () => {
  assert.ok(has(run('a@gmail.com', '', '', new Set(), 'https://bit.ly/abc'), 'warn', 'accorciato'));
  assert.ok(has(run('a@gmail.com', '', '', new Set(), 'http://192.168.1.5/login'), 'danger', 'numerico'));
  assert.ok(has(run('a@gmail.com', '', '', new Set(), 'http://example.org/x'), 'warn', 'HTTPS'));
});
test('link: sito diverso da quello ufficiale quando il mittente e\' ufficiale', () => {
  const r = run('avvisi@inps.it', '', '', new Set(), 'https://altro-sito.example.org/pagina');
  assert.ok(has(r, 'warn', 'fuori dai domini ufficiali'));
});
test('link: link ufficiali sono ok', () => {
  const r = run('avvisi@inps.it', '', '', new Set(), 'https://www.inps.it/it/it.html');
  assert.equal(r.level, 'ok');
});
test('link: elenco minacce', () => {
  const r = run('a@gmail.com', '', '', new Set(['truffa.example']), 'https://login.truffa.example/x');
  assert.equal(r.level, 'danger');
});
test('estrazione link dal testo', () => {
  assert.deepEqual(extractUrls('clicca https://a.it/x, oppure www.b.it.'), ['https://a.it/x', 'www.b.it']);
});
test('testo: servono almeno due segnali', () => {
  assert.equal(analyzeText('Ciao, ti scrivo per la riunione').length, 0);
  assert.equal(analyzeText('Il tuo conto verrà sospeso. Conferma i tuoi dati entro 24 ore').length, 1);
});
test('testo: allegati rischiosi', () => {
  assert.equal(analyzeText('Apri la fattura allegata fattura_123.zip').length, 1);
});
test('testo sospetto da dominio ufficiale abbassa il verdetto', () => {
  const r = run('avvisi@inps.it', 'Il tuo account sarà sospeso, conferma i tuoi dati entro 24 ore');
  assert.equal(r.level, 'warn');
});
test('brand a tre lettere: TIM', () => {
  assert.equal(run('a@tim.it').level, 'ok');
  assert.equal(run('a@tim-fattura.it').level, 'danger');
  assert.equal(run('Tim Rossi <tim@gmail.com>').level, 'unknown');
});

// ---- archivio brand ----
test('archivio brand coerente', () => {
  const ids = new Set(), domains = new Map();
  for (const b of brands) {
    assert.ok(b.id && b.name && Array.isArray(b.domains) && b.domains.length, b.id);
    assert.ok(!ids.has(b.id), 'id duplicato ' + b.id);
    ids.add(b.id);
    for (const d of b.domains) {
      assert.match(d, /^[a-z0-9.-]+\.[a-z]{2,}$/, 'dominio non valido ' + d);
      assert.ok(!domains.has(d), `dominio ${d} in ${b.id} e in ${domains.get(d)}`);
      domains.set(d, b.id);
    }
  }
});
