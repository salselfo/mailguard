import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze } from '../docs/core.js';

const brands = JSON.parse(readFileSync(new URL('../docs/brands.json', import.meta.url))).brands;
const run = (sender, extra = '', headers = '', threats = new Set()) => analyze({ sender, extra, headers, brands, threats });

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
