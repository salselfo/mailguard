// MailGuard core: funziona sia nel browser sia in Node.
const SEV = { ok: 0, unknown: 1, warn: 2, danger: 3 };

// Sostituzioni usate dai truffatori: mediaw0rld, paypa1, rnediaworld...
const HOMO = [[/rn/g, 'm'], [/vv/g, 'w'], [/0/g, 'o'], [/1/g, 'l'], [/3/g, 'e'], [/5/g, 's'], [/\$/g, 's'], [/\|/g, 'l']];

export function norm(s) {
  let t = (s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  for (const [r, v] of HOMO) t = t.replace(r, v);
  return t;
}

export function lev(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

export function parseSender(input) {
  const s = (input || '').trim();
  const m = s.match(/^(.*?)<([^>]+)>\s*$/);
  let display = '', email = s;
  if (m) {
    display = m[1].replace(/^["'\s]+|["'\s]+$/g, '');
    email = m[2].trim();
  }
  email = email.toLowerCase();
  const em = email.match(/^[^\s@]+@([^\s@]+\.[^\s@]+)$/);
  if (!em) return { valid: false, display, email, domain: '' };
  return { valid: true, display, email, domain: em[1].replace(/\.$/, '') };
}

export function registrable(d) {
  const p = d.split('.');
  if (p.length <= 2) return d;
  const sl = ['co', 'com', 'gov', 'org', 'net', 'edu'];
  if (p[p.length - 1].length === 2 && sl.includes(p[p.length - 2])) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}

export function isOfficial(domain, brand) {
  return brand.domains.some((d) => domain === d || domain.endsWith('.' + d));
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Nel testo si cercano nome e parole chiave di almeno 4 lettere: "Tim" da solo
// potrebbe essere una persona, quindi i brand corti usano frasi piu' lunghe.
function claimsBrand(text, brand) {
  const t = norm(text);
  if (!t.trim()) return false;
  const kws = [brand.name, ...(brand.keywords || [])].map((k) => norm(k).trim()).filter((k) => k.length >= 4);
  return kws.some((k) => new RegExp('(^|[^a-z0-9])' + esc(k) + '([^a-z0-9]|$)').test(t));
}

// 'contains' = il nome del brand compare nel dominio; 'lookalike' = dominio quasi identico.
export function imitation(domain, brand) {
  const body = norm(domain).split('.').slice(0, -1);
  const tokens = body.flatMap((l) => l.split(/[-_]/)).filter(Boolean);
  const kws = [...new Set([brand.name, ...(brand.keywords || [])]
    .map((k) => norm(k).replace(/[^a-z0-9]/g, '')).filter((k) => k.length >= 3))];
  const mains = brand.domains.map((d) => norm(d.split('.')[0])).filter((m) => m.length >= 5);
  let kind = null;
  for (const t of tokens) {
    for (const k of kws) {
      if (k.length === 3) {
        // nomi di tre lettere (es. TIM): sospetti solo se affiancati ad altre parole
        if (t === k) { if (tokens.length > 1) return 'contains'; kind = 'lookalike'; }
        continue;
      }
      if (t === k || (k.length >= 8 && t.includes(k))) return 'contains';
      if (t.startsWith(k)) kind = 'lookalike';
    }
  }
  for (const l of body) {
    for (const m of mains) {
      if (l !== m && lev(l, m) <= (m.length <= 6 ? 1 : 2)) kind = 'lookalike';
    }
  }
  return kind;
}

export function parseHeaders(raw) {
  const text = (raw || '').replace(/\r?\n[ \t]+/g, ' ');
  const first = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z-]+):\s*(.*)$/);
    if (m) {
      const k = m[1].toLowerCase();
      if (!(k in first)) first[k] = m[2]; // si considera solo l'intestazione piu' in alto, aggiunta dal tuo server
    }
  }
  const auth = first['authentication-results'] || '';
  const pick = (k) => {
    const m = auth.match(new RegExp('\\b' + k + '=([a-z]+)', 'i'));
    return m ? m[1].toLowerCase() : null;
  };
  let spf = pick('spf');
  if (!spf && first['received-spf']) spf = first['received-spf'].split(/\s+/)[0].toLowerCase();
  return {
    from: first['from'] || '',
    returnPath: first['return-path'] || '',
    replyTo: first['reply-to'] || '',
    spf, dkim: pick('dkim'), dmarc: pick('dmarc'),
    hasAuth: !!auth || !!first['received-spf'],
  };
}

function inThreats(domain, threats) {
  const p = domain.split('.');
  for (let i = 0; i < p.length - 1; i++) {
    const c = p.slice(i).join('.');
    if (threats.has(c)) return c;
  }
  return null;
}

export function summarize(findings) {
  let level = 'ok';
  for (const f of findings) if (SEV[f.level] > SEV[level]) level = f.level;
  return level;
}

// ---- Testo della mail: segnali tipici del phishing ----
const SIGNALS = [
  ['urgenza', /\b(entro\s+(?:le\s+)?\d+\s*(?:ore|giorni)|immediatamente|urgente|ultimo\s+(?:avviso|giorno|sollecito)|al piu presto)\b/],
  ['minaccia di blocco', /\b(sospes[oa]|bloccat[oa]|disattivat[oa]|limitat[oa]|chius[oa]|scadut[oa]|cancellat[oa])\b/],
  ['richiesta di dati', /\b(verific\w*|conferm\w*|aggiorn\w*|convalid\w*)\b[^.]{0,40}\b(dati|account|conto|carta|password|identita|accesso|credenziali)\b/],
  ['soldi o premi', /\b(rimborso|vincit\w*|premio|bonus|multa|pagamento in sospeso)\b/],
  ['invito a cliccare', /\b(clicc\w*|accedi|accedere|apri\s+il\s+link)\b[^.]{0,20}\b(qui|link|collegamento|sotto)\b/],
  ['codici o dati sensibili', /\b(otp|codice\s+di\s+(?:sicurezza|verifica)|pin|iban|numero\s+di\s+carta|cvv)\b/],
];
const BAD_ATTACH = /\b[\w.-]+\.(?:exe|scr|zip|rar|7z|iso|img|html?|js|vbs|lnk|jar|docm|xlsm|pptm|msi|apk)\b/i;

export function analyzeText(text) {
  const out = [];
  const t = (text || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  if (!t.trim()) return out;
  const hits = SIGNALS.filter(([, re]) => re.test(t)).map(([name]) => name);
  if (hits.length >= 2) {
    out.push({ level: 'warn', text: `Il testo usa tecniche tipiche del phishing: ${hits.join(', ')}.` });
  }
  const att = t.match(BAD_ATTACH);
  if (att) out.push({ level: 'warn', text: `Si parla di un allegato rischioso (${att[0]}): non aprirlo.` });
  return out;
}

// ---- Link ----
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rebrand.ly',
  'shorturl.at', 'tiny.cc', 'buff.ly', 'rb.gy', 't.ly', 'lnkd.in', 'short.io']);

export function extractUrls(text) {
  const m = (text || '').match(/(?:https?:\/\/|www\.)[^\s<>"'`)\]]+/gi) || [];
  return [...new Set(m.map((u) => u.replace(/[.,;:!?]+$/, '')))];
}

function parseUrl(u) {
  try {
    const url = new URL(/^https?:/i.test(u) ? u : 'http://' + u);
    return { host: url.hostname.toLowerCase().replace(/\.$/, ''), userinfo: !!(url.username || url.password), https: url.protocol === 'https:' };
  } catch (e) {
    return null;
  }
}

export function analyzeLinks({ text, brands = [], threats = new Set(), senderDomain = '', officialBrands = [] }) {
  const urls = extractUrls(text);
  const out = [];
  if (!urls.length) return out;
  const seen = new Set();
  const add = (level, msg) => { const k = level + msg; if (!seen.has(k)) { seen.add(k); out.push({ level, text: msg }); } };
  let problems = 0;
  for (const u of urls.slice(0, 15)) {
    const p = parseUrl(u);
    if (!p) continue;
    const h = p.host;
    const before = out.length;
    if (p.userinfo) add('danger', `Il link ${h} nasconde la vera destinazione dietro un "nome@": trucco classico del phishing.`);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) add('danger', `Un link punta a un indirizzo numerico (${h}) invece che a un sito.`);
    if (SHORTENERS.has(h)) add('warn', `Link accorciato (${h}): non si vede dove porta. Non aprirlo.`);
    if (!p.https) add('warn', `Il link verso ${h} non usa HTTPS.`);
    if (h.includes('xn--')) add('warn', `Il link verso ${h} usa caratteri speciali (punycode).`);
    const hit = inThreats(h, threats);
    if (hit) add('danger', `Il link verso ${hit} compare negli elenchi pubblici di phishing/malware.`);
    for (const b of brands) {
      if (isOfficial(h, b)) continue;
      const im = imitation(h, b);
      if (im === 'contains') add('danger', `Il link verso ${h} contiene il nome di ${b.name} ma non è un suo dominio ufficiale.`);
      else if (im === 'lookalike') add('warn', `Il link verso ${h} assomiglia a un dominio di ${b.name}.`);
    }
    for (const b of officialBrands) {
      if (!isOfficial(h, b) && registrable(h) !== registrable(senderDomain)) {
        add('warn', `Il link porta a ${h}, fuori dai domini ufficiali di ${b.name}. Le newsletter usano a volte siti di tracciamento, ma nel dubbio apri il sito scrivendo tu l'indirizzo.`);
      }
    }
    if (out.length > before) problems++;
  }
  // Alcuni enti dichiarano pubblicamente di non inviare mai link nelle email.
  if (urls.length) for (const b of officialBrands) {
    if (b.no_link_policy) add('ok', 'Nota: ' + b.no_link_policy);
  }
  if (!problems) add('ok', `Link controllati (${Math.min(urls.length, 15)}): nessun segnale evidente. Non significa che siano sicuri.`);
  if (urls.length > 15) add('unknown', `Ho controllato solo i primi 15 link su ${urls.length}.`);
  return out;
}

export function advice(level) {
  switch (level) {
    case 'danger': return 'Non cliccare, non rispondere e non aprire allegati. Cancella la mail e, se vuoi, segnalala su commissariatodips.it (Polizia Postale).';
    case 'warn': return 'Non fidarti finché non hai verificato: apri il sito dell\'ente scrivendo tu l\'indirizzo nel browser, senza usare i link della mail.';
    case 'ok': return 'Se la mail chiede dati, password o pagamenti, entra comunque dal sito ufficiale scrivendo tu l\'indirizzo.';
    default: return 'Non posso dirti se è sicura. Nel dubbio non cliccare i link e verifica dal sito ufficiale.';
  }
}

export function analyze({ sender, extra = '', links = '', headers = '', brands = [], threats = new Set() }) {
  const findings = [];
  const add = (level, text) => findings.push({ level, text });
  const h = headers.trim() ? parseHeaders(headers) : null;
  let s = parseSender(sender);
  if (!s.valid && h && h.from) s = parseSender(h.from);
  if (!s.valid) {
    return { level: 'unknown', sender: s, findings: [{ level: 'unknown', text: 'Indirizzo del mittente non valido.' }] };
  }
  const d = s.domain;
  const official = brands.filter((b) => isOfficial(d, b));
  const names = official.map((b) => b.name).join(', ');

  if (official.length) add('ok', `Il dominio ${d} è tra quelli ufficiali di ${names}.`);

  for (const b of brands) {
    if (official.includes(b)) continue;
    if (claimsBrand(s.display, b)) {
      add('danger', `Il mittente si presenta come ${b.name}, ma ${d} non è tra i suoi domini ufficiali.`);
    } else if (claimsBrand(extra, b)) {
      add('warn', `Il messaggio parla di ${b.name}, ma il mittente (${d}) non è un suo dominio ufficiale.`);
    }
    const im = imitation(d, b);
    if (im === 'contains') add('danger', `Il dominio ${d} contiene il nome di ${b.name} ma non è un suo dominio ufficiale: tipico del phishing.`);
    else if (im === 'lookalike') add('warn', `Il dominio ${d} assomiglia a quello di ${b.name} (${b.domains[0]}): controlla lettera per lettera.`);
  }

  if (d.includes('xn--')) add('warn', 'Il dominio usa caratteri speciali (punycode): può nascondere lettere ingannevoli.');

  const hit = inThreats(d, threats);
  if (hit) add('danger', `Il dominio ${hit} compare negli elenchi pubblici di phishing/malware.`);

  if (h) {
    const o = official.length > 0;
    if (!h.hasAuth) {
      add('warn', 'Nelle intestazioni non trovo i risultati SPF, DKIM e DMARC: non posso escludere lo spoofing.');
    } else {
      const keys = ['spf', 'dkim', 'dmarc'];
      const bad = keys.filter((k) => ['fail', 'softfail', 'permerror'].includes(h[k]));
      const good = keys.filter((k) => h[k] === 'pass');
      if (bad.length) {
        add(o ? 'danger' : 'warn',
          `Autenticazione fallita (${bad.map((k) => k.toUpperCase() + '=' + h[k]).join(', ')}): ` +
          (o ? 'il messaggio finge di arrivare da un dominio ufficiale, quasi certamente spoofing.' : 'il mittente non è verificabile.'));
      } else if (good.length) {
        add(o ? 'ok' : 'unknown', o
          ? `Autenticazione superata (${good.map((k) => k.toUpperCase()).join(', ')}): il messaggio arriva davvero da quel dominio.`
          : 'L\'autenticazione è valida, ma prova solo che il dominio è quello dichiarato, non che sia affidabile.');
      } else {
        add('unknown', 'Risultati SPF/DKIM/DMARC assenti o neutri.');
      }
    }
    const rp = parseSender(h.returnPath.replace(/[<>]/g, ''));
    if (rp.valid && registrable(rp.domain) !== registrable(d)) {
      add('warn', `Il percorso di ritorno (${rp.domain}) è diverso dal mittente: normale per le newsletter, sospetto altrove.`);
    }
    const rt = parseSender(h.replyTo);
    if (rt.valid && registrable(rt.domain) !== registrable(d)) {
      add('warn', `Le risposte andrebbero a ${rt.domain}, un dominio diverso dal mittente.`);
    }
    const hf = parseSender(h.from);
    if (hf.valid && registrable(hf.domain) !== registrable(d)) {
      add('warn', `Il mittente nelle intestazioni (${hf.domain}) non coincide con quello indicato (${d}).`);
    }
  } else if (official.length) {
    add('ok', 'Il solo indirizzo non esclude lo spoofing: incolla le intestazioni complete per il controllo definitivo.');
  }

  for (const f of analyzeText(`${s.display} ${extra}`)) findings.push(f);
  for (const f of analyzeLinks({ text: `${links} ${extra}`, brands, threats, senderDomain: d, officialBrands: official })) findings.push(f);

  if (!findings.length) {
    add('unknown', 'Brand non riconosciuto: non posso né confermare né smentire. Verifica a mano.');
  }
  return { level: summarize(findings), sender: s, findings };
}

// ---- Controlli online (DNS-over-HTTPS e RDAP), facoltativi ----
export async function dohTxt(name, f = globalThis.fetch) {
  const r = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    { headers: { accept: 'application/dns-json' } });
  const j = await r.json();
  return (j.Answer || []).filter((a) => a.type === 16)
    .map((a) => a.data.replace(/"\s+"/g, '').replace(/^"|"$/g, ''));
}

export async function dnsChecks(domain, { official = false, fetchImpl = globalThis.fetch } = {}) {
  const out = [];
  const reg = registrable(domain);
  try {
    const [t1, t2, dm] = await Promise.all([
      dohTxt(domain, fetchImpl),
      domain !== reg ? dohTxt(reg, fetchImpl) : Promise.resolve([]),
      dohTxt('_dmarc.' + reg, fetchImpl),
    ]);
    const spf = [...t1, ...t2].find((v) => /^v=spf1/i.test(v));
    const dmarc = dm.find((v) => /^v=DMARC1/i.test(v));
    const policy = dmarc ? (dmarc.match(/\bp=(\w+)/i) || [])[1] : null;
    if (!spf && !dmarc) {
      out.push({ level: official ? 'unknown' : 'warn', text: `Il dominio ${reg} non ha né SPF né DMARC: tipico dei domini improvvisati.` });
    } else if (official) {
      if (policy === 'reject' || policy === 'quarantine') {
        out.push({ level: 'ok', text: `Il dominio ufficiale ha DMARC "${policy}": i messaggi falsificati vengono bloccati dai provider che lo rispettano.` });
      } else {
        out.push({ level: 'unknown', text: 'Il dominio ufficiale non blocca la falsificazione (DMARC assente o "none"): il solo indirizzo vale poco, servono le intestazioni.' });
      }
    }
  } catch (e) {
    out.push({ level: 'unknown', text: 'Controlli DNS non disponibili al momento.' });
  }
  if (!official) {
    try {
      const r = await fetchImpl(`https://rdap.org/domain/${reg}`);
      const j = await r.json();
      const ev = (j.events || []).find((e) => e.eventAction === 'registration');
      if (ev) {
        const days = Math.floor((Date.now() - new Date(ev.eventDate).getTime()) / 86400000);
        if (days < 30) out.push({ level: 'danger', text: `Dominio registrato solo ${days} giorni fa.` });
        else if (days < 180) out.push({ level: 'warn', text: `Dominio registrato da soli ${days} giorni.` });
      }
    } catch (e) { /* RDAP e' best effort */ }
  }
  return out;
}
