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
    .map((k) => norm(k).replace(/[^a-z0-9]/g, '')).filter((k) => k.length >= 4))];
  const mains = brand.domains.map((d) => norm(d.split('.')[0]));
  let kind = null;
  for (const t of tokens) {
    for (const k of kws) {
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

export function analyze({ sender, extra = '', headers = '', brands = [], threats = new Set() }) {
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
        out.push({ level: 'unknown', text: 'Il dominio ufficiale non blocca la falsificazione (DMARC assente o "none"): controlla bene le intestazioni.' });
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
