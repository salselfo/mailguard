#!/usr/bin/env python3
"""Aggiornatore automatico di MailGuard.

Cosa fa ad ogni esecuzione:
1. Per ogni dominio ufficiale controlla SPF, DMARC e MX e segnala i cambiamenti.
2. Controlla (se indicate in brands.json) le pagine ufficiali di avviso phishing.
3. Scarica elenchi pubblici di phishing/malware e salva i domini segnalati.
4. NON aggiunge mai domini ufficiali da solo: li propone nel changelog.
Se la rete non risponde, non modifica nulla.
"""
import datetime
import hashlib
import json
import pathlib
import re
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DATA = DOCS / "data"
UA = {"User-Agent": "mailguard-updater/1.0"}
TYPES = {"TXT": 16, "A": 1, "MX": 15}

# URLhaus e' stato tolto: da giugno 2025 richiede una chiave personale (Auth-Key).
# "relevant": tiene solo i domini .it o che contengono il nome di un brand monitorato
# (serve per elenchi enormi, che non possono stare in una pagina web).
FEEDS = [
    {"name": "openphish", "url": "https://openphish.com/feed.txt", "kind": "urls"},
    {"name": "phishing-database",
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "kind": "domains", "relevant": True},
]
MAX_PER_FEED = 30000


def get(url, accept=None, timeout=25):
    headers = dict(UA)
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def doh(name, rtype):
    """Ritorna una lista di risposte, oppure None se la rete ha fallito."""
    url = "https://cloudflare-dns.com/dns-query?name=%s&type=%s" % (urllib.parse.quote(name), rtype)
    try:
        j = json.loads(get(url, accept="application/dns-json"))
    except Exception:
        return None
    return [a["data"].replace('" "', "").strip('"') for a in j.get("Answer", []) if a.get("type") == TYPES[rtype]]


def snapshot(domain):
    txt = doh(domain, "TXT")
    if txt is None:
        return None
    spf = next((v for v in txt if v.lower().startswith("v=spf1")), "")
    includes = sorted(re.findall(r"(?:include|redirect)[:=](\S+)", spf, re.I))
    dm = doh("_dmarc." + domain, "TXT") or []
    dmarc = next((v for v in dm if v.upper().startswith("V=DMARC1")), "")
    m = re.search(r"\bp=(\w+)", dmarc, re.I)
    mx = doh(domain, "MX")
    return {
        "spf_includes": includes,
        "dmarc_policy": m.group(1).lower() if m else None,
        "has_mx": bool(mx),
    }


def diff(old, new):
    out = []
    if not old:
        return out
    added = sorted(set(new["spf_includes"]) - set(old["spf_includes"]))
    removed = sorted(set(old["spf_includes"]) - set(new["spf_includes"]))
    if added:
        out.append(("spf", "nuovi mittenti autorizzati nello SPF: %s (da valutare, non aggiunti all'archivio)" % ", ".join(added)))
    if removed:
        out.append(("spf", "mittenti rimossi dallo SPF: %s" % ", ".join(removed)))
    if old["dmarc_policy"] != new["dmarc_policy"]:
        out.append(("dmarc", "politica DMARC cambiata da %s a %s" % (old["dmarc_policy"], new["dmarc_policy"])))
    if old["has_mx"] != new["has_mx"]:
        out.append(("mx", "record MX %s" % ("comparso" if new["has_mx"] else "sparito")))
    return out


def page_hash(url):
    try:
        html = get(url)
    except Exception:
        return None
    text = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", html, flags=re.S | re.I)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(text.encode()).hexdigest()


def load(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def host_of(url):
    try:
        h = urllib.parse.urlparse(url.strip()).hostname
    except Exception:
        return None
    return h.lower().rstrip(".") if h else None


def brand_keywords(brands):
    kws = set()
    for b in brands:
        for k in [b["name"]] + b.get("keywords", []) + [d.split(".")[0] for d in b["domains"]]:
            k = re.sub(r"[^a-z0-9]", "", k.lower())
            if len(k) >= 4:
                kws.add(k)
    return kws


def fetch_feed(feed, kws):
    try:
        body = get(feed["url"], timeout=120)
    except Exception:
        return None
    hosts = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if feed["kind"] == "hostfile":
            parts = line.split()
            h = parts[-1].lower() if len(parts) >= 2 else None
        elif feed["kind"] == "domains":
            h = line.lower().rstrip(".")
        else:
            h = host_of(line)
        if not h or not re.match(r"^[a-z0-9.-]+\.[a-z0-9-]{2,}$", h):
            continue
        if feed.get("relevant") and not (h.endswith(".it") or any(k in h for k in kws)):
            continue
        hosts.add(h)
        if len(hosts) >= MAX_PER_FEED:
            break
    return hosts


def main():
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    today = now[:10]
    DATA.mkdir(parents=True, exist_ok=True)
    brands = load(DOCS / "brands.json", {"brands": []})["brands"]
    state = load(DATA / "state.json", {"domains": {}, "pages": {}})
    log = load(DATA / "changelog.json", [])
    new_entries = []

    for b in brands:
        for d in b["domains"]:
            snap = snapshot(d)
            if snap is None:
                continue
            for kind, detail in diff(state["domains"].get(d), snap):
                new_entries.append({"date": today, "brand": b["name"], "domain": d, "type": kind, "detail": "%s: %s" % (d, detail)})
            state["domains"][d] = snap
        for url in b.get("alert_pages", []):
            h = page_hash(url)
            if h is None:
                continue
            old = state["pages"].get(url)
            if old and old != h:
                new_entries.append({"date": today, "brand": b["name"], "domain": url, "type": "page", "detail": "pagina di avviso aggiornata: %s" % url})
            state["pages"][url] = h

    counts = {}
    domains = set()
    ok_any = False
    kws = brand_keywords(brands)
    for feed in FEEDS:
        cache = DATA / ("feed_%s.json" % feed["name"])
        hosts = fetch_feed(feed, kws)
        if hosts is None:
            # fonte non raggiungibile: si tengono i dati dell'ultima volta
            hosts = set(load(cache, []))
            counts[feed["name"]] = "non raggiungibile (dati precedenti: %d)" % len(hosts)
        else:
            ok_any = True
            cache.write_text(json.dumps(sorted(hosts)), encoding="utf-8")
            counts[feed["name"]] = len(hosts)
        domains |= hosts

    meta = load(DATA / "meta.json", {})
    if ok_any:
        (DATA / "threats.json").write_text(json.dumps({"updated": now, "domains": sorted(domains)}), encoding="utf-8")
        meta["feeds"] = counts
    meta["updated"] = now
    meta["new_changes"] = len(new_entries)

    log = (new_entries + log)[:200]
    (DATA / "state.json").write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
    (DATA / "changelog.json").write_text(json.dumps(log, indent=1, ensure_ascii=False), encoding="utf-8")
    (DATA / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print("feed:", counts or "nessuno raggiungibile", "| novità:", len(new_entries))


if __name__ == "__main__":
    main()
