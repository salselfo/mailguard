# MailGuard

Incolli l'indirizzo di un mittente e ottieni un verdetto: dominio ufficiale, sospetto o minaccia probabile.

## Cosa controlla
- **Impersonificazione del brand**: se il nome mostrato (o l'oggetto) dichiara INPS, MediaWorld ecc. ma il dominio non è tra quelli ufficiali, scatta l'allarme.
- **Domini sosia**: `inps-rimborsi.it`, `mediaw0rld.it`, `inpss.it`, punycode.
- **Spoofing**: incollando le intestazioni complete legge SPF, DKIM, DMARC e confronta mittente, Return-Path e Reply-To.
- **Controlli online** (dal browser): SPF e DMARC del dominio, età del dominio (RDAP).
- **Elenchi pubblici di phishing/malware**, aggiornati ogni giorno.

## Aggiornamento automatico
`updater/update.py` gira ogni giorno con GitHub Actions e:
1. controlla SPF, DMARC, MX dei domini ufficiali e registra i cambiamenti in `docs/data/changelog.json`;
2. controlla le pagine ufficiali di avviso phishing indicate in `alert_pages` (vuote di default, aggiungi gli indirizzi che vuoi monitorare);
3. scarica gli elenchi pubblici di minacce (OpenPhish, URLhaus) in `docs/data/threats.json`.

L'aggiornatore non aggiunge mai nuovi domini ufficiali da solo, per evitare che qualcuno possa avvelenare l'archivio. I nuovi mittenti autorizzati compaiono nel changelog e li approvi tu a mano in `docs/brands.json`.

## Messa online (gratis)
1. Crea un repository su GitHub e carica questa cartella.
2. Settings, Pages: sorgente "Deploy from a branch", branch `main`, cartella `/docs`.
3. Settings, Actions, General: abilita "Read and write permissions" per i workflow.
4. Tab Actions, "Aggiornamento MailGuard", "Run workflow" per il primo aggiornamento.

## Prima di fidarti
- I domini in `docs/brands.json` sono un seed: verificali dai siti ufficiali di ogni brand.
- Un dominio ufficiale non prova che la mail sia vera: serve il controllo delle intestazioni.
- Un dominio sconosciuto non è per forza innocuo: il verdetto "non determinabile" va verificato a mano.

## Test
`node --test tests/core.test.mjs`
