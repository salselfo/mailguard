# MailGuard

Incolli l'indirizzo di un mittente (e, se vuoi, testo, link e intestazioni) e ottieni un verdetto: dominio ufficiale, non determinabile, sospetto o minaccia probabile, con un consiglio su cosa fare.

## Cosa controlla
- **Impersonificazione del brand**: se il nome mostrato o il testo dichiarano INPS, MediaWorld, Poste ecc. ma il dominio non è tra quelli ufficiali, scatta l'allarme.
- **Domini sosia**: `inps-rimborsi.it`, `mediaw0rld.it`, `inpss.it`, punycode.
- **Link**: nome@ nascosto, indirizzi numerici, link accorciati, HTTP, domini che imitano un brand, link fuori dal dominio ufficiale del mittente.
- **Testo**: urgenza, minacce di blocco, richieste di dati, premi o rimborsi, codici, allegati rischiosi. Serve più di un segnale per far scattare l'avviso.
- **Spoofing**: con le intestazioni complete legge SPF, DKIM, DMARC e confronta mittente, Return-Path e Reply-To.
- **Controlli online** (dal browser, disattivabili): SPF e DMARC del dominio, età del dominio (RDAP).
- **Elenchi pubblici di phishing**, aggiornati ogni giorno.
- **Installabile sul telefono**: Condividi, Aggiungi a Home.

## Privacy
L'analisi avviene nel browser. Indirizzo completo, testo e link non vengono salvati né inviati. Solo con i controlli online attivi viene interrogato il nome del dominio (Cloudflare per il DNS, registro dei domini per l'età).

## Aggiornamento automatico
`updater/update.py` gira ogni giorno con GitHub Actions e:
1. controlla SPF, DMARC, MX dei domini ufficiali e registra i cambiamenti in `docs/data/changelog.json`;
2. controlla le pagine ufficiali di avviso phishing indicate in `alert_pages` (vuote di default, aggiungi gli indirizzi che vuoi monitorare);
3. scarica gli elenchi pubblici di minacce (OpenPhish e Phishing.Database, quest'ultimo filtrato sui brand e sui domini .it) in `docs/data/threats.json`. Se una fonte non risponde, tiene i dati dell'ultima volta. URLhaus è escluso perché richiede una chiave personale.

L'aggiornatore non aggiunge mai nuovi domini ufficiali da solo, per evitare che qualcuno possa avvelenare l'archivio. I nuovi mittenti autorizzati compaiono nel changelog e li approvi tu a mano in `docs/brands.json`.

## Test automatici
Ad ogni modifica, `.github/workflows/test.yml` esegue i test. In locale: `node --test tests/core.test.mjs`.

## Limiti da conoscere
- I domini in `docs/brands.json` sono un seed: verificali dai siti ufficiali di ogni brand.
- Un dominio ufficiale non prova che la mail sia vera: serve il controllo delle intestazioni. Alcuni brand (ad esempio Poste) non bloccano la falsificazione via DMARC.
- Un dominio sconosciuto non è per forza innocuo: il verdetto "non determinabile" va verificato a mano.
- Tutti i sottodomini di un dominio ufficiale contano come ufficiali.
- Il controllo del testo è pensato per l'italiano e funziona per segnali, non per intelligenza: può sbagliare in entrambe le direzioni.
