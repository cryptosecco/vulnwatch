# vulnwatch: design

- **Data:** 2026-11-03
- **Stato:** bozza da approvare
- **Macchina:** il Mac del proprietario (macOS 27.0.1, Apple Silicon)

## Perché

Ogni giorno escono vulnerabilità nuove, e alcune vengono sfruttate subito. Il proprietario vuole che ogni mattina un job legga il feed di cve.now, capisca cosa colpisce questo Mac e lo chiuda in fretta. Le condizioni sono due:

1. **Nulla di noi deve arrivare a cve.now**, né a nessun'altra fonte: niente inventario, pacchetti, versioni o percorsi.
2. **Ogni input esterno può essere ostile**: cve.now, le fonti primarie, i registri di pacchetti, il testo delle advisory. Si diffida sempre, si fa sempre l'audit, e si applica solo se l'audit è verde.

## Obiettivi

1. Una volta al giorno: scaricare il feed in modo uniforme, fare l'inventario locale e confrontare in locale.
2. Due corsie:
   - **automatica**: solo correzioni urgenti, verificate e con audit verde, dai canali ufficiali;
   - **manuale**: tutto il resto, presentato in un report con il comando pronto da approvare.
3. Un audit gate prima di ogni applicazione, automatica o approvata, rieseguito al momento dell'applicazione.
4. Un report e una notifica ogni giorno, anche quando non c'è nulla o quando il job fallisce.

## Non-obiettivi

- Altre macchine (es. `server-remoto`): eventualmente in seguito.
- Modificare automaticamente codice o lockfile dei progetti.
- Applicare automaticamente aggiornamenti di macOS.
- Sostituire l'igiene normale: gli aggiornamenti automatici di macOS e del browser restano attivi.
- Un modello AI dentro il ciclo non sorvegliato.

## Anti-obiettivi (fallimento anche se "funziona")

- Una richiesta verso una fonte di vulnerabilità che dipende dal nostro inventario.
- Un comando il cui contenuto (URL, nome pacchetto, versione, script, flag) viene dal testo o dai dati di una advisory.
- Installare qualcosa senza audit, o una versione diversa da quella verificata.
- Rompere l'ambiente in silenzio: venv su Python di brew, servizi brew, Node nel PATH. Non deve ripetersi l'incidente del 2026-10-23.
- Tacere quando il job fallisce: "nessun dato" non vuol dire "sicuro".
- Un job che si aggiorna da solo, o che gira dopo essere stato manomesso.
- Girare come root, o chiedere password in modalità non sorvegliata.

## Modello di minaccia

Sono **non fidati**:
- tutti i campi di cve.now, compresi quelli strutturati;
- le fonti primarie (i record CVE li scrivono i CNA, le GHSA i maintainer);
- i metadati dei registri;
- la rete.

| # | Minaccia | Contromisura |
|---|---|---|
| T1 | Iniezione di comandi o prompt nel testo delle advisory | Nessun LLM nel ciclo. Nessun comando costruito dal testo. Il testo resta inerte nel report (vedi Report). |
| T2 | Dati strutturati avvelenati (falso "fixed in X", falso "affected", URL falsi) | Il feed decide solo **quando** aggiornare qualcosa che abbiamo già, mai **cosa** installare né **da dove**. In corsia automatica serve la conferma di una fonte primaria indipendente. |
| T3 | Supply chain dell'aggiornamento stesso (maintainer compromesso, release malevola appena pubblicata) | Audit gate: cooldown, maintainer, script di installazione, nuove dipendenze, provenance, firma/Team ID, insieme di pacchetti toccati. |
| T4 | Profilazione da parte delle fonti | Invariante sull'insieme delle richieste (I1). |
| T5 | Iniezione nel terminale o nel report (escape ANSI, bidi Unicode, zero-width, link) | Sanitizzazione di tutto il testo esterno. |
| T6 | Manomissione del job | Installazione blindata (vedi Pianificazione): codice, configurazione e plist di root in sola lettura, verificati con un manifest di hash a ogni esecuzione. Nessuna dipendenza esterna. |
| T7 | Risposte enormi o malformate, DoS | Limiti di dimensione, timeout, validazione dello schema, fail closed. |
| T8 | MITM o redirect verso host estranei | Solo HTTPS e allowlist di host, compresi i target di redirect. |
| T9 | Omissione: cve.now nasconde una CVE sfruttata semplicemente non pubblicandola | Il catalogo KEV della CISA e i dati OSV/GHSA vengono confrontati da soli con l'inventario, non solo come conferma di cve.now. |
| T10 | Stato locale avvelenato da un processo con il nostro utente | Lo stato è un dato non fidato: nessuna cache dei verdetti di audit, ogni applicazione rifà l'audit da capo. |

## Invarianti (ognuno ha un test)

- **I1 – Richieste uniformi.** Ogni richiesta verso una fonte di vulnerabilità dipende solo da dati pubblici (contenuto dei feed, date, configurazione fissa), mai dall'inventario. Test: due inventari diversi producono log delle richieste identici.
- **I2 – Comandi da playbook.** Ogni comando eseguito viene da un template fisso del playbook. I template si riempiono solo con valori dell'inventario locale e con la versione verificata dall'audit.
- **I3 – Fail closed.** Audit verde vuol dire tutti i controlli passati. Qualsiasi controllo fallito, sconosciuto o in errore dà rosso: la voce va in corsia manuale con i motivi.
- **I4 – Versione esatta.** Si installa esattamente la versione verificata. Subito prima di applicare si ricontrolla che il canale offra ancora quella versione (TOCTOU).
- **I5 – Niente privilegi.** Mai root e mai prompt di password in modalità non sorvegliata.
- **I6 – Tracciabilità.** Ogni azione va in un log append-only con prima, dopo e prove dell'audit.

## Flusso giornaliero

1. **Auto-controllo.**
   - Codice, configurazione e plist devono essere di root e non scrivibili da altri utenti o gruppi.
   - Gli hash dei file devono corrispondere al manifest scritto all'installazione, anch'esso di root.

   Altrimenti il job si ferma e manda una notifica.
2. **Download uniforme** (lista fissa, vedi Fonti):
   - feed generici di cve.now: `kev`, `critical` e `/api/v1/entries?filter=critical,kev` paginato fino all'ultima esecuzione;
   - il dettaglio `/api/v1/entries/<id>` di **ogni** voce nuova di quelle liste, senza scegliere;
   - le fonti primarie in blocco.
3. **Inventario locale** (vedi Inventario). Non esce mai dal Mac.
4. **Archivio locale e confronto completo.**
   - Ogni advisory scaricata resta in un archivio locale: voci di cve.now, catalogo KEV completo, dati OSV/GHSA.
   - **Ogni giorno si riconfronta tutto l'archivio** con l'inventario, non solo le novità. Così una CVE vecchia scatta quando installi il software colpito, e una voce "senza patch" si riapre quando la patch esce.
   - Il KEV e l'OSV/GHSA si confrontano anche da soli (T9).
   - Primo avvio: KEV completo, più le voci critiche e KEV di cve.now degli ultimi 90 giorni.
   - Le voci manuali restano nel report finché non sono risolte, o ignorate esplicitamente con un motivo.
   - Il confronto per tipo:
     - pacchetti di ecosistema: (ecosistema, nome) esatti più intervallo di versioni;
     - app e brew: una tabella di alias locale e curata (vendor/prodotto ↔ formula/cask/app bundle).
   - Le corrispondenze approssimate vanno solo in corsia manuale.
5. **Classificazione della corsia.** Una voce è candidata alla corsia automatica solo se valgono tutte queste condizioni:
   - è KEV o critica;
   - è **confermata da una fonte primaria**, cioè:
     - la CVE esiste in una fonte primaria;
     - riguarda quel prodotto;
     - lo stato KEV viene dal catalogo della CISA, oppure la gravità critica dal record CVE;
     - **l'intervallo di versioni viene da una fonte primaria** (OSV/GHSA per gli ecosistemi, il record CVE per il resto).

     Se l'intervallo c'è solo su cve.now, la voce va in manuale. Conseguenza voluta: brew e app finiranno spesso in manuale, perché i record CVE raramente hanno intervalli utilizzabili.
   - il bersaglio sta in un canale abilitato all'automatico (vedi Playbook) e non è nella lista di blocco;
   - il canale ufficiale offre una versione ≥ quella corretta.

   Tutto il resto va in corsia manuale.
6. **Audit gate** per canale (vedi Playbook).
7. **Applicazione** (solo corsia automatica e solo con audit verde): si salva lo stato per il rollback, poi si esegue il template.
8. **Verifica dopo l'applicazione**:
   - la versione è cambiata;
   - il binario parte;
   - per le app: firma, notarizzazione e Team ID invariato;
   - per brew: venv con `home` inesistente, servizi brew rimasti sul vecchio keg, versione del `node` nel PATH.

   Se qualcosa non torna parte una notifica forte, con le istruzioni di rollback.
9. **Report e notifica.**

## Fonti e rete

- **Fonte di innesco:** cve.now, solo gli endpoint generici sopra, più l'host del redirect statico `f9gkulwameaj0boi.public.blob.vercel-storage.com`. Mai `/stack`, `check_stack`, `/api/v1/search` o filtri `tech`/`ecosystem`.
- **Conferma primaria**, scaricata in blocco e con una lista fissa, non derivata dall'inventario:
  - il catalogo KEV della CISA (JSON completo);
  - i record CVE dai delta pubblici di cvelistV5;
  - per i pacchetti di ecosistema, l'OSV o il GitHub Advisory Database in blocco, per un insieme fisso di ecosistemi.

  Il meccanismo incrementale lo sceglie il builder.
- **Canali ufficiali di aggiornamento:** Homebrew (API e bottle), il registry npm, il Google updater. Questi vedono ciò che vedrebbero in un aggiornamento normale. È accettato, perché sono i canali che usiamo comunque.
- **Rete:** solo HTTPS, allowlist di host, redirect seguiti solo verso host in allowlist, limiti di dimensione e timeout.

## Inventario

- Versione di macOS.
- App in `/Applications` e `~/Applications`: bundle id, versione, Team ID.
- Formule e cask brew.
- Pacchetti npm globali sotto `~/.npm-global`.
- Le copie di Node e Bun note:
  - le copie di Node di un'app agente con il suo Node: `~/.agent-app/node` e `~/.agent-app/profiles/example/node`;
  - Node di brew;
  - `/usr/local/bin/node`;
  - un'app di coding agent e app desktop con Node incorporato;
  - la Bun di brew e quella di `~/.example-tool`.
- Lockfile dei progetti, **solo per il report**, in `~/Code`, `~/Projects` e `~/Projects/example-app` (scelta del proprietario). Mai nelle cartelle protette da TCC. La v1 legge solo i lockfile npm (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`) e i `requirements.txt`. I formati TOML (`uv.lock`, `poetry.lock`, `Cargo.lock`) vengono dopo: Python 3.9 non ha `tomllib`.

## Playbook (canali)

### Corsia automatica ammessa

**Formula di homebrew/core con bottle per questa macchina**
- Audit:
  - il dry-run dell'upgrade tocca **solo** il bersaglio;
  - nessuna nuova dipendenza;
  - nessun `post_install` o caveat nuovo;
  - la versione candidata è disponibile da almeno 48 h.
- Esecuzione: `HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_AUTOREMOVE=1 brew upgrade --formula <nome>`.
- Rollback: il vecchio keg resta (niente cleanup) e se ne registra il percorso.

**Pacchetto npm globale**
- Audit:
  - pubblicato da almeno 48 h;
  - maintainer invariati;
  - script di installazione (`preinstall`/`install`/`postinstall`) invariati;
  - nessuna nuova dipendenza diretta;
  - provenance presente se c'era nella versione installata;
  - **stessa versione maggiore** di quella installata;
  - il campo `engines` è soddisfatto dalla copia di Node proprietaria del prefix.
- Esecuzione: `npm install -g <nome>@<versione-verificata>` con il `npm` della copia di Node proprietaria del prefix.

**Regole comuni alla corsia automatica**
- **Lista di blocco** (`hold`), nella configurazione di root: cambiarla richiede `sudo`. Le voci bloccate non vanno mai in automatico, anche con audit verde. Contenuto iniziale:
  - `example-agent`, tenuto indietro apposta per via del Node 22 di un'app agente;
  - `@example/cli`, che si aggiorna da solo.
- Le formule brew devono restare sulla stessa versione maggiore.
- **Mai chiudere o riavviare nulla.** Se il bersaglio è una formula usata da un servizio brew attivo, va in manuale. Dopo un aggiornamento automatico, il report elenca cosa va riavviato.

### Sempre corsia manuale

- **Cask** (app installate con brew): sostituire un'app in `/Applications` da un processo non sorvegliato richiede il permesso macOS "Gestione app". Le regole di alcuni cask chiudono l'app. Con `apply` da Terminale:
  - audit: dry-run con il solo bersaglio, cooldown di 48 h;
  - verifica dopo: `codesign --verify`, `spctl --assess`, Team ID uguale al precedente.
- **Google Chrome**: il Google updater installa la versione che Google sta servendo in quel momento, quindi non si può verificare prima né fissare la versione (I3, I4). Chrome si aggiorna comunque da solo. vulnwatch:
  - controlla che la versione installata sia ≥ quella corretta;
  - se non lo è, avvisa;
  - con `apply` avvia l'updater solo su approvazione del proprietario, poi verifica firma e Team ID di Google;
  - non riavvia mai il browser, segnala solo che va riavviato.
- Aggiornamenti di macOS.
- Runtime Node e Bun, comprese le copie di un'app agente con il suo Node e la pkg di root in `/usr/local/bin/node`. Le procedure sono in una nota privata sulle copie di Node.
- Python e venv.
- Altre app.
- Lockfile dei progetti.
- Tutto ciò che chiede sudo.
- Vulnerabilità senza patch: la mitigazione la decide il proprietario.

### Approvazione manuale

`vulnwatch apply <id>`, da terminale e interattivo:
1. riesegue l'audit su dati freschi;
2. mostra prove e differenze;
3. chiede s/N;
4. applica la versione esatta;
5. verifica e scrive nel log.

Il proprietario può superare **esplicitamente** il cooldown (es. `--accept-fresh`) quando una KEV non può aspettare.

Nella v1 `apply` esegue solo i template del playbook: formula brew, cask, npm globale, avvio del Google updater. Per tutte le altre voci manuali mostra solo istruzioni:
- runtime Node e Bun;
- Python e venv;
- altre app;
- lockfile;
- tutto ciò che richiede privilegi di amministratore.

Le procedure delle istruzioni vengono dalle note in memoria. Template eseguibili per queste voci potranno arrivare in versioni successive, ognuno con audit, rollback e verifica propri.

**Permessi macOS (TCC).** Non si dà nessun permesso di privacy a `/usr/bin/python3`: varrebbe per ogni script Python del Mac. Per questo i cask vanno solo in `apply` da Terminale, e la ricerca dei lockfile esclude `~/Documents`, `~/Desktop` e `~/Downloads`.

## Report e notifica

- **Dove:**
  - report: `~/Library/Application Support/vulnwatch/reports/YYYY-MM-DD.md` (più `.json`);
  - log: `~/Library/Logs/vulnwatch/`.

  Mai in `~/Documents` o `~/Desktop`, perché iCloud li può rendere "dataless".
- **Sezioni:**
  1. Applicato automaticamente: prima/dopo e prove dell'audit.
  2. Aspetta te: esito dell'audit, motivi del rosso, comando `vulnwatch apply <id>`.
  3. Senza patch.
  4. Errori o nessun dato.
- **Testo esterno:**
  - sanitizzato: rimossi controlli, ANSI, bidi e zero-width; lunghezza troncata;
  - mostrato come citazione "non fidata", con gli URL come testo non cliccabile.
  - I comandi nel report li genera il nostro codice, mai il feed.
- **Notifica macOS:** solo conteggi, senza testo esterno.

## Pianificazione e stack

- **Installazione blindata** (scelta del proprietario):
  - codice e configurazione copiati in `/usr/local/libexec/vulnwatch/`, di `root:wheel`, file `644` e cartelle `755`;
  - la configurazione (lista di blocco, tabella di alias, cooldown, allowlist di host) sta lì: cambiarla richiede `sudo`;
  - un manifest di hash, scritto all'installazione e anch'esso di root, viene verificato a ogni esecuzione (vedi Auto-controllo);
  - il comando `vulnwatch` per `apply` e i report è un link di root in `/usr/local/bin` verso la copia installata, mai verso il repo di sviluppo.
- **Installazione e aggiornamenti** con `sudo ./install.sh`, lanciato dal proprietario da un commit revisionato del repo:
  - copia i file;
  - scrive il manifest;
  - installa il plist;
  - lo carica nella sessione del proprietario.

  vulnwatch non si aggiorna mai da solo.
- **LaunchAgent** in `/Library/LaunchAgents/` (plist di root). Gira come il proprietario nella sua sessione, senza privilegi:
  - ogni giorno alle 07:30;
  - recupera l'esecuzione persa se il Mac era in stop;
  - `ProgramArguments`: `/usr/bin/python3 -I /usr/local/libexec/vulnwatch/vulnwatch.py run`;
  - ambiente minimo con PATH esplicito.
- **Stato, report e log** restano nello spazio utente (`~/Library/Application Support/vulnwatch`, `~/Library/Logs/vulnwatch`) e sono dati non fidati (T10).
- **Linguaggio:**
  - Python 3, solo standard library;
  - interprete `/usr/bin/python3` di Apple (3.9.6): brew non lo tocca, quindi il job non si rompe aggiornando Python di brew;
  - nessuna dipendenza esterna, quindi nulla da sottoporre ad audit.
- **Repo e test:**
  - repo: `~/Code/vulnwatch` (git);
  - test con `unittest`.

## Test di accettazione

1. **I1:** due inventari diversi producono log di rete identici.
2. **Iniezione:** advisory con `curl … | sh`, escape ANSI, bidi e link. Non finiscono mai in un comando e nel report sono neutralizzati.
3. **Dati avvelenati:** "fixed in" falso o URL falso non cambiano cosa si installa né da dove.
4. **Audit rosso**, ognuno con motivo nel report:
   - release più giovane del cooldown;
   - maintainer cambiato;
   - nuovo `postinstall`;
   - nuova dipendenza;
   - dry-run che tocca altri pacchetti;
   - Team ID cambiato;
   - controllo in errore.
5. **Fail closed:** con la rete giù il report dice "nessun dato", parte la notifica e non si fa nessuna azione.
6. **Manomissione:** il job rifiuta di girare e avvisa in tre casi:
   - un file del codice o della configurazione non corrisponde al manifest;
   - un file è scrivibile da altri;
   - un file non è di root.
7. **Rottura dopo l'upgrade:** un venv con `home` sparito e un servizio brew sul vecchio keg vengono segnalati.

## Avvio

Per i primi 7 giorni c'è una **modalità ombra**: la corsia automatica scrive solo "avrei applicato X" con l'audit completo, senza applicare nulla. Poi il proprietario decide se accenderla.

## Lasciato al builder

- Quali fonti primarie in blocco usare e come scaricarle in modo incrementale, nel rispetto di I1.
- La normalizzazione dei nomi e il contenuto iniziale della tabella di alias.
- Come ottenere in modo affidabile, per brew, il confronto tra la definizione installata e quella candidata.
- Il formato del report e la retention di report e stato.
- La struttura interna del codice.

## Decisioni prese da Claude (da verificare)

- Nessun LLM nel job giornaliero; Claude si usa solo in sessione con il proprietario.
- Cooldown di 48 h per la corsia automatica, superabile solo a mano.
- Corsia automatica limitata a **formula di homebrew/core e npm globale**. Cask e Chrome passano in manuale: un updater che non si può verificare prima non rispetta "audit, poi applica", e i cask richiederebbero permessi TCC.
- La conferma primaria include anche l'intervallo di versioni. Senza quello si va in manuale.
- Archivio locale riconfrontato ogni giorno; il KEV e l'OSV/GHSA si confrontano anche da soli; primo avvio con KEV completo più 90 giorni di cve.now.
- Lista di blocco con `example-agent` e `@example/cli`; regola della stessa versione maggiore; controllo di `engines`.
- Mai chiudere o riavviare app e servizi.
- Nella v1 `apply` esegue solo i template del playbook; le altre voci mostrano istruzioni.
- Nessun permesso TCC a interpreti condivisi.
- Orario 07:30, LaunchAgent invece di cron.
- Repo in `~/Code/vulnwatch`, stato in `~/Library/Application Support/vulnwatch`.
- Python di sistema, solo standard library.
- Modalità ombra per 7 giorni.
- Nome "vulnwatch".

## Decisioni del proprietario

- Schema a due corsie; ogni input esterno è ostile; si applica solo con audit verde.
- Nulla di noi a cve.now o ad altre fonti.
- Installazione blindata: codice e configurazione di root, `sudo` all'installazione e a ogni aggiornamento di vulnwatch.
- Lockfile cercati in `~/Code`, `~/Projects` e `~/Projects/example-app`.
