```text
  .----------.
  |       // |                 _                          _          _
  |      //  |  __   __ _   _ | | _ __  __      __  __ _ | |_   ___ | |__
  | \\  //   |  \ \ / /| | | || || '_ \ \ \ /\ / / / _` || __| / __|| '_ \
  |  \\//    |   \ V / | |_| || || | | | \ V  V / | (_| || |_ | (__ | | | |
   \  \/    /     \_/   \__,_||_||_| |_|  \_/\_/   \__,_| \__| \___||_| |_|
    '.____.'

  dati pubblici       il tuo Mac                              tu
 +------------+      +--------------------------------+      +----------------------+
 | cve.now    |      | ciò che hai installato         |      | report alle 07:30    |
 | CISA KEV   | ---> | è confrontato qui, in locale;  | ---> | vulnwatch apply <id> |
 | record CVE |      | aggiornamenti verificati prima |      |                      |
 | OSV        |      |                                |      |                      |
 +------------+      +--------------------------------+      +----------------------+
                    <----- nulla del tuo Mac torna indietro -----
```

**Un controllo giornaliero delle vulnerabilità del tuo Mac che non rivela a nessuno cosa usi.**

[![tests](https://github.com/cryptosecco/vulnwatch/actions/workflows/tests.yml/badge.svg)](https://github.com/cryptosecco/vulnwatch/actions/workflows/tests.yml) · macOS · solo libreria standard di Python · [MIT](LICENSE) · *[Read in English](README.md)*

## Perché

Il Mac di chi sviluppa ha centinaia di componenti che ricevono correzioni di sicurezza:
- macOS e le sue app;
- le formule Homebrew e i comandi npm globali;
- le copie di Node portate da altri strumenti;
- le dipendenze fissate in ogni progetto che hai clonato.

Ogni giorno escono vulnerabilità nuove, e alcune sono già sfruttate quando ne leggi. Starci dietro a mano non è realistico. La scorciatoia solita, mandare l'elenco dei pacchetti a un servizio di scansione, consegna a terzi la mappa esatta di cosa non è aggiornato sulla tua macchina.

vulnwatch fa tutto il controllo **sul tuo Mac**:
- Ogni mattina alle 07:30 scarica gli stessi dati pubblici sulle vulnerabilità che riceve chiunque e li confronta in locale con ciò che hai installato.
- Ti dice cosa è colpito, qual è la correzione e il comando esatto per applicarla dopo un nuovo audit.
- Parte in **modalità ombra**: segnala, ma non cambia mai nulla da solo, finché non decidi di accendere gli aggiornamenti automatici.

## Cosa ottieni

Una notifica di macOS come *"3 da approvare · 0 applicate · 0 malevoli"* e un report giornaliero in Markdown, più uno in JSON. Una voce appare così; codici e versioni sono inventati:

```markdown
### formula brew `openssl@3` `3.5.9` · 2 vulnerabilità
- Posizione: `/opt/homebrew`
- Versione corretta: 3.5.10 (fonte: cverecord)
- KEV: no · Critiche: sì (1)
- Vulnerabilità: `CVE-2026-1111` (`7c1f0a2b9d4e`), `CVE-2026-2222` (`2b8e4d1c0f3a`)

| controllo | esito | dettaglio |
|---|---|---|
| tap_core | ✅ ok |  |
| candidate | ✅ ok | `3.5.10` |
| same_major | ✅ ok |  |
| bottle_available | ✅ ok |  |
| dry_run_only_target | ✅ ok |  |
| post_install_unchanged | ✅ ok |  |
| caveats_unchanged | ✅ ok |  |
| not_running_service | ✅ ok |  |
| not_deprecated | ✅ ok |  |
| cooldown | ✅ ok | `pubblicata 96 ore fa` |

- Comando: `vulnwatch apply 7c1f0a2b9d4e`
> [testo non fidato] `OpenSSL: titolo d'esempio`
```

Il report elenca anche ciò che non ha ancora una patch, le corrispondenze approssimate da verificare, i pacchetti malevoli, le voci ignorate e se tutte le fonti hanno risposto. In modalità ombra mostra anche cosa vulnwatch avrebbe aggiornato da solo.

## Perché fidarsi

- **Privato per costruzione.** Quello che scarica dalle fonti di vulnerabilità non dipende mai da cosa hai installato, quindi le fonti non possono ricavare il tuo software dalle richieste. Il confronto avviene tutto in locale.
- **Prima l'audit, poi l'applicazione.** Prima di applicare un aggiornamento lo verifica sul canale ufficiale:
  - chi l'ha pubblicato;
  - gli script di installazione e le nuove dipendenze;
  - la provenienza;
  - un cooldown di 48 ore.

  Un controllo sconosciuto conta come fallito.
- **Installazione blindata.** Il codice viene installato di root, in sola lettura, esattamente dal commit git che hai revisionato. Ogni run lo verifica con un manifest di hash.
- **Niente da installare.** Usa il Python dei Command Line Tools di Apple e solo la sua libreria standard: niente pip, npm o Homebrew obbligatori.

## Cosa controlla

| Fonte (dati pubblici) | Cosa porta |
|---|---|
| [cve.now](https://cve.now) | Voci recenti critiche e già sfruttate |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilità sfruttate davvero |
| [Record CVE](https://github.com/CVEProject/cvelistV5) | Intervalli ufficiali delle versioni colpite |
| [OSV](https://osv.dev) (npm, PyPI) | Advisory dei pacchetti e pacchetti malevoli |

Le confronta con:
- macOS e le app in `/Applications`;
- formule e cask di Homebrew;
- pacchetti npm globali;
- copie di Node e Bun, nel PATH o installate con nvm, volta, fnm, asdf, mise;
- i pacchetti fissati nei lockfile dei tuoi progetti: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements.txt`.

## Rispetto ad altri strumenti

| Strumento | Cosa copre | Cosa invia |
|---|---|---|
| `brew outdated` / `brew upgrade` | solo Homebrew; ogni aggiornamento, non solo quelli di sicurezza | nulla oltre alle richieste di Homebrew stesso |
| `npm audit` | un progetto alla volta | l'elenco delle dipendenze di quel progetto, al registro npm |
| Dependabot, Snyk e simili | i repository che colleghi | leggono manifest e lockfile nel loro servizio |
| `osv-scanner` | le cartelle che gli indichi | nomi e versioni dei pacchetti all'API di OSV, salvo uso offline |
| **vulnwatch** | tutto il Mac: macOS, app, Homebrew, npm globali, copie di Node/Bun, i lockfile di ogni progetto | niente del tuo software verso le fonti di vulnerabilità |

Non sostituisce quegli strumenti: tieni Dependabot sui repository, perché vulnwatch sorveglia la macchina su cui lavori. In più fa l'audit di ogni aggiornamento prima di applicarlo, cosa che gli altri non fanno per te.

## Installazione (circa 5 minuti)

Serve macOS (Apple Silicon o Intel), un account amministratore e i Command Line Tools di Apple (`xcode-select --install` se manca `git`). Homebrew e npm sono facoltativi.

```bash
git clone https://github.com/cryptosecco/vulnwatch.git
cd vulnwatch
./setup.sh                                   # rileva il tuo Mac, fa due domande, scrive config/config.json
sudo ./install.sh "$(git rev-parse HEAD)"    # installa esattamente il commit che hai in checkout
```

**Cosa fa `./setup.sh`:**
- trova Homebrew, i pacchetti npm globali, le copie di Node e Bun, le cartelle dei progetti e la lingua;
- ti chiede di confermare lingua e cartelle;
- mostra un conteggio locale di cosa verrà controllato.

Non invia nulla in rete di suo (il controllo aggiornamenti di npm viene spento) e non gira mai come root.

**Cosa fa `install.sh`:**
1. rifiuta un repo con modifiche non committate, o un commit diverso da quello in checkout;
2. esegue i test come utente;
3. copia quel commit in `/usr/local/libexec/vulnwatch` (di root, in sola lettura) e scrive il manifest di hash;
4. installa il job giornaliero in `/Library/LaunchAgents/local.vulnwatch.plist` e il comando `vulnwatch`;
5. avvia il primo run.

## Cosa succede dopo

- **Il primo run** parte subito dopo l'installazione e dura **circa 2 ore**: scarica 90 giorni di dati pubblici. Lo segui con `vulnwatch status`.
- **Il report** finisce in `~/Library/Application Support/vulnwatch/reports/<data>.md`, insieme a un `.json`. Una notifica ti dice quante voci ti aspettano.
- **Ogni mattina alle 07:30** ripete il controllo e scarica solo ciò che è cambiato. Se il Mac dorme, parte al risveglio.
- **Non applica nulla** finché è attiva la modalità ombra. Ogni voce del report dice cosa fare; per formule Homebrew e npm globali dà il comando esatto `vulnwatch apply <id>`.

```
$ vulnwatch status
Installato:  commit 0123456789ab
Integrità:   integra
Pianificato: ogni giorno alle 07:30
Ultimo run:  partito 2026-11-03T06:30:00Z, finito 2026-11-03 06:41:12 UTC, esito ok
Report:      ~/Library/Application Support/vulnwatch/reports/2026-11-03.md
             Riepilogo per elemento: 0 malevoli · 0 applicati · 0 in ombra · 3 da approvare · 1 senza patch · …
Modalità:    ombra (solo report, non applica mai nulla da solo)
```

## Uso quotidiano

| Comando | Cosa fa |
|---|---|
| `vulnwatch status` | installazione, pianificazione, ultimo run, ultimo report |
| `vulnwatch report` | percorso dell'ultimo report |
| `vulnwatch apply <id>` | rifà l'audit, mostra ogni controllo, chiede conferma, installa la versione verificata |
| `vulnwatch apply <id> --accept-fresh` | come sopra, accettando una versione più giovane del cooldown di 48 ore |
| `vulnwatch ignore <id> --reason "…"` | toglie una voce dalle cose da fare (resta elencata tra le "Ignorate") |
| `vulnwatch selfcheck` | verifica la copia installata con il suo manifest |
| `vulnwatch run` | esegue subito il controllo giornaliero |

I log sono in `~/Library/Logs/vulnwatch/`. `actions.jsonl` registra ogni modifica fatta da vulnwatch, `requests-<data>.log` ogni richiesta HTTP fatta da vulnwatch (in `run` e in `apply`).

## Accendere la corsia automatica

Quando qualche report ti ha convinto:
1. imposta `"auto_apply": true` in `config/config.json`;
2. reinstalla con `sudo ./install.sh "$(git rev-parse HEAD)"`.

Da quel momento vulnwatch applica da solo gli aggiornamenti, ma solo per **le formule Homebrew di homebrew/core e i pacchetti npm globali**, solo con audit completamente verde, e solo nei giorni in cui tutte le fonti hanno risposto. Restano manuali per scelta:
- le formule di Python, Node e Bun, perché altri strumenti dipendono da loro;
- app, cask e macOS;
- tutto ciò che sta nei tuoi progetti;
- quello che metti nella lista `hold`.

## Aggiornare

vulnwatch non si aggiorna mai da solo. Per aggiornarlo:

```bash
git pull
git log -p ORIG_HEAD..HEAD                   # leggi cosa è cambiato
sudo ./install.sh "$(git rev-parse HEAD)"
```

## Disinstallare

```bash
sudo ./install.sh --uninstall           # toglie codice, job e comando; tiene report e log
sudo ./install.sh --uninstall --purge   # cancella anche report, stato e log
```

## Cosa esce dal tuo Mac

- **Verso le fonti** (cve.now, CISA, l'elenco CVE su GitHub, OSV) partono le stesse richieste generiche per tutti: il feed delle voci critiche recenti, il catalogo KEV completo, i record CVE per id presi dal registro pubblico delle modifiche, gli export completi di OSV. Niente del tuo software compare mai in un URL, in un header o nel corpo di una richiesta.
- **Verso i canali ufficiali, solo durante un audit:**
  - `registry.npmjs.org` riceve la richiesta dei metadati dell'unico pacchetto npm sotto audit, come li scarica `npm` stesso;
  - `api.github.com` riceve la richiesta della storia dei commit dell'unica formula Homebrew sotto audit (per il cooldown);
  - succede nel job giornaliero, per ogni elemento Homebrew o npm con una correzione nota, e quando lanci `vulnwatch apply`.
- **Homebrew e npm stessi, quando vulnwatch li lancia:**
  - il job giornaliero esegue `brew update` prima di fare l'audit di un elemento Homebrew con una correzione;
  - un'applicazione esegue `brew upgrade` o `npm install -g`, che scaricano il pacchetto;
  - sono richieste di Homebrew e di npm, le stesse di quando li lanci a mano, e quindi non finiscono nel log di vulnwatch.
- **Nient'altro.** Non ci sono telemetria né account, e ogni richiesta HTTP fatta da vulnwatch è in `requests-<data>.log`.

## Domande frequenti

**Perché l'installazione chiede sudo?** Il codice installato e la sua configurazione sono di root, quindi niente di ciò che gira col tuo utente, che sia un malware o una dipendenza compromessa, può cambiare di nascosto cosa fa il job. Il job però gira col tuo utente, senza privilegi.

**Perché non Homebrew o pip?** Perché lo scopo è installare esattamente il codice che hai revisionato: `install.sh` installa un commit git, verificato, e nient'altro.

**Funziona senza Homebrew o npm?** Sì. Il setup rileva cosa hai, e quei controlli si spengono.

**Linux o Windows?** No. vulnwatch è costruito attorno a macOS: launchd, `/Applications`, firme del codice, Homebrew.

**Il primo run è lento.** Sì: scarica 90 giorni di dati pubblici, e cve.now chiede al massimo una richiesta ogni 2 secondi. I run successivi scaricano solo ciò che è cambiato.

## Verificalo tu

Sono circa 5.000 righe di Python con la sola libreria standard, senza dipendenze. Da dove partire:
- `vulnwatch/runner.py`: l'ordine di un run;
- `vulnwatch/net.py`: allowlist degli host e log delle richieste;
- `vulnwatch/apply.py`: i template fissi dei comandi;
- `vulnwatch/audit/`: i controlli;
- `vulnwatch/selfcheck.py`: il controllo di manomissione;
- `install.sh`.

Test:

```bash
/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py'
```

Vedi anche [SECURITY.md](SECURITY.md), [docs/configuration.md](docs/configuration.md) e [CONTRIBUTING.md](CONTRIBUTING.md) (in inglese).

## Licenza

[MIT](LICENSE)
