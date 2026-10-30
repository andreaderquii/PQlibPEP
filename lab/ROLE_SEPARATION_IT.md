# PQlibPEP: A, transcryptor e B come processi distinti

## Cosa cambia

Questa variante aggiunge tre processi reali che usano la pipeline crittografica
esistente. Ogni processo carica soltanto il proprio bundle. La cifratura del
payload è ora una responsabilità dell'API di A; il transcryptor valuta la PRF su
input cifrati, esegue il rekey RLWE A→B e aggiunge Enc_B(0); B apre il risultato.
A inoltra a B la risposta ancora cifrata e, su mTLS A→B, il controllo della
richiesta creato prima dell'invio al transcryptor. La risposta di B ad A contiene
solo una conferma; il PID e gli attributi decifrati rimangono nel processo B.

| Entità runtime | Materiale posseduto |
|---|---|
| A | chiave TFHE di input, chiave RLWE sorgente, chiavi pubbliche e contesto |
| Transcryptor | chiave PRF in chiaro, KSK/BSK TFHE, rekey RLWE A→B, chiavi pubbliche e contesto |
| B | chiave TFHE di output, chiave RLWE destinatario, chiavi pubbliche e contesto |

La chiave PRF è materiale riservato affidato al transcryptor, non una chiave
pubblica. Questa è l'analogia di fiducia con il converter PEP scelta per il
progetto. LWR calcola PID_D = F_s(encoding(D, epoch, namespace, ID)); non è una
conversione reversibile da PID_A a PID_B. Il payload RLWE è un ramo indipendente,
composto con la PRF dalla transazione applicativa. Non vengono implementate RS2
né una pipeline multi-hop di trasformazioni dei PID già calcolati.

## Assunzione di setup

`pqpep-lab provision` è un DEALER FIDATO OFFLINE. Usa il setup TFHE esistente e
vede tutte le chiavi segrete durante la generazione. La KSK e la BSK attuali
richiedono materiale di chiave sorgente/intermedio/destinatario durante il
setup. I tre bundle vengono poi distribuiti separatamente; il dealer e la
chiave privata della CA non sono presenti nei processi runtime. Non è
implementata né provata la cancellazione sicura dei segreti del dealer.

Il risultato è separazione dei ruoli a runtime con setup fidato, non setup
decentralizzato o multiparty. Eliminare il dealer richiede un diverso protocollo di provisioning delle
chiavi di valutazione TFHE, che questa patch non implementa. Questa è una
limitazione della routine attuale, non una prova che ogni alternativa debba
necessariamente usare un dealer o un protocollo multiparty.
Il rekey RLWE può essere generato da A conoscendo soltanto sk_A e pk_B; il dealer
lo esegue in questa fase offline e consegna al transcryptor soltanto il rekey.

## Comunicazione di rete

Le comunicazioni runtime avvengono soltanto su TCP con TLS reciproco. Le
identità hanno certificati diversi. T e B verificano la CA e accettano soltanto
il certificato foglia di A previsto dal provisioning; A verifica nome e CA dei
server `transcryptor` e `recipient`. B non accetta il controllo della richiesta
da T. Le connessioni hanno lunghezze limitate e timeout.

I tre container hanno IP distinti 172.29.88.10 (A), .20 (T), .30 (B), senza porte
pubblicate. La rete Docker è privata/internal. I mount di provisioning sono
separati per ruolo e di sola lettura; non esistono volumi comuni per le richieste
o le risposte, né IPC condiviso. La CA privata è montata soltanto nel tool offline.
I container condividono kernel e amministratore della VM: gli IP diversi non
impediscono all'amministratore dell'host di leggere i segreti dei container.

La PKI usa certificati RSA convenzionali: il trasporto non costituisce una
garanzia post-quantum. Per il successivo esperimento su tre host Internet,
distribuire esclusivamente la directory del rispettivo ruolo, usare indirizzi
VPN e mTLS; questi servizi non vanno esposti come API pubbliche.

## Comandi Docker

Dalla radice del progetto, in una VM Linux o Docker Desktop:

```powershell
docker compose -f lab/compose.yaml --profile setup build setup
```

Primo controllo funzionale con parametri toy espliciti e setup eseguito una
sola volta. `lab/material` non deve già contenere bundle di un'altra run:

```powershell
$env:PQPEP_PROFILE = "toy"
docker compose -f lab/compose.yaml --profile setup run --rm setup
docker compose -f lab/compose.yaml up -d transcryptor recipient
docker compose -f lab/compose.yaml logs transcryptor recipient
```

Attendere `[READY]` da entrambi i servizi, poi:

```powershell
docker compose -f lab/compose.yaml --profile send run --rm source
docker compose -f lab/compose.yaml logs recipient transcryptor
```

B stampa il PID e il numero di coefficienti aperti; A riceve soltanto `opened`.
Per un secondo ID usare `$env:PQPEP_LAB_ID = "patient-demo-002"` prima del comando
source. Per il medesimo ID/dominio/epoca il PID rimane stabile sotto gli stessi
materiali PRF. I payload del comando source sono sintetici (coefficienti i mod 17).

```powershell
docker compose -f lab/compose.yaml down
```

Per il profilo PRF paper, conservare separatamente l'intera vecchia directory
`lab/material`, poi ripetere il provisioning con `$env:PQPEP_PROFILE = "paper"`.
Il comando rifiuta di sovrascrivere chiavi esistenti. Questo profilo mantiene
RLWE N=256, q=998244353 e il preset TFHE sperimentale attuale; NON è un preset
production-secure. Setup e bundle T possono occupare diversi GB di memoria.
Non è necessario rigenerare i materiali a ogni richiesta.

## Compilazione e test senza Docker

```powershell
cargo check --locked --features pep-role-lab --bin pqpep-lab --test pep_role_separation_test
cargo test --locked --release --features pep-role-lab --test pep_role_separation_test -- --nocapture --test-threads=1
cargo build --locked --release --features pep-role-lab --bin pqpep-lab
```

Il lab su host reali usa gli stessi comandi dell'eseguibile:

```
pqpep-lab provision DIRECTORY [paper|toy]            # solo offline
pqpep-lab transcryptor DIRECTORY_T IP_T:7001
pqpep-lab recipient DIRECTORY_B IP_B:7002
pqpep-lab source DIRECTORY_A IP_T:7001 IP_B:7002
```

Ogni directory runtime contiene `role.bin`, `cert.pem`, `key.pem`, `ca.pem`.
Le directory T e B contengono anche `authorized-source.pem`, che è il solo
certificato pubblico di A. Il comando di provisioning genera i bundle; lo
script `lab/make-certs.sh DIRECTORY` genera la PKI di laboratorio con OpenSSL.
La CA privata rimane in `DIRECTORY/offline-ca`, da escludere dagli host runtime.

## Sviste corrette e limiti residui

- Il controllo pending di A ha un formato esplicito, distinto dal payload per
  T. Il parser richiede byte da A autenticato: un fingerprint non è una firma.
- Una route include fingerprint delle chiavi pubbliche RLWE, contesto TFHE,
  dimensione/modulo e base del rekey. Questa associazione è autenticata dal
  provisioning e da mTLS, non dalla matematica di un tag pubblico.
- Il rekey viene controllato per numero di digit, dimensioni e modulo di ogni
  polinomio prima dell'aritmetica, inclusi i rekey per richiesta.
- I costruttori rifiutano moduli incompatibili con la PKE scalar e dimensioni
  di anello non supportate; generate_rekey verifica anche il grado di pk_B.b.
- A cifra e prepara la richiesta senza ricevere la chiave PRF o i segreti di B.
  B apre la risposta senza ricevere i segreti di A o la chiave PRF.
- T e B rifiutano duplicati esatti/transaction ID già consumati durante il
  processo. La cache è limitata a 4096 elementi e fallisce chiusa; non persiste
  ai riavvii. Non è implementata gestione idempotente dei retry dopo perdita
  della risposta, né un database di replay crash-safe.

Restano il problema noto di collusione RLWE T+B, il dizionario PRF quando T
conosce ID prevedibili e ottiene PID in chiaro, i parametri non validati e il
modello di input produttore/evaluatore onesti. Anche le chiavi di valutazione
TFHE contengono segreti cifrati sotto chiavi successive: questa costruzione
non ha una garanzia di resistenza alla collusione T+B per quel ramo; il test
RLWE non costituisce un'analisi del ramo TFHE. La separazione dei processi non
risolve questi problemi. Non ci sono prove di correttezza della PRF o di H(ID)
fornite da un peer malevolo, né autenticazione applicativa post-quantum.

I bundle sono file locali fidati, vincolati alla versione di questo progetto e
TFHE 1.6.2. La loro deserializzazione non è un endpoint di rete per dati esterni.
I certificati scadono dopo 30 giorni; una nuova PKI richiede distribuzione
coerente dei nuovi certificati a tutti i ruoli.

## Stabilità dei PID durante la rotazione delle chiavi

Il provisioning salva `offline-prf-epoch.bin` fuori dalle directory runtime.
Contiene la chiave PRF e il suo dominio/epoca. Va conservato dal provisioner e
non consegnato ad A o B. Per creare nuovi materiali di cifratura mantenendo i
PID usare esplicitamente questa chiave preesistente:

```
pqpep-lab provision NUOVA_DIRECTORY paper VECCHIA_DIRECTORY/offline-prf-epoch.bin
```

Il profilo deve corrispondere alla chiave conservata. Creare una nuova chiave
PRF senza riusare il file cambia deliberatamente i PID; non va confuso con una
semplice rotazione delle chiavi di cifratura. Il test di separazione controlla
anche due setup di cifratura indipendenti con la medesima chiave PRF persistente.
La funzione `trusted_dealer_setup` è solo una scorciatoia sperimentale che genera
una PRF nuova; l'API da usare per rotazioni è `OfflinePrfKey::provision`.

La cifratura TFHE di input attuale è simmetrica: A è il produttore autorizzato
che possiede quella chiave. Non è implementata l'API di cifratura pubblica
anonima di input tipica di altre costruzioni PEP. Le API di hash e i limiti
contro input malevoli restano quelli documentati nel progetto.

## Dettagli della verifica fornita

`lab/smoke_local.py` avvia tre processi indipendenti su IP loopback differenti,
crea certificati di prova e controlla sia il giro A→T→A→B sia il rifiuto di un
certificato B usato per chiamare l'endpoint riservato ad A. Richiede Python 3,
OpenSSL e una shell `sh`; nella VM Linux, dopo la build:

```
python3 lab/smoke_local.py --profile toy
python3 lab/smoke_local.py --profile paper
```

Ogni esecuzione crea materiali temporanei di prova e li rimuove se il test
riesce; se fallisce conserva la directory privata per la diagnosi. Non è un
benchmark: una sola richiesta funzionale, non dieci ripetizioni. Docker Compose
realizza poi lo stesso scambio tra namespace di rete separati.

La feature privata TFHE usa soltanto `core_crypto`; è stato rimosso il caricamento
delle API `integer/shortint`, inutilizzate dal sorgente attivo, per ridurre il
costo di compilazione. Il circuito crittografico e i parametri sono gli stessi.
Riferimento per il confronto dei ruoli e degli attributi nella libpep originale:
https://github.com/NOLAI/libpep (consultato il 30 ottobre 2026).
