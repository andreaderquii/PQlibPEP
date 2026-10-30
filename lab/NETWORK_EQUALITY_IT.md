# Verifica esatta della pipeline di rete

La pipeline A -> T -> A -> B -> A era completa. Il vecchio ACK confermava l'apertura; questo aggiornamento conferma anche la correttezza rispetto a un riferimento indipendente dal percorso cifrato.

Sostituire interamente, dalla radice contenente Cargo.toml:

- src/bin/pqpep_lab.rs
- src/lib/core/pep_roles.rs

La patch contiene anche lab/smoke_local.py aggiornato, facoltativo per Windows e usato qui per le verifiche tra processi Linux. Nessuna dipendenza nuova; non sostituire Cargo.toml/Cargo.lock. Conservare tutti i materiali in lab/material.

Il provisioner offline calcola il PID atteso attraverso FastLwrPrf in chiaro, con la chiave PRF esistente, l'identificatore sintetico, il namespace, dominio ed epoca. Non usa la valutazione TFHE per produrre il riferimento. Salva b/lab-reference.bin con PID atteso, payload sintetico e fingerprint del contesto. Il file non contiene l'identificatore originale o la chiave PRF e rimane nel mount del solo destinatario. E' un vettore di test fidato, non una funzionalità per dati personali di produzione.

B confronta esattamente tutti i 32 byte finali del PID e tutti i coefficienti del payload. Quindi invia `verified`. Qualunque differenza produce un rifiuto e A termina con errore. La verifica è sul risultato finale dopo l'insieme delle trasformazioni; non dimostra isolatamente l'esecuzione di ogni operazione, la sicurezza o la resistenza alla collusione. Il confronto del PID riguarda i 256 bit finali: i quattro bit dei 52 simboli scartati dal packing non appartengono al PID e non sono confrontati.

## Comandi PowerShell completi con i materiali paper esistenti

Dopo aver copiato i due file Rust:

```powershell
Set-Location "C:\Users\andre\OneDrive\Desktop\informatica\magistrale 1\RU2\internship\PQlibPEP\PQlibPEP"

cargo check --locked --features pep-role-lab --bin pqpep-lab
cargo test --locked --release --features pep-role-lab --bin pqpep-lab -- --nocapture

docker compose -f lab/compose.yaml down
docker compose -f lab/compose.yaml --profile setup build setup

$env:PQPEP_PROFILE = "paper"
$env:PQPEP_LAB_ID = "patient-demo-001"
docker compose -f lab/compose.yaml --profile setup run --rm -e PQPEP_LAB_ID=patient-demo-001 --entrypoint pqpep-lab setup reference /material

docker compose -f lab/compose.yaml up -d --no-build transcryptor recipient
docker compose -f lab/compose.yaml logs -f transcryptor recipient
```

Attendere [READY] da T E B. Premere Ctrl+C per lasciare la visualizzazione dei log; i servizi rimangono attivi. Poi:

```powershell
docker compose -f lab/compose.yaml --profile send run --rm source
docker compose -f lab/compose.yaml logs --timestamps transcryptor recipient
```

ATTENZIONE: non eseguire il comando ordinario `setup` senza l'override `--entrypoint pqpep-lab ... reference /material`: la generazione del riferimento è un'operazione distinta dal provisioning delle chiavi. `reference` legge le chiavi esistenti senza rigenerarle. Non sovrascrive un riferimento già esistente: nelle esecuzioni successive saltare questo comando. Se occorre cambiare il vettore sintetico, fermare B e rimuovere solo lab/material/b/lab-reference.bin prima di rigenerarlo, impostando lo stesso PQPEP_LAB_ID per reference e source.

## Esito atteso

```text
[B] [PASS] PID equality: all 32 bytes match the offline CLEAR-PRF reference
[B] [PASS] Attribute equality: ALL 256/256 coefficients match the original synthetic payload after RLWE rekeying + rerandomization
[A] [PASS] B acknowledged EXACT PID and ALL attribute equality against the offline reference. Plaintext/PID remain at B.
```

`Reference comparison completed` è misurato separatamente dall'apertura. Il tempo totale richiesta->ACK include anche i confronti. I timer sono diagnostici; per una statistica servono ripetizioni controllate.

## Test negativo facoltativo su Windows

Dopo un giro riuscito, mantenendo T e B attivi:

```powershell
$env:PQPEP_LAB_ID = "deliberately-wrong-lab-identifier"
docker compose -f lab/compose.yaml --profile send run --rm source
docker compose -f lab/compose.yaml logs --tail 25 recipient
$env:PQPEP_LAB_ID = "patient-demo-001"
```

Questo giro DEVE fallire: B deve stampare `PID equality FAILED`, A deve ricevere un rifiuto e non deve stampare l'ACK di uguaglianza. Una nuova richiesta con l'ID corretto può essere eseguita normalmente.
