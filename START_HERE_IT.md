# Ripartenza: reference e benchmark PRF

Estrarre TUTTO questo ZIP nella cartella contenente Cargo.toml, accettando la sostituzione e mantenendo i percorsi.

File essenziali:
- src/bin/pqpep_lab.rs
- src/lib/core/pep_roles.rs
- run_network_verified.ps1
- run_prf_scaling_benchmark.ps1

Il problema reference non era il testo del comando: il vecchio binario non implementava ancora quel sottocomando. I due file Rust inclusi sono quelli della patch di uguaglianza, già verificati tra tre processi via mTLS con profili toy e paper. Lo script di avvio controlla la presenza del codice, ricostruisce l'immagine, aggiunge il riferimento offline se manca, aspetta T/B e invia una richiesta. Si ferma al primo errore. Non rigenera le chiavi e non rimuove lab/material. Riutilizza gli eventuali riferimenti già presenti: se sono incompatibili o riferiti a un altro ID, B rifiuta il giro e bisogna esaminarli.

Comandi PowerShell dalla cartella del progetto:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_network_verified.ps1
```

Per il giro positivo devono apparire il confronto esatto dei 32 byte del PID, dei 256 coefficienti e l'ACK `verified`. Non basta `opened`.

Per ripetere lo scaling, dopo che il giro di rete è terminato:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_prf_scaling_benchmark.ps1 -SelfTest
```

Procedere solo se appare `[PASS] Both stdout and stderr were saved to the live log.` Poi fermare i container per evitare altre elaborazioni durante il benchmark:

```powershell
docker compose -f lab/compose.yaml stop transcryptor recipient
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_prf_scaling_benchmark.ps1
```

Il benchmark resta invariato: un setup condiviso, output 16/32/64 byte, un warm-up escluso dalle statistiche per taglia e 10 campioni misurati per taglia. Non lanciarlo contemporaneamente ad altri benchmark. Può richiedere parecchio tempo; il messaggio RUNNING ogni 30 secondi indica solo che il processo è ancora attivo, non garantisce progresso del circuito.

Il log principale viene scritto durante il run in:
`%LOCALAPPDATA%\PQlibPEP\benchmarks\prf-scaling-<data>-<id>\pep_prf_scaling_output.txt`

Il percorso esatto è stampato subito. stdout.txt e stderr.txt rimangono nella stessa cartella anche in caso di errore. L'ordine fra i due stream nel log combinato è approssimativo; i file grezzi sono distinti. Il file del progetto `pep_prf_scaling_output.txt` viene aggiornato al termine, ma non è l'unica copia dei risultati. Il self-test usa una propria cartella e non sovrascrive un benchmark precedente.

L'esito positivo richiede exit code 0, 30 righe SAMPLE, 3 riepiloghi STATS e il test Rust passato. Se una di queste condizioni manca lo script segnala errore e conserva l'output. Non cancellare le directory dei log prima di aver raccolto i risultati. Condividere il log del benchmark vero, non quello del self-test.
