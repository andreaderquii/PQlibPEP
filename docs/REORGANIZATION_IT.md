# Riordino del progetto — 31 ottobre 2026

## Scelte

- `old implementations/` diventa `archive/old_implementations/`. Non è nascosta
  né ignorata da Git: conserva lavoro sperimentale e provenienza del report.
- `bpr12_oblivious.rs` e `bpr12_oblivious_test.rs` sono archiviati insieme.
  Il primo era ancora dichiarato in `src/lib/core/mod.rs`; tale dichiarazione
  è rimossa. La pipeline TFHE corrente non importa quel modulo.
- Era presente anche `tests/fast_lwr_prf_pep_hybrid_pipeline.rs`: una vecchia
  copia di un modulo della libreria, non un integration test. Cargo la scopriva
  come test e falliva sugli import `crate::core`/`crate::algebra`. È archiviata;
  i veri test `fast_lwr_prf_pep_hybrid_pipeline_test.rs` e trace restano attivi.
- Non si archiviano indiscriminatamente tutti i file contenenti “BPR12”:
  `rlwr_prf`, il profilo in `parameters.rs` e i moduli aritmetici hanno ancora
  riferimenti attivi. Una menzione storica non è una dipendenza dal modulo rimosso.
- `examples/` è conservata: contiene una sola demo eseguibile della transazione
  ibrida, documentata nel README. Non è necessaria alla libreria; resta utile
  per mostrare come usare le API senza leggere un benchmark.
- I sei launcher sono sotto `scripts/`, i cinque log originali sotto
  `benchmarks/results/`. I loro contenuti sono preservati byte per byte.

## Percorsi aggiornati

Tutti i launcher risolvono la root attraverso `scripts/common/ProjectPaths.ps1`.
Cargo gira nella root; il network launcher usa la stessa root per `src/` e `lab/`.
I log del progetto vengono scritti in `benchmarks/results/`, creata se manca.
I log live persistenti e i file grezzi dello scaling rimangono in LOCALAPPDATA;
la copia finale è nella nuova cartella, e il self-test non la sovrascrive.
Le guide e i comandi nuovi indicano `scripts/`.

## Applicare alla copia esistente

Lo ZIP contiene la cartella completa `PQlibPEP/`, più un installer esterno.
Non basta sovrascrivere la vecchia cartella: i vecchi percorsi rimarrebbero sul disco,
compreso il test BPR12 che importerebbe il modulo ora archiviato.

Estrarre lo ZIP in una cartella separata; dal percorso che contiene
`APPLY_REORGANIZATION.ps1` eseguire:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\APPLY_REORGANIZATION.ps1 -ProjectPath "C:\percorso\del\progetto\PQlibPEP"
```

L'installer controlla gli hash dei file dell'archivio prima di modificare la copia
locale, salva i file toccati in un backup esterno e rimuove solo i vecchi percorsi
che hanno una destinazione verificata. Non tocca la cronologia `.git`, `target`,
chiavi o certificati di `lab/material`. Eventuali guide locali note vengono
spostate in `docs/`; i riferimenti testuali ai launcher vengono aggiornati anche
nelle guide di `lab/`, se presenti. Un conflitto di contenuto blocca l'operazione.
I file locali estranei allo ZIP vengono preservati.

Controllare `git status --short` prima di creare un commit. I benchmark non
vanno ripetuti per questo spostamento; i nuovi test di verifica non generano
nuovi dati sperimentali.

## Lab non incluso

`lab/`, `target/` e `.git/` non erano nello ZIP ricevuto e non sono ricostruiti.
Per Docker serve la propria cartella `lab/` originale. `target/` è rigenerabile;
`.git/` rimane nella propria copia di lavoro. Non cancellare la configurazione
Docker insieme ai bundle: sono i bundle generati a essere pesanti.
