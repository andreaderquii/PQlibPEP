# Verifica del riordino — 31 ottobre 2026

## Ambiente di verifica

Linux x86_64, Rust/Cargo 1.99.1, PowerShell 7.5.5.
Gli script usano sintassi compatibile con Windows PowerShell 5.1, ma questa
verifica non è stata eseguita su Windows. I risultati qui descritti sono
controlli di regressione del riordino, non nuovi benchmark per il report.

## Controlli completati

- Parsing PowerShell: tutti i sei launcher, l'helper comune e l'installer.
- Tre self-test reali dei launcher scaling: stdout e stderr acquisiti,
  nessun log sperimentale originale sovrascritto.
- Avvio dei cinque launcher benchmark con Cargo simulato: directory di lavoro
  corretta anche da un'altra directory, percorsi contenenti spazi, destinazione
  dei log sotto `benchmarks/results/`, comandi e argomenti attesi.
- Exit code 7 del Cargo simulato propagato dai cinque launcher.
- Avvio del launcher di rete con Docker simulato: risoluzione della root,
  Compose e ruoli corretta. Un `lab/compose.yaml` mancante viene segnalato
  prima di eseguire Docker. Non è una prova reale TCP/mTLS.
- Installer provato su una copia dello ZIP originale: `-CheckOnly` non scrive;
  la migrazione corrisponde ai file attesi; una seconda esecuzione non cambia
  nulla; un contenuto sorgente divergente viene rifiutato prima delle scritture.
- Sentinelle in `.git/`, `target/` e `lab/material/` preservate. Note locali non
  incluse nello ZIP preservate; guide locali spostate/aggiornate.
- `cargo check --locked --tests --examples --features pep-role-lab -j 2`: PASS.
- `cargo check --locked --bin pqpep-lab --features pep-role-lab -j 2`: PASS.
- `cargo test --locked --release --features pep-role-lab --test pep_api_test
  --test pep_role_separation_test -j 2 -- --test-threads=1`: PASS, 3 test.
  Transazione API, separazione dei ruoli/replay/rotazione, materiale di rekey
  malformato: tutti corretti.
- `Cargo.toml` e `Cargo.lock` invariati. Il codice crittografico attivo è
  invariato; in `src/` cambia solo la dichiarazione del modulo BPR12 archiviato.
- I cinque log originali sono identici byte per byte dopo lo spostamento.

Il primo controllo Cargo aveva individuato la vecchia copia di modulo in
`tests/fast_lwr_prf_pep_hybrid_pipeline.rs`; il file è stato archiviato.
I target correnti e i veri test della pipeline rimangono nel progetto.

## Hash dei log conservati

| File | SHA-256 |
| --- | --- |
| `pep_benchmark_20261029_191820.log` | `2bbc4a946e293b5f116a7bd0c91676f1fb9102750d770c0aba1282f9fd495d57` |
| `pep_prf_scaling_16_output.txt` | `211a982803df66102dc3c52e0beab7ae870f9059d81f6d32d794427a9702139b` |
| `pep_prf_scaling_32_output.txt` | `982e31db10226243e00fb792f8bcf4e676c99d2909636f08165a0f5280f95d87` |
| `pep_prf_scaling_output.txt` | `865f5af167b610e4900f2369b0567352729f9df9ef7d71c4fd0555f030933119` |
| `rlwe_hop_noise_output.txt` | `6756869284eb49d345a490d60965b4083a133e1d3e4b376eda8e65cd6553386b` |
