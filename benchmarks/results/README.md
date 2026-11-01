# Benchmark evidence

These are the original logs, moved without editing their contents. Historical
absolute paths and launch commands printed inside them describe those recorded
runs; they are evidence, not current instructions. Use the root README to rerun.

| File | Meaning |
| --- | --- |
| `pep_benchmark_20261029_191820.log` | Local primitive/API costs |
| `pep_prf_scaling_output.txt` | Original combined 16/32/64-byte sweep; preserve the power-condition caveat |
| `pep_prf_scaling_16_output.txt` | Dedicated 16-byte repeat |
| `pep_prf_scaling_32_output.txt` | Dedicated 32-byte repeat |
| `rlwe_hop_noise_output.txt` | Local RLWE multi-hop/noise diagnostic |

These are local measurements, not Docker network benchmarks. The report uses
its stated session selections; relocation does not change sample provenance.
Subsequent launcher runs copy/write their project log here. As before, fixed-name
scaling/hop log copies can be replaced by a later run. Authoritative scaling logs
remain in per-run LOCALAPPDATA directories. Preserve an evidence copy before
rerunning if you need the original named project logs unchanged.
