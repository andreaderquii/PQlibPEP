# Validation of the launch scripts

Executed with PowerShell 7.4.6 on Linux:
- Both .ps1 files parsed with zero syntax errors.
- Logging self-test captured stdout and stderr, returned 0, retained raw output.
- Simulated cargo success emitted 30 samples / 3 summaries / Rust success marker: runner accepted the complete log and copied it into a project path containing a space.
- Simulated cargo failure returned 17: runner returned 17 and retained both the authoritative and project logs.
- Simulated Docker successful sequence: down -> build -> reference -> up -> readiness -> source -> logs.
- Simulated Docker reference failure: script stopped at reference; did not start services or send a request afterward.

These tests validate script control flow and logging; simulated outputs are not benchmark results. Windows PowerShell 5.1 and Docker Desktop were not executed here. Run -SelfTest on the target Windows machine before the actual benchmark.

The included Rust files are unchanged from PQlibPEP-network-equality-patch.zip. Their original release compilation and real toy/paper three-process mTLS correctness checks are recorded in lab/NETWORK_EQUALITY_VALIDATION.txt. This update adds launch/logging scripts; it does not change the cryptographic circuit or benchmark parameters.
