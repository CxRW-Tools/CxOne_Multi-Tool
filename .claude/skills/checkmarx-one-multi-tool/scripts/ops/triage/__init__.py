"""
Triage engine — the realistic triage pass and its per-scanner handlers.

`triage_operation.TriageOperation` orchestrates; the `*_handler` modules
implement the SAST / IaC / SCA / Secrets / Containers specifics. Callers import
the submodule directly (`from ops.triage.triage_operation import
TriageOperation`) to keep handler imports lazy and cycle-free.
"""
