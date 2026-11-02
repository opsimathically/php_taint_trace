# Verification Execution Mode

```mermaid
flowchart LR
    A[run_remote_verifier_tests.sh] --> B[php_worker]
    B --> C[scripts/run_verifier_worker.php --drain]
    C --> D[results.jsonl]
    C --> E[decisions.jsonl]
    C --> F[dead_letters.jsonl]
    D --> G[Validation + Assertions]
    E --> G
    F --> G
```

## Notes

- The remote verifier test harness is now worker-only (`php_worker`).
- DBGp batch backend is intentionally removed from this path to avoid session-plumbing timeouts and replay instability.
- Throughput and accuracy are improved by focusing on deterministic oracle replay + scoring in one backend.
