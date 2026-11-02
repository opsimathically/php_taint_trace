# End-to-End Verification Flow

```mermaid
flowchart TD
    U[External Request / App Traffic] --> A[PHP App Runtime]
    A --> B[php_taint_trace Runtime Instrumentation]
    B --> C[Hook Detection Runner]
    C --> D[Findings + Detector Candidates]

    D --> E[Request Envelope JSONL<br/>findings + optional candidates]
    D --> F[Verification Job Factory]
    F --> G[JsonlVerificationQueue<br/>jobs.jsonl]

    G --> I[PHP VerificationWorker<br/>Oracles + Replay Runners]
    I --> K[Verification Results<br/>results.jsonl]
    I --> L[Risk Scoring + Tiering]
    L --> M[Decisions<br/>decisions.jsonl]
    K --> P[Metrics + Gates + Reporting]
    M --> P
```

## Notes

- `php_taint_trace` handles request-time detection, candidate creation, and queueing.
- Verification runs through the native PHP worker path.
- Sink oracles (RCE/SSRF/SQLi/File/XSS/IDOR/XXE) drive confirmation and false-positive reduction.
