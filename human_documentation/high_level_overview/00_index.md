# High-Level Overview: `php_taint_trace` Verification + UI

This folder provides high-level Mermaid diagrams showing how `php_taint_trace` worker-based verification and the visualizer UI work together to perform vulnerability verification with reduced false positives.

## Diagram Index

- [01_end_to_end_verification_flow.md](01_end_to_end_verification_flow.md)
  - End-to-end request/detection/candidate/job/verification flow.
- [02_backend_execution_modes.md](02_backend_execution_modes.md)
  - Worker backend behavior and execution model.
- [03_artifact_and_decision_lifecycle.md](03_artifact_and_decision_lifecycle.md)
  - Runtime data artifacts and how they are produced/consumed.
- [04_remote_e2e_orchestration_and_parity.md](04_remote_e2e_orchestration_and_parity.md)
  - Remote test orchestration and full-category verification validation.
- [05_daemon_cooperative_architecture.md](05_daemon_cooperative_architecture.md)
  - How worker execution and the UI daemon integrate with `php_taint_trace`.
- [06_project_drift_controls.md](06_project_drift_controls.md)
  - Scope and interface controls that keep this architecture aligned to verification goals.
