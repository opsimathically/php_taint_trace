# Verification Corpus (Phase D)

Each JSON file defines one labeled verifier scenario used by:

- `scripts/run_local_verifier_corpus.sh`
- `scripts/report_verification_metrics.sh`
- `scripts/run_release_gate.sh`

Required fields:

- `scenario_id`
- `category`
- `expected_outcome`
- `expected_decision_tier`
- `endpoint`
- `payload_plan.target_query_param`

Phase D baseline uses one expected-confirmed scenario per class:

- `rce`, `ssrf`, `sqli`, `file`, `xss`, `idor` (plus `xxe` in additional sink expansion scenarios)

Additional adversarial false-positive challenge scenarios live in:

- `tests/fixtures/verification_corpus_false_positive_challenges/`

Additional sink-expansion verifier scenarios (`additional_sinks_v1`) include:

- SSRF socket transports (`stream_socket_client`, `pfsockopen`)
- mixed wrapper SSRF surfaces using file APIs (`file_get_contents`, `fopen`, `readfile`)
- RCE `mail` argument-position precision (`mail` additional-params behavior, modeled via `rce_mail_arg5_*` routes)
- file method path handling (`SplFileObject::__construct`)
- SQLi prepared-query style replay surface (`sqli_pg_query_prepared*` fixture routes)

Additional sink-expansion verifier scenarios (`additional_sinks_v2`) include:

- XXE parser/entity surface (`/xxe`, `/xxe_safe`)

Additional sink-expansion verifier scenarios (`additional_sinks_v3`) include:

- XXE method sink surfaces:
  - `DOMDocument::load` (`/xxe?sink=dom_load`)
  - `XMLReader::open` (`/xxe?sink=xmlreader_open`)

Additional sink-expansion verifier scenarios (`additional_sinks_v4`) include extension-conditional sinks:

- SSRF method sink:
  - `SoapClient::__construct` (`/ssrf_soapclient_construct*`)
- SQLi function sink:
  - `sqlsrv_prepare` (`/sqli_sqlsrv_prepare*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v5`) include:

- SSRF method sink (non-WSDL constructor mode):
  - `SoapClient::__construct` location-option path (`/ssrf_soapclient_construct_location*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v6`) include:

- SSRF method sink:
  - `SoapClient::__setLocation` path (`/ssrf_soapclient_setlocation*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v7`) include:

- XXE method sink variants:
  - `DOMDocument::loadXML` (`/xxe?sink=dom_loadxml`)
  - `XMLReader::XML` (`/xxe?sink=xmlreader_xml`)

Additional sink-expansion verifier scenarios (`additional_sinks_v8`) include:

- SSRF cURL aux-tracking sink paths:
  - `curl_exec` with `curl_setopt(CURLOPT_URL, ...)` (`/ssrf_curl_setopt*`)
  - `curl_exec` with `curl_setopt_array([CURLOPT_URL => ...])` (`/ssrf_curl_setopt_array*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v9`) include:

- SSRF cURL multi-handle sink paths:
  - `curl_multi_exec` with `curl_setopt(CURLOPT_URL, ...)` + `curl_multi_add_handle(...)` (`/ssrf_curl_multi_setopt*`)
  - `curl_multi_exec` with `curl_setopt_array([CURLOPT_URL => ...])` + `curl_multi_add_handle(...)` (`/ssrf_curl_multi_setopt_array*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v12`) include:

- SSRF socket/header sink paths:
  - `fsockopen` (`/ssrf_fsockopen*`)
  - `get_headers` (`/ssrf_get_headers*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v13`) include:

- RCE command-family sink paths:
  - `exec` (`/rce_exec*`)
  - `shell_exec` (`/rce_shell_exec*`)
  - `popen` (`/rce_popen*`)
  - `passthru` (`/rce_passthru*`)
  - `proc_open` (`/rce_proc_open*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v15`) include:

- SQLi method sink surfaces:
  - `PDO::query` (`/sqli_pdo_query*`)
  - `SQLite3::querySingle` (`/sqli_sqlite3_querysingle*`)
- XXE SimpleXML sink surfaces:
  - `simplexml_load_string` (`/xxe?sink=simplexml`)
  - `simplexml_load_file` (`/xxe?sink=simplexml_file`)

Additional sink-expansion verifier scenarios (`additional_sinks_v16`) include:

- SQLi method sink surfaces:
  - `PDO::exec` (`/sqli_pdo_exec*`)
  - `SQLite3::query` (`/sqli_sqlite3_query*`)
  - `SQLite3::exec` (`/sqli_sqlite3_exec*`)
- file sink surfaces:
  - `fopen` (`/file_fopen*`)
  - `readfile` (`/file_readfile*`)

Additional sink-expansion verifier scenarios (`additional_sinks_v17`) include:

- RCE opcode sink surface:
  - `include_or_eval` via eval route (`/rce_eval*`)

Optional execution requirements can be declared per-scenario:

- `requires_extensions`
- `requires_functions`
- `requires_classes`
- `requires_methods`

When requirements are not met in local corpus runs, scenarios are skipped with explicit runtime summary accounting in `scenario_requirements_summary.json`.
