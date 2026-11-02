# False Positive Challenge Corpus

This corpus is intentionally designed to pressure-test verifier false-positive handling.

It includes two scenario sets per vulnerability class:

- `*_safe_*`: likely detector candidates that should **not** be confirmed by verifier oracles.
- `*_tricky_confirmed_*`: superficially guarded flows that are still exploitable and should be **confirmed**.

Current coverage:

- scenario count evolves as new sink packets are added (validated by `scripts/run_false_positive_challenge_tests.sh`)
- base set: 4 scenarios per class (`2 safe + 2 vulnerable`) for each of:
  - `rce`, `ssrf`, `sqli`, `file`, `xss`, `idor`
- additional sink-expansion set:
  - SSRF socket transport scenarios (`stream_socket_client`)
  - SSRF wrapper-path scenarios for `file_get_contents`, `fopen`, `readfile`
  - RCE `mail` arg-position precision scenarios (`mail` additional-params path)
  - file method sink scenarios (`SplFileObject::__construct`)
  - SQLi prepared-query route scenarios (`sqli_pg_query_prepared*`)
  - XXE parser/entity scenarios (`/xxe`, `/xxe_safe`)
  - XXE method sink scenarios (`/xxe?sink=dom_load`, `/xxe?sink=xmlreader_open`)
  - XXE method sink variants (`/xxe?sink=dom_loadxml`, `/xxe?sink=xmlreader_xml`)
  - extension-conditional scenarios:
    - SSRF `SoapClient::__construct` (`/ssrf_soapclient_construct*`)
    - SSRF `SoapClient::__construct` location-option mode (`/ssrf_soapclient_construct_location*`)
    - SSRF `SoapClient::__setLocation` (`/ssrf_soapclient_setlocation*`)
    - SSRF `curl_exec` via `curl_setopt`/`curl_setopt_array` (`/ssrf_curl_setopt*`, `/ssrf_curl_setopt_array*`)
    - SSRF `curl_multi_exec` via `curl_multi_add_handle` + `curl_setopt`/`curl_setopt_array` (`/ssrf_curl_multi_setopt*`, `/ssrf_curl_multi_setopt_array*`)
    - SSRF `fsockopen` + `get_headers` (`/ssrf_fsockopen*`, `/ssrf_get_headers*`)
    - SQLi `sqlsrv_prepare` (`/sqli_sqlsrv_prepare*`)
    - RCE command-family guarded/tricky scenarios (`/rce_exec_*`, `/rce_proc_open_*`)
  - additional sink-expansion v15:
    - SQLi method sink guarded/tricky scenarios (`/sqli_pdo_query_*`, `/sqli_sqlite3_querysingle_*`)
    - XXE SimpleXML guarded/tricky scenarios (`/xxe?sink=simplexml*`, `/xxe?sink=simplexml_file*`)
  - additional sink-expansion v16:
    - SQLi method sink guarded/tricky scenarios (`/sqli_pdo_exec_*`, `/sqli_sqlite3_query_*`, `/sqli_sqlite3_exec_*`)
    - file sink guarded/tricky scenarios (`/file_fopen_*`, `/file_readfile_*`)
  - additional sink-expansion v17:
    - RCE opcode sink guarded/tricky scenarios (`/rce_eval_tricky_confirmed*`, `/rce_eval_safe_guarded*`)

Run with:

```bash
bash scripts/run_false_positive_challenge_tests.sh
```

Generated replay-shape matrix coverage is available via:

```bash
bash scripts/run_false_positive_matrix_tests.sh
```
