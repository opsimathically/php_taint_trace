# Remote Vulnerable App Lab Fixtures

These intentionally vulnerable PHP apps are used to validate end-to-end taint
tracing against remote, unmodified app code paths.

Apps:

- `xss_app`: reflected output via `printf`
- `rce_app`: command execution via `system` plus variant sink routes (`mail`, `exec`, `shell_exec`, `popen`, `passthru`, `proc_open`, extension-conditional `pcntl_exec`, `expect_popen`, `dl`)
- `file_app`: arbitrary file read via `file_get_contents` plus sink variants (`fopen`, `readfile`, `SplFileObject::__construct`)
- `ssrf_app`: URL fetch via `file_get_contents` plus socket/method variants (`stream_socket_client`, `pfsockopen`, `fsockopen`, `get_headers`, `curl_exec` via `curl_setopt`/`curl_setopt_array`, `curl_multi_exec` via `curl_multi_add_handle`, `SoapClient::__construct` including non-WSDL `location` mode, and `SoapClient::__setLocation`)
- `sqli_app`: MySQL-backed unsafe query via `PDO::query` plus variant/extension-conditional paths (`PDO::exec`, `mysqli_execute_query`, `SQLite3::querySingle`, `SQLite3::query`, `SQLite3::exec`, `pg_prepare`, `pg_execute`, `pg_send_execute`, `sqlsrv_query`, `sqlsrv_prepare`, `oci_parse`)
- `idor_app`: owner/non-owner authorization differential with vulnerable mode
- `xxe_app`: XML entity handling via `simplexml_load_string` and `simplexml_load_file` (plus DOM/XMLReader sink variants) with vulnerable/safe modes

These fixtures are deployed to the configured remote test container by:

- `scripts/deploy_remote_vuln_lab.sh`

And validated remotely by:

- `scripts/run_remote_vuln_lab_tests.sh`
- `scripts/run_remote_verifier_tests.sh`
