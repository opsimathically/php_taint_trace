# xmark Extension (Rewrite)

Initial native extension for PHP 8.x runtime instrumentation in this rewrite project.

## Build

From repo root:

```bash
./scripts/build_xmark_extension.sh
```

Install:

```bash
./scripts/build_xmark_extension.sh --install
```

Enable in `php.ini`:

```ini
extension=xmark.so
```

## Implemented APIs

- `xmark(...)`
- `xcheck(...)`
- `xmark_register_hook(...)`
- `xregister_opcode_callback(...)`
- `xmark_clear_hooks()`
- `xmark_hook_count()`

## Exported Constants

- `XMARK_ASSIGN_CONCAT`
- `XMARK_CONCAT`
- `XMARK_FAST_CONCAT`
- `XMARK_ROPE_END`
- `XMARK_DO_FCALL`
- `XMARK_DO_FCALL_BY_NAME`
- `XMARK_DO_ICALL`
- `XMARK_DO_UCALL`
- `XMARK_ECHO`
- `XMARK_EXIT`
- `XMARK_INCLUDE_OR_EVAL`
- `XMARK_INIT_DYNAMIC_CALL`
- `XMARK_INIT_METHOD_CALL`
- `XMARK_INIT_USER_CALL`

## Current Limits

- Function/method observer hooks are implemented.
- Opcode callback hooks are implemented through user opcode handlers.
- Opcode handlers affect code compiled after registration.
- Taint marks are keyed by runtime string identity (`zend_string*`), not by raw string value.
