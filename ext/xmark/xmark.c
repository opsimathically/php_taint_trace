#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "Zend/zend_observer.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm_opcodes.h"
#include "ext/standard/info.h"
#include <stdint.h>

static HashTable xmark_hooks;
static HashTable xmark_opcode_hooks;
static HashTable xmark_hooks_by_target;
static HashTable xmark_opcode_hooks_by_opcode;
static HashTable xmark_tainted_strings;
static zend_bool xmark_initialized = 0;
static zend_bool xmark_in_dispatch = 0;
static zend_long xmark_next_opcode_hook_id = 0;

static void xmark_mark_value(zval *value, zend_bool recursive);
static zend_bool xmark_check_value(zval *value, zend_bool recursive);
static zend_string *xmark_resolve_call_target(zend_execute_data *execute_data, zend_bool *is_method);
static void xmark_dispatch_hooks(zend_execute_data *execute_data, zval *return_value, zend_bool at_begin);
static int xmark_opcode_handler(zend_execute_data *execute_data);
static zend_bool xmark_parse_opcode_target(
    zval *opcode_spec,
    zend_uchar *opcode,
    zend_bool *assign_concat_only,
    zend_string **normalized_target
);
static zend_bool xmark_register_opcode_hook(
    zend_string *id,
    zval *opcode_spec,
    zend_string *phase,
    zval *handler
);
static void xmark_collect_opcode_arguments(zend_execute_data *execute_data, zval *arguments);
static zend_bool xmark_apply_opcode_result(zend_execute_data *execute_data, zval *replacement);
static void xmark_mark_return_tainted(zval *return_value, zval *hook_result);
static zend_ulong xmark_string_identity_key(zend_string *value);
static void xmark_index_hook_by_target(zend_string *target, zend_string *id);
static void xmark_index_opcode_hook(zend_uchar opcode, zend_string *id);
static zend_bool xmark_list_contains_string(zval *list, zend_string *value);
static zend_bool xmark_value_contains_keyword(zval *value, const char *keyword, size_t keyword_len);
static zend_bool xmark_opcode_should_dispatch(zend_uchar opcode, zval *arguments);
static zend_bool xmark_is_runtime_optimized_hook_id(zend_string *id);

PHP_FUNCTION(xmark);
PHP_FUNCTION(xcheck);
PHP_FUNCTION(xmark_register_hook);
PHP_FUNCTION(xregister_opcode_callback);
PHP_FUNCTION(xmark_clear_hooks);
PHP_FUNCTION(xmark_hook_count);

ZEND_BEGIN_ARG_INFO_EX(arginfo_xmark, 0, 0, 1)
    ZEND_ARG_INFO(1, value)
    ZEND_ARG_TYPE_INFO(0, recursive, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, source, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_xcheck, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, recursive, _IS_BOOL, 0, "true")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_xmark_register_hook, 0, 5, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, kind, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, target, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, phase, IS_STRING, 0)
    ZEND_ARG_CALLABLE_INFO(0, handler, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_xregister_opcode_callback, 0, 2, _IS_BOOL, 0)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_CALLABLE_INFO(0, handler, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, phase, IS_STRING, 0, "\"before\"")
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, id, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_xmark_clear_hooks, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_xmark_hook_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry xmark_functions[] = {
    PHP_FE(xmark, arginfo_xmark)
    PHP_FE(xcheck, arginfo_xcheck)
    PHP_FE(xmark_register_hook, arginfo_xmark_register_hook)
    PHP_FE(xregister_opcode_callback, arginfo_xregister_opcode_callback)
    PHP_FE(xmark_clear_hooks, arginfo_xmark_clear_hooks)
    PHP_FE(xmark_hook_count, arginfo_xmark_hook_count)
    PHP_FE_END
};

PHP_FUNCTION(xmark)
{
    zval *value = NULL;
    zend_bool recursive = 1;
    zend_string *source = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL_EX(value, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(recursive)
        Z_PARAM_STR_OR_NULL(source)
    ZEND_PARSE_PARAMETERS_END();

    (void) source;
    xmark_mark_value(value, recursive);
}

PHP_FUNCTION(xcheck)
{
    zval *value = NULL;
    zend_bool recursive = 1;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(value)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(recursive)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(xmark_check_value(value, recursive));
}

PHP_FUNCTION(xmark_register_hook)
{
    zend_string *id = NULL;
    zend_string *kind = NULL;
    zend_string *target = NULL;
    zend_string *phase = NULL;
    zval *handler = NULL;
    zval hook;
    zval handler_copy;
    zend_string *target_lc = NULL;
    zend_string *phase_lc = NULL;

    ZEND_PARSE_PARAMETERS_START(5, 5)
        Z_PARAM_STR(id)
        Z_PARAM_STR(kind)
        Z_PARAM_STR(target)
        Z_PARAM_STR(phase)
        Z_PARAM_ZVAL(handler)
    ZEND_PARSE_PARAMETERS_END();

    if (!zend_is_callable(handler, 0, NULL)) {
        php_error_docref(NULL, E_WARNING, "handler is not callable");
        RETURN_FALSE;
    }

    if (
        strcasecmp(ZSTR_VAL(kind), "function") != 0 &&
        strcasecmp(ZSTR_VAL(kind), "method") != 0 &&
        strcasecmp(ZSTR_VAL(kind), "opcode") != 0
    ) {
        php_error_docref(NULL, E_WARNING, "unsupported hook kind '%s'", ZSTR_VAL(kind));
        RETURN_FALSE;
    }

    if (strcasecmp(ZSTR_VAL(kind), "opcode") == 0) {
        zval opcode_spec;
        ZVAL_STR_COPY(&opcode_spec, target);
        RETVAL_BOOL(xmark_register_opcode_hook(id, &opcode_spec, phase, handler));
        zval_ptr_dtor(&opcode_spec);
        return;
    }

    phase_lc = zend_string_tolower(phase);
    if (
        strcasecmp(ZSTR_VAL(phase_lc), "before") != 0 &&
        strcasecmp(ZSTR_VAL(phase_lc), "after") != 0 &&
        strcasecmp(ZSTR_VAL(phase_lc), "replace") != 0
    ) {
        zend_string_release(phase_lc);
        php_error_docref(NULL, E_WARNING, "unsupported hook phase '%s'", ZSTR_VAL(phase));
        RETURN_FALSE;
    }

    array_init(&hook);
    add_assoc_str(&hook, "id", zend_string_copy(id));
    add_assoc_str(&hook, "kind", zend_string_copy(kind));
    target_lc = zend_string_tolower(target);
    add_assoc_str(&hook, "target", target_lc);
    add_assoc_str(&hook, "phase", phase_lc);
    ZVAL_COPY(&handler_copy, handler);
    add_assoc_zval(&hook, "handler", &handler_copy);

    zend_hash_update(&xmark_hooks, id, &hook);
    xmark_index_hook_by_target(target_lc, id);
    RETURN_TRUE;
}

PHP_FUNCTION(xregister_opcode_callback)
{
    zval *opcode_spec = NULL;
    zval *handler = NULL;
    zend_string *phase = NULL;
    zend_string *id = NULL;
    zend_string *resolved_phase = NULL;
    zend_string *resolved_id = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_ZVAL(opcode_spec)
        Z_PARAM_ZVAL(handler)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR_OR_NULL(phase)
        Z_PARAM_STR_OR_NULL(id)
    ZEND_PARSE_PARAMETERS_END();

    if (!zend_is_callable(handler, 0, NULL)) {
        php_error_docref(NULL, E_WARNING, "handler is not callable");
        RETURN_FALSE;
    }

    if (phase == NULL) {
        resolved_phase = zend_string_init("before", sizeof("before") - 1, 0);
    } else {
        resolved_phase = zend_string_tolower(phase);
    }

    if (
        strcasecmp(ZSTR_VAL(resolved_phase), "before") != 0 &&
        strcasecmp(ZSTR_VAL(resolved_phase), "after") != 0 &&
        strcasecmp(ZSTR_VAL(resolved_phase), "replace") != 0
    ) {
        zend_string_release(resolved_phase);
        php_error_docref(NULL, E_WARNING, "unsupported hook phase '%s'", phase ? ZSTR_VAL(phase) : "before");
        RETURN_FALSE;
    }

    if (id == NULL) {
        resolved_id = strpprintf(0, "opcode.%ld", ++xmark_next_opcode_hook_id);
    } else {
        resolved_id = zend_string_copy(id);
    }

    RETVAL_BOOL(xmark_register_opcode_hook(resolved_id, opcode_spec, resolved_phase, handler));
    zend_string_release(resolved_phase);
    zend_string_release(resolved_id);
}

PHP_FUNCTION(xmark_clear_hooks)
{
    ZEND_PARSE_PARAMETERS_NONE();
    zend_hash_clean(&xmark_hooks);
    zend_hash_clean(&xmark_opcode_hooks);
    zend_hash_clean(&xmark_hooks_by_target);
    zend_hash_clean(&xmark_opcode_hooks_by_opcode);
}

PHP_FUNCTION(xmark_hook_count)
{
    ZEND_PARSE_PARAMETERS_NONE();
    RETURN_LONG(
        (zend_long) zend_hash_num_elements(&xmark_hooks) +
        (zend_long) zend_hash_num_elements(&xmark_opcode_hooks)
    );
}

static void xmark_mark_value(zval *value, zend_bool recursive)
{
    if (Z_ISREF_P(value)) {
        value = Z_REFVAL_P(value);
    }

    if (Z_TYPE_P(value) == IS_STRING) {
        zval marker;
        ZVAL_TRUE(&marker);
        zend_hash_index_update(
            &xmark_tainted_strings,
            xmark_string_identity_key(Z_STR_P(value)),
            &marker
        );
        return;
    }

    if (recursive && Z_TYPE_P(value) == IS_ARRAY) {
        zval *inner;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(value), inner) {
            xmark_mark_value(inner, 1);
        } ZEND_HASH_FOREACH_END();
    }
}

static zend_bool xmark_check_value(zval *value, zend_bool recursive)
{
    if (Z_ISREF_P(value)) {
        value = Z_REFVAL_P(value);
    }

    if (Z_TYPE_P(value) == IS_STRING) {
        return zend_hash_index_exists(
            &xmark_tainted_strings,
            xmark_string_identity_key(Z_STR_P(value))
        );
    }

    if (recursive && Z_TYPE_P(value) == IS_ARRAY) {
        zval *inner;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(value), inner) {
            if (xmark_check_value(inner, 1)) {
                return 1;
            }
        } ZEND_HASH_FOREACH_END();
    }

    return 0;
}

static zend_ulong xmark_string_identity_key(zend_string *value)
{
    return (zend_ulong) (uintptr_t) value;
}

static zend_bool xmark_list_contains_string(zval *list, zend_string *value)
{
    zval *entry = NULL;

    if (list == NULL || Z_TYPE_P(list) != IS_ARRAY) {
        return 0;
    }

    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(list), entry) {
        if (Z_TYPE_P(entry) == IS_STRING && zend_string_equals(Z_STR_P(entry), value)) {
            return 1;
        }
    } ZEND_HASH_FOREACH_END();

    return 0;
}

static void xmark_index_hook_by_target(zend_string *target, zend_string *id)
{
    zval *list = zend_hash_find(&xmark_hooks_by_target, target);
    zval created;

    if (list == NULL || Z_TYPE_P(list) != IS_ARRAY) {
        array_init(&created);
        zend_hash_update(&xmark_hooks_by_target, target, &created);
        list = zend_hash_find(&xmark_hooks_by_target, target);
    }

    if (list == NULL || Z_TYPE_P(list) != IS_ARRAY) {
        return;
    }

    if (!xmark_list_contains_string(list, id)) {
        add_next_index_str(list, zend_string_copy(id));
    }
}

static void xmark_index_opcode_hook(zend_uchar opcode, zend_string *id)
{
    zval *list = zend_hash_index_find(&xmark_opcode_hooks_by_opcode, (zend_ulong) opcode);
    zval created;

    if (list == NULL || Z_TYPE_P(list) != IS_ARRAY) {
        array_init(&created);
        zend_hash_index_update(&xmark_opcode_hooks_by_opcode, (zend_ulong) opcode, &created);
        list = zend_hash_index_find(&xmark_opcode_hooks_by_opcode, (zend_ulong) opcode);
    }

    if (list == NULL || Z_TYPE_P(list) != IS_ARRAY) {
        return;
    }

    if (!xmark_list_contains_string(list, id)) {
        add_next_index_str(list, zend_string_copy(id));
    }
}

static zend_bool xmark_value_contains_keyword(zval *value, const char *keyword, size_t keyword_len)
{
    zval *inner = NULL;

    if (keyword == NULL || keyword_len == 0) {
        return 0;
    }

    if (Z_ISREF_P(value)) {
        value = Z_REFVAL_P(value);
    }

    if (Z_TYPE_P(value) == IS_STRING) {
        return php_memnstr(
            Z_STRVAL_P(value),
            keyword,
            keyword_len,
            Z_STRVAL_P(value) + Z_STRLEN_P(value)
        ) != NULL;
    }

    if (Z_TYPE_P(value) == IS_ARRAY) {
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(value), inner) {
            if (xmark_value_contains_keyword(inner, keyword, keyword_len)) {
                return 1;
            }
        } ZEND_HASH_FOREACH_END();
    }

    return 0;
}

static zend_bool xmark_opcode_should_dispatch(zend_uchar opcode, zval *arguments)
{
    if (arguments == NULL || Z_TYPE_P(arguments) != IS_ARRAY) {
        return 1;
    }

    switch (opcode) {
        case ZEND_ASSIGN_OP:
        case ZEND_CONCAT:
        case ZEND_FAST_CONCAT:
        case ZEND_ROPE_END:
        case ZEND_ECHO:
#ifdef ZEND_EXIT
        case ZEND_EXIT:
#endif
            return xmark_check_value(arguments, 1);
        case ZEND_DO_FCALL:
        case ZEND_DO_FCALL_BY_NAME:
        case ZEND_DO_ICALL:
        case ZEND_DO_UCALL:
        case ZEND_INIT_DYNAMIC_CALL:
        case ZEND_INIT_METHOD_CALL:
        case ZEND_INIT_USER_CALL:
        case ZEND_INCLUDE_OR_EVAL:
            if (xmark_check_value(arguments, 1)) {
                return 1;
            }
            return xmark_value_contains_keyword(arguments, "xtanzi", sizeof("xtanzi") - 1);
        default:
            return 1;
    }
}

static zend_bool xmark_is_runtime_optimized_hook_id(zend_string *id)
{
    if (id == NULL) {
        return 0;
    }

    return
        zend_string_equals_literal(id, "opcode.assign_concat") ||
        zend_string_equals_literal(id, "opcode.concat") ||
        zend_string_equals_literal(id, "opcode.fast_concat") ||
        zend_string_equals_literal(id, "opcode.rope_end") ||
        zend_string_equals_literal(id, "opcode.do_fcall") ||
        zend_string_equals_literal(id, "opcode.do_fcall_by_name") ||
        zend_string_equals_literal(id, "opcode.do_icall") ||
        zend_string_equals_literal(id, "opcode.do_ucall") ||
        zend_string_equals_literal(id, "opcode.echo") ||
        zend_string_equals_literal(id, "opcode.exit") ||
        zend_string_equals_literal(id, "opcode.include_or_eval") ||
        zend_string_equals_literal(id, "opcode.init_dynamic_call") ||
        zend_string_equals_literal(id, "opcode.init_method_call") ||
        zend_string_equals_literal(id, "opcode.init_user_call");
}

static zend_string *xmark_opcode_label(zend_uchar opcode, zend_bool assign_concat_only)
{
    if (assign_concat_only) {
        return zend_string_init("XMARK_ASSIGN_CONCAT", sizeof("XMARK_ASSIGN_CONCAT") - 1, 0);
    }

    switch (opcode) {
        case ZEND_CONCAT:
            return zend_string_init("XMARK_CONCAT", sizeof("XMARK_CONCAT") - 1, 0);
        case ZEND_FAST_CONCAT:
            return zend_string_init("XMARK_FAST_CONCAT", sizeof("XMARK_FAST_CONCAT") - 1, 0);
        case ZEND_ROPE_END:
            return zend_string_init("XMARK_ROPE_END", sizeof("XMARK_ROPE_END") - 1, 0);
        case ZEND_DO_FCALL:
            return zend_string_init("XMARK_DO_FCALL", sizeof("XMARK_DO_FCALL") - 1, 0);
        case ZEND_DO_FCALL_BY_NAME:
            return zend_string_init("XMARK_DO_FCALL_BY_NAME", sizeof("XMARK_DO_FCALL_BY_NAME") - 1, 0);
        case ZEND_DO_ICALL:
            return zend_string_init("XMARK_DO_ICALL", sizeof("XMARK_DO_ICALL") - 1, 0);
        case ZEND_DO_UCALL:
            return zend_string_init("XMARK_DO_UCALL", sizeof("XMARK_DO_UCALL") - 1, 0);
        case ZEND_ECHO:
            return zend_string_init("XMARK_ECHO", sizeof("XMARK_ECHO") - 1, 0);
#ifdef ZEND_EXIT
        case ZEND_EXIT:
            return zend_string_init("XMARK_EXIT", sizeof("XMARK_EXIT") - 1, 0);
#endif
        case ZEND_INCLUDE_OR_EVAL:
            return zend_string_init("XMARK_INCLUDE_OR_EVAL", sizeof("XMARK_INCLUDE_OR_EVAL") - 1, 0);
        case ZEND_INIT_DYNAMIC_CALL:
            return zend_string_init("XMARK_INIT_DYNAMIC_CALL", sizeof("XMARK_INIT_DYNAMIC_CALL") - 1, 0);
        case ZEND_INIT_METHOD_CALL:
            return zend_string_init("XMARK_INIT_METHOD_CALL", sizeof("XMARK_INIT_METHOD_CALL") - 1, 0);
        case ZEND_INIT_USER_CALL:
            return zend_string_init("XMARK_INIT_USER_CALL", sizeof("XMARK_INIT_USER_CALL") - 1, 0);
        default:
            return strpprintf(0, "XMARK_OPCODE_%u", (unsigned int) opcode);
    }
}

static zend_bool xmark_parse_opcode_target(
    zval *opcode_spec,
    zend_uchar *opcode,
    zend_bool *assign_concat_only,
    zend_string **normalized_target
)
{
    zend_string *lowered = NULL;
    const char *name = NULL;

    *assign_concat_only = 0;
    *normalized_target = NULL;

    if (Z_TYPE_P(opcode_spec) == IS_LONG) {
        if (Z_LVAL_P(opcode_spec) < 0 || Z_LVAL_P(opcode_spec) > 255) {
            return 0;
        }

        *opcode = (zend_uchar) Z_LVAL_P(opcode_spec);
        *normalized_target = xmark_opcode_label(*opcode, 0);
        return 1;
    }

    if (Z_TYPE_P(opcode_spec) != IS_STRING) {
        return 0;
    }

    lowered = zend_string_tolower(Z_STR_P(opcode_spec));
    name = ZSTR_VAL(lowered);
    if (strncmp(name, "xmark_", sizeof("xmark_") - 1) == 0) {
        name += sizeof("xmark_") - 1;
    }

    if (strcmp(name, "assign_concat") == 0) {
        *opcode = ZEND_ASSIGN_OP;
        *assign_concat_only = 1;
    } else if (strcmp(name, "concat") == 0) {
        *opcode = ZEND_CONCAT;
    } else if (strcmp(name, "fast_concat") == 0) {
        *opcode = ZEND_FAST_CONCAT;
    } else if (strcmp(name, "rope_end") == 0) {
        *opcode = ZEND_ROPE_END;
    } else if (strcmp(name, "do_fcall") == 0) {
        *opcode = ZEND_DO_FCALL;
    } else if (strcmp(name, "do_fcall_by_name") == 0) {
        *opcode = ZEND_DO_FCALL_BY_NAME;
    } else if (strcmp(name, "do_icall") == 0) {
        *opcode = ZEND_DO_ICALL;
    } else if (strcmp(name, "do_ucall") == 0) {
        *opcode = ZEND_DO_UCALL;
    } else if (strcmp(name, "echo") == 0) {
        *opcode = ZEND_ECHO;
#ifdef ZEND_EXIT
    } else if (strcmp(name, "exit") == 0) {
        *opcode = ZEND_EXIT;
#endif
    } else if (strcmp(name, "include_or_eval") == 0) {
        *opcode = ZEND_INCLUDE_OR_EVAL;
    } else if (strcmp(name, "init_dynamic_call") == 0) {
        *opcode = ZEND_INIT_DYNAMIC_CALL;
    } else if (strcmp(name, "init_method_call") == 0) {
        *opcode = ZEND_INIT_METHOD_CALL;
    } else if (strcmp(name, "init_user_call") == 0) {
        *opcode = ZEND_INIT_USER_CALL;
    } else {
        zend_string_release(lowered);
        return 0;
    }

    *normalized_target = xmark_opcode_label(*opcode, *assign_concat_only);
    zend_string_release(lowered);
    return 1;
}

static zend_bool xmark_register_opcode_hook(
    zend_string *id,
    zval *opcode_spec,
    zend_string *phase,
    zval *handler
)
{
    zval hook;
    zval handler_copy;
    zend_string *phase_lc = NULL;
    zend_string *target = NULL;
    zend_uchar opcode = 0;
    zend_bool assign_concat_only = 0;

    if (!zend_is_callable(handler, 0, NULL)) {
        php_error_docref(NULL, E_WARNING, "handler is not callable");
        return 0;
    }

    phase_lc = zend_string_tolower(phase);
    if (
        strcasecmp(ZSTR_VAL(phase_lc), "before") != 0 &&
        strcasecmp(ZSTR_VAL(phase_lc), "after") != 0 &&
        strcasecmp(ZSTR_VAL(phase_lc), "replace") != 0
    ) {
        zend_string_release(phase_lc);
        php_error_docref(NULL, E_WARNING, "unsupported hook phase '%s'", ZSTR_VAL(phase));
        return 0;
    }

    if (!xmark_parse_opcode_target(opcode_spec, &opcode, &assign_concat_only, &target)) {
        zend_string_release(phase_lc);
        php_error_docref(NULL, E_WARNING, "unsupported opcode target");
        return 0;
    }

    array_init(&hook);
    add_assoc_str(&hook, "id", zend_string_copy(id));
    add_assoc_str(&hook, "kind", zend_string_init("opcode", sizeof("opcode") - 1, 0));
    add_assoc_str(&hook, "target", target);
    add_assoc_str(&hook, "phase", phase_lc);
    add_assoc_long(&hook, "opcode", (zend_long) opcode);
    add_assoc_bool(&hook, "assign_concat_only", assign_concat_only ? 1 : 0);
    ZVAL_COPY(&handler_copy, handler);
    add_assoc_zval(&hook, "handler", &handler_copy);

    zend_hash_update(&xmark_opcode_hooks, id, &hook);
    xmark_index_opcode_hook(opcode, id);
    zend_set_user_opcode_handler(opcode, xmark_opcode_handler);
    return 1;
}

static void xmark_add_operand_argument(
    zval *arguments,
    const zend_op *opline,
    const zend_execute_data *execute_data,
    int op_type,
    const znode_op *node
)
{
    zval *value = NULL;

    if (op_type == IS_UNUSED) {
        return;
    }

    value = zend_get_zval_ptr(opline, op_type, node, execute_data);
    if (value == NULL) {
        add_next_index_null(arguments);
        return;
    }

    Z_TRY_ADDREF_P(value);
    add_next_index_zval(arguments, value);
}

static void xmark_add_call_arguments(zend_execute_data *execute_data, zval *arguments)
{
    zend_execute_data *call = execute_data->call;
    zval params;
    uint32_t argc = 0;
    uint32_t i = 0;
    zend_string *name = NULL;

    if (call == NULL || call->func == NULL || call->func->common.function_name == NULL) {
        add_next_index_null(arguments);
        array_init(&params);
        add_next_index_zval(arguments, &params);
        return;
    }

    if (call->func->common.scope != NULL) {
        name = strpprintf(
            0,
            "%s::%s",
            ZSTR_VAL(call->func->common.scope->name),
            ZSTR_VAL(call->func->common.function_name)
        );
    } else {
        name = zend_string_copy(call->func->common.function_name);
    }
    add_next_index_str(arguments, name);

    array_init(&params);
    argc = ZEND_CALL_NUM_ARGS(call);
    for (i = 0; i < argc; i++) {
        zval *arg = ZEND_CALL_ARG(call, i + 1);
        if (arg == NULL) {
            add_next_index_null(&params);
            continue;
        }

        Z_TRY_ADDREF_P(arg);
        add_next_index_zval(&params, arg);
    }

    add_next_index_zval(arguments, &params);
}

static void xmark_collect_opcode_arguments(zend_execute_data *execute_data, zval *arguments)
{
    const zend_op *opline = execute_data->opline;

    array_init(arguments);

    switch (opline->opcode) {
        case ZEND_DO_FCALL:
        case ZEND_DO_FCALL_BY_NAME:
        case ZEND_DO_ICALL:
        case ZEND_DO_UCALL:
            xmark_add_call_arguments(execute_data, arguments);
            break;
        case ZEND_INCLUDE_OR_EVAL:
        case ZEND_ECHO:
#ifdef ZEND_EXIT
        case ZEND_EXIT:
#endif
        case ZEND_INIT_DYNAMIC_CALL:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            break;
        case ZEND_INIT_METHOD_CALL:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op2_type, &opline->op2);
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            break;
        case ZEND_INIT_USER_CALL:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            break;
        case ZEND_ASSIGN_OP:
        case ZEND_CONCAT:
        case ZEND_FAST_CONCAT:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op2_type, &opline->op2);
            break;
        case ZEND_ROPE_END:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            break;
        default:
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op1_type, &opline->op1);
            xmark_add_operand_argument(arguments, opline, execute_data, opline->op2_type, &opline->op2);
            break;
    }
}

static zend_bool xmark_apply_opcode_result(zend_execute_data *execute_data, zval *replacement)
{
    const zend_op *opline = execute_data->opline;

    if (opline->opcode == ZEND_ASSIGN_OP) {
        zval *target = zend_get_zval_ptr(opline, opline->op1_type, &opline->op1, execute_data);
        if (target != NULL) {
            if (Z_TYPE_P(target) != IS_UNDEF) {
                zval_ptr_dtor(target);
            }
            ZVAL_COPY(target, replacement);
            return 1;
        }
    }

    if (opline->result_type != IS_UNUSED) {
        zval *result = EX_VAR(opline->result.var);
        if (result != NULL) {
            if (Z_TYPE_P(result) != IS_UNDEF) {
                zval_ptr_dtor(result);
            }
            ZVAL_COPY(result, replacement);
            return 1;
        }
    }

    return 0;
}

static void xmark_mark_return_tainted(zval *return_value, zval *hook_result)
{
    if (return_value == NULL || hook_result == NULL) {
        return;
    }

    /*
     * Observer-based replacement of return zvals can be unstable across runtime
     * versions and internal function return paths. For taint propagation, we only
     * need to mark the engine-produced return value when the hook result is tainted.
     */
    if (xmark_check_value(hook_result, 1)) {
        xmark_mark_value(return_value, 1);
    }
}

static int xmark_opcode_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *hook_ids = NULL;
    zval *hook_id = NULL;
    zval replacement;
    zend_bool has_replacement = 0;

    if (
        !xmark_initialized ||
        xmark_in_dispatch ||
        opline == NULL ||
        zend_hash_num_elements(&xmark_opcode_hooks_by_opcode) == 0
    ) {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    hook_ids = zend_hash_index_find(&xmark_opcode_hooks_by_opcode, (zend_ulong) opline->opcode);
    if (hook_ids == NULL || Z_TYPE_P(hook_ids) != IS_ARRAY) {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    ZVAL_UNDEF(&replacement);
    xmark_in_dispatch = 1;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(hook_ids), hook_id) {
        zval *hook_opcode = NULL;
        zval *phase = NULL;
        zval *handler = NULL;
        zval *assign_concat_only = NULL;
        zval *id = NULL;
        zval *target = NULL;
        zval *hook = NULL;
        zval context;
        zval arguments;
        zval metadata;
        zval retval;
        zend_bool is_assign_concat = 0;
        zend_bool is_before = 0;

        if (Z_TYPE_P(hook_id) != IS_STRING) {
            continue;
        }

        hook = zend_hash_find(&xmark_opcode_hooks, Z_STR_P(hook_id));
        if (hook == NULL || Z_TYPE_P(hook) != IS_ARRAY) {
            continue;
        }

        hook_opcode = zend_hash_str_find(Z_ARRVAL_P(hook), "opcode", sizeof("opcode") - 1);
        phase = zend_hash_str_find(Z_ARRVAL_P(hook), "phase", sizeof("phase") - 1);
        handler = zend_hash_str_find(Z_ARRVAL_P(hook), "handler", sizeof("handler") - 1);
        assign_concat_only = zend_hash_str_find(Z_ARRVAL_P(hook), "assign_concat_only", sizeof("assign_concat_only") - 1);
        id = zend_hash_str_find(Z_ARRVAL_P(hook), "id", sizeof("id") - 1);
        target = zend_hash_str_find(Z_ARRVAL_P(hook), "target", sizeof("target") - 1);

        if (
            hook_opcode == NULL || phase == NULL || handler == NULL ||
            Z_TYPE_P(hook_opcode) != IS_LONG || Z_TYPE_P(phase) != IS_STRING
        ) {
            continue;
        }

        if ((zend_uchar) Z_LVAL_P(hook_opcode) != opline->opcode) {
            continue;
        }

        is_assign_concat = assign_concat_only != NULL && zend_is_true(assign_concat_only);
        if (is_assign_concat) {
            if (opline->opcode != ZEND_ASSIGN_OP || opline->extended_value != ZEND_CONCAT) {
                continue;
            }
        }

        is_before = strcasecmp(Z_STRVAL_P(phase), "before") == 0;
        xmark_collect_opcode_arguments(execute_data, &arguments);
        if (
            id != NULL &&
            Z_TYPE_P(id) == IS_STRING &&
            xmark_is_runtime_optimized_hook_id(Z_STR_P(id)) &&
            !xmark_opcode_should_dispatch(opline->opcode, &arguments)
        ) {
            zval_ptr_dtor(&arguments);
            continue;
        }

        array_init(&context);
        array_init(&metadata);
        add_assoc_long(&metadata, "opcode", (zend_long) opline->opcode);
        if (id != NULL && Z_TYPE_P(id) == IS_STRING) {
            add_assoc_str(&metadata, "hook_id", zend_string_copy(Z_STR_P(id)));
        }
        if (target != NULL && Z_TYPE_P(target) == IS_STRING) {
            add_assoc_str(&metadata, "opcode_target", zend_string_copy(Z_STR_P(target)));
        }

        add_assoc_zval(&context, "arguments", &arguments);
        add_assoc_zval(&context, "metadata", &metadata);
        add_assoc_str(
            &context,
            "phase",
            zend_string_init(is_before ? "before" : "after", is_before ? 6 : 5, 0)
        );
        add_assoc_bool(&context, "has_result", is_before ? 0 : 1);
        add_assoc_null(&context, "result");

        ZVAL_UNDEF(&retval);
        {
            zval params[1];
            ZVAL_COPY_VALUE(&params[0], &context);
            if (call_user_function(EG(function_table), NULL, handler, &retval, 1, params) == SUCCESS) {
                if (!is_before && Z_TYPE(retval) != IS_NULL) {
                    if (!has_replacement) {
                        ZVAL_COPY(&replacement, &retval);
                        has_replacement = 1;
                    } else {
                        zval_ptr_dtor(&replacement);
                        ZVAL_COPY(&replacement, &retval);
                    }
                }
            }
        }

        if (!Z_ISUNDEF(retval)) {
            zval_ptr_dtor(&retval);
        }
        zval_ptr_dtor(&context);
    } ZEND_HASH_FOREACH_END();
    xmark_in_dispatch = 0;

    if (has_replacement) {
        zend_bool applied = xmark_apply_opcode_result(execute_data, &replacement);
        zval_ptr_dtor(&replacement);
        if (applied) {
            return ZEND_USER_OPCODE_CONTINUE;
        }
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

static zend_string *xmark_resolve_call_target(zend_execute_data *execute_data, zend_bool *is_method)
{
    zend_function *function = execute_data->func;
    zend_string *raw = NULL;
    zend_string *lowered = NULL;

    *is_method = 0;

    if (function == NULL || function->common.function_name == NULL) {
        return NULL;
    }

    if (function->common.scope != NULL) {
        raw = strpprintf(
            0,
            "%s::%s",
            ZSTR_VAL(function->common.scope->name),
            ZSTR_VAL(function->common.function_name)
        );
        *is_method = 1;
    } else {
        raw = zend_string_copy(function->common.function_name);
    }

    lowered = zend_string_tolower(raw);
    zend_string_release(raw);
    return lowered;
}

static zend_bool xmark_phase_matches(zend_string *phase, zend_bool at_begin)
{
    if (at_begin) {
        return strcasecmp(ZSTR_VAL(phase), "before") == 0 ||
            strcasecmp(ZSTR_VAL(phase), "replace") == 0;
    }

    return strcasecmp(ZSTR_VAL(phase), "after") == 0 ||
        strcasecmp(ZSTR_VAL(phase), "replace") == 0;
}

static void xmark_dispatch_hooks(zend_execute_data *execute_data, zval *return_value, zend_bool at_begin)
{
    zend_string *call_target = NULL;
    zend_bool is_method = 0;
    zval *hook_ids = NULL;
    zval *hook_id = NULL;

    if (!xmark_initialized || xmark_in_dispatch || zend_hash_num_elements(&xmark_hooks_by_target) == 0) {
        return;
    }

    call_target = xmark_resolve_call_target(execute_data, &is_method);
    if (call_target == NULL) {
        return;
    }

    hook_ids = zend_hash_find(&xmark_hooks_by_target, call_target);
    if (hook_ids == NULL || Z_TYPE_P(hook_ids) != IS_ARRAY) {
        zend_string_release(call_target);
        return;
    }

    xmark_in_dispatch = 1;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(hook_ids), hook_id) {
        zval *kind = NULL;
        zval *target = NULL;
        zval *phase = NULL;
        zval *handler = NULL;
        zval *id = NULL;
        zval *hook = NULL;
        zval context;
        zval args;
        zval metadata;
        zval retval;
        uint32_t argc = 0;
        uint32_t i = 0;

        if (Z_TYPE_P(hook_id) != IS_STRING) {
            continue;
        }

        hook = zend_hash_find(&xmark_hooks, Z_STR_P(hook_id));
        if (hook == NULL || Z_TYPE_P(hook) != IS_ARRAY) {
            continue;
        }

        kind = zend_hash_str_find(Z_ARRVAL_P(hook), "kind", sizeof("kind") - 1);
        target = zend_hash_str_find(Z_ARRVAL_P(hook), "target", sizeof("target") - 1);
        phase = zend_hash_str_find(Z_ARRVAL_P(hook), "phase", sizeof("phase") - 1);
        handler = zend_hash_str_find(Z_ARRVAL_P(hook), "handler", sizeof("handler") - 1);
        id = zend_hash_str_find(Z_ARRVAL_P(hook), "id", sizeof("id") - 1);

        if (
            kind == NULL || target == NULL || phase == NULL || handler == NULL ||
            Z_TYPE_P(kind) != IS_STRING || Z_TYPE_P(target) != IS_STRING ||
            Z_TYPE_P(phase) != IS_STRING
        ) {
            continue;
        }

        if (is_method && strcasecmp(Z_STRVAL_P(kind), "method") != 0) {
            continue;
        }

        if (!is_method && strcasecmp(Z_STRVAL_P(kind), "function") != 0) {
            continue;
        }

        if (!xmark_phase_matches(Z_STR_P(phase), at_begin)) {
            continue;
        }

        array_init(&context);
        array_init_size(&args, ZEND_CALL_NUM_ARGS(execute_data));
        argc = ZEND_CALL_NUM_ARGS(execute_data);
        for (i = 0; i < argc; i++) {
            zval *argument = ZEND_CALL_ARG(execute_data, i + 1);
            if (argument == NULL) {
                add_next_index_null(&args);
                continue;
            }

            Z_TRY_ADDREF_P(argument);
            add_next_index_zval(&args, argument);
        }

        array_init(&metadata);
        add_assoc_str(&metadata, "call_target", zend_string_copy(call_target));
        if (id != NULL && Z_TYPE_P(id) == IS_STRING) {
            add_assoc_str(&metadata, "hook_id", zend_string_copy(Z_STR_P(id)));
        }

        add_assoc_zval(&context, "arguments", &args);
        add_assoc_zval(&context, "metadata", &metadata);
        add_assoc_str(&context, "phase", zend_string_init(at_begin ? "before" : "after", at_begin ? 6 : 5, 0));

        if (at_begin || return_value == NULL) {
            add_assoc_bool(&context, "has_result", 0);
            add_assoc_null(&context, "result");
        } else {
            add_assoc_bool(&context, "has_result", 1);
            Z_TRY_ADDREF_P(return_value);
            add_assoc_zval(&context, "result", return_value);
        }

        ZVAL_UNDEF(&retval);
        {
            zval params[1];
            ZVAL_COPY_VALUE(&params[0], &context);
            if (call_user_function(EG(function_table), NULL, handler, &retval, 1, params) == SUCCESS) {
                if (
                    !at_begin &&
                    return_value != NULL &&
                    strcasecmp(Z_STRVAL_P(phase), "replace") == 0 &&
                    Z_TYPE(retval) != IS_NULL
                ) {
                    xmark_mark_return_tainted(return_value, &retval);
                }
            }
        }

        if (!Z_ISUNDEF(retval)) {
            zval_ptr_dtor(&retval);
        }
        zval_ptr_dtor(&context);
    } ZEND_HASH_FOREACH_END();

    xmark_in_dispatch = 0;
    zend_string_release(call_target);
}

static void xmark_observer_begin(zend_execute_data *execute_data)
{
    xmark_dispatch_hooks(execute_data, NULL, 1);
}

static void xmark_observer_end(zend_execute_data *execute_data, zval *return_value)
{
    xmark_dispatch_hooks(execute_data, return_value, 0);
}

static zend_observer_fcall_handlers xmark_observer_init(zend_execute_data *execute_data)
{
    zend_observer_fcall_handlers handlers = {NULL, NULL};
    (void) execute_data;

    if (!xmark_initialized || zend_hash_num_elements(&xmark_hooks) == 0) {
        return handlers;
    }

    handlers.begin = xmark_observer_begin;
    handlers.end = xmark_observer_end;
    return handlers;
}

static void xmark_register_legacy_constants(int module_number)
{
    REGISTER_LONG_CONSTANT("XMARK_ASSIGN_CONCAT", ZEND_ASSIGN_OP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_CONCAT", ZEND_CONCAT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_FAST_CONCAT", ZEND_FAST_CONCAT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_ROPE_END", ZEND_ROPE_END, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_DO_FCALL", ZEND_DO_FCALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_DO_FCALL_BY_NAME", ZEND_DO_FCALL_BY_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_DO_ICALL", ZEND_DO_ICALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_DO_UCALL", ZEND_DO_UCALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_ECHO", ZEND_ECHO, CONST_CS | CONST_PERSISTENT);
#ifdef ZEND_EXIT
    REGISTER_LONG_CONSTANT("XMARK_EXIT", ZEND_EXIT, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("XMARK_INCLUDE_OR_EVAL", ZEND_INCLUDE_OR_EVAL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_INIT_DYNAMIC_CALL", ZEND_INIT_DYNAMIC_CALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_INIT_METHOD_CALL", ZEND_INIT_METHOD_CALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XMARK_INIT_USER_CALL", ZEND_INIT_USER_CALL, CONST_CS | CONST_PERSISTENT);
}

PHP_MINIT_FUNCTION(xmark)
{
    xmark_register_legacy_constants(module_number);
    zend_observer_fcall_register(xmark_observer_init);
    return SUCCESS;
}

PHP_RINIT_FUNCTION(xmark)
{
#if defined(ZTS) && defined(COMPILE_DL_XMARK)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    zend_hash_init(&xmark_hooks, 16, NULL, ZVAL_PTR_DTOR, 0);
    zend_hash_init(&xmark_opcode_hooks, 16, NULL, ZVAL_PTR_DTOR, 0);
    zend_hash_init(&xmark_hooks_by_target, 16, NULL, ZVAL_PTR_DTOR, 0);
    zend_hash_init(&xmark_opcode_hooks_by_opcode, 16, NULL, ZVAL_PTR_DTOR, 0);
    zend_hash_init(&xmark_tainted_strings, 128, NULL, ZVAL_PTR_DTOR, 0);
    xmark_initialized = 1;
    xmark_in_dispatch = 0;
    xmark_next_opcode_hook_id = 0;
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(xmark)
{
    if (xmark_initialized) {
        zend_hash_destroy(&xmark_hooks);
        zend_hash_destroy(&xmark_opcode_hooks);
        zend_hash_destroy(&xmark_hooks_by_target);
        zend_hash_destroy(&xmark_opcode_hooks_by_opcode);
        zend_hash_destroy(&xmark_tainted_strings);
        xmark_initialized = 0;
    }

    return SUCCESS;
}

PHP_MINFO_FUNCTION(xmark)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "xmark support", "enabled");
    php_info_print_table_row(2, "taint keying", "zend_string identity");
    php_info_print_table_row(2, "observer hooks", "function/method");
    php_info_print_table_row(2, "opcode hooks", "user opcode handler");
    php_info_print_table_row(2, "legacy opcode constants", "XMARK_* exported");
    php_info_print_table_end();
}

zend_module_entry xmark_module_entry = {
    STANDARD_MODULE_HEADER,
    "xmark",
    xmark_functions,
    PHP_MINIT(xmark),
    NULL,
    PHP_RINIT(xmark),
    PHP_RSHUTDOWN(xmark),
    PHP_MINFO(xmark),
    "0.1.0",
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_XMARK
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(xmark)
#endif
