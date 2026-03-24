#include "quickjs.h"
#include <stdlib.h>

void qjs_free_value(JSContext *ctx, JSValue v) {
    JS_FreeValue(ctx, v);
}

void qjs_free_value_rt(JSRuntime *rt, JSValue v) {
    JS_FreeValueRT(rt, v);
}

JSValue qjs_dup_value(JSContext *ctx, JSValue v) {
    return JS_DupValue(ctx, v);
}

JSValue qjs_dup_value_rt(JSRuntime *rt, JSValue v) {
    return JS_DupValueRT(rt, v);
}

const char *qjs_to_cstring(JSContext *ctx, JSValue val) {
    return JS_ToCString(ctx, val);
}

void qjs_free_cstring(JSContext *ctx, const char *str) {
    JS_FreeCString(ctx, str);
}

JSValue qjs_get_property(JSContext *ctx, JSValue this_obj, JSAtom prop) {
    return JS_GetProperty(ctx, this_obj, prop);
}

int qjs_set_property(JSContext *ctx, JSValue this_obj, JSAtom prop, JSValue val) {
    return JS_SetProperty(ctx, this_obj, prop, val);
}

JSValue qjs_new_cfunction(JSContext *ctx, JSCFunction *func, const char *name, int length) {
    return JS_NewCFunction(ctx, func, name, length);
}

JSValue qjs_new_cfunction_magic(JSContext *ctx, JSCFunctionMagic *func,
                                const char *name, int length, JSCFunctionEnum cproto, int magic) {
    return JS_NewCFunctionMagic(ctx, func, name, length, cproto, magic);
}

int qjs_is_number(JSValue v) {
    return JS_IsNumber(v);
}

int qjs_is_big_int(JSContext *ctx, JSValue v) {
    return JS_IsBigInt(ctx, v);
}

int qjs_is_bool(JSValue v) {
    return JS_IsBool(v);
}

int qjs_is_null(JSValue v) {
    return JS_IsNull(v);
}

int qjs_is_undefined(JSValue v) {
    return JS_IsUndefined(v);
}

int qjs_is_exception(JSValue v) {
    return JS_IsException(v);
}

int qjs_is_uninitialized(JSValue v) {
    return JS_IsUninitialized(v);
}

int qjs_is_string(JSValue v) {
    return JS_IsString(v);
}

int qjs_is_symbol(JSValue v) {
    return JS_IsSymbol(v);
}

int qjs_is_object(JSValue v) {
    return JS_IsObject(v);
}

int32_t qjs_value_get_tag(JSValue v) {
    return JS_VALUE_GET_TAG(v);
}

int32_t qjs_value_get_int(JSValue v) {
    return JS_VALUE_GET_INT(v);
}

int qjs_value_get_bool(JSValue v) {
    return JS_VALUE_GET_BOOL(v);
}

double qjs_value_get_float64(JSValue v) {
    return JS_VALUE_GET_FLOAT64(v);
}

void *qjs_value_get_ptr(JSValue v) {
    return JS_VALUE_GET_PTR(v);
}

JSValue qjs_mkval(int32_t tag, int32_t val) {
    return JS_MKVAL(tag, val);
}

JSValue qjs_mkptr(int32_t tag, void *ptr) {
    return JS_MKPTR(tag, ptr);
}

JSValue qjs_new_bool(JSContext *ctx, int val) {
    return JS_NewBool(ctx, val);
}

JSValue qjs_new_int32(JSContext *ctx, int32_t val) {
    return JS_NewInt32(ctx, val);
}

JSValue qjs_new_int64(JSContext *ctx, int64_t val) {
    return JS_NewInt64(ctx, val);
}

JSValue qjs_new_uint32(JSContext *ctx, uint32_t val) {
    return JS_NewUint32(ctx, val);
}

JSValue qjs_new_float64(JSContext *ctx, double val) {
    return JS_NewFloat64(ctx, val);
}

int qjs_to_uint32(JSContext *ctx, uint32_t *pres, JSValue val) {
    return JS_ToUint32(ctx, pres, val);
}

int qjs_to_int64(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToInt64(ctx, pres, val);
}

int qjs_to_index(JSContext *ctx, uint64_t *pres, JSValue val) {
    return JS_ToIndex(ctx, pres, val);
}

int qjs_to_float64(JSContext *ctx, double *pres, JSValue val) {
    return JS_ToFloat64(ctx, pres, val);
}

int qjs_to_big_int64(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToBigInt64(ctx, pres, val);
}

int qjs_to_int64_ext(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToInt64Ext(ctx, pres, val);
}

int qjs_value_to_u64(JSContext *ctx, uint64_t *pres, JSValue val) {
    if (JS_IsBigInt(ctx, val)) {
        JSValue str = JS_ToString(ctx, val);
        if (JS_IsException(str)) {
            *pres = 0;
            return -1;
        }
        const char *cstr = JS_ToCString(ctx, str);
        JS_FreeValue(ctx, str);
        if (!cstr) {
            *pres = 0;
            return -1;
        }
        char *end;
        *pres = strtoull(cstr, &end, 10);
        JS_FreeCString(ctx, cstr);
        return 0;
    }
    return JS_ToInt64(ctx, (int64_t *)pres, val);
}

JSValue qjs_null(void) {
    return JS_NULL;
}

JSValue qjs_undefined(void) {
    return JS_UNDEFINED;
}

JSValue qjs_false(void) {
    return JS_FALSE;
}

JSValue qjs_true(void) {
    return JS_TRUE;
}

JSValue qjs_exception(void) {
    return JS_EXCEPTION;
}

JSValue qjs_uninitialized(void) {
    return JS_UNINITIALIZED;
}

void qjs_update_stack_top(JSContext *ctx) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_UpdateStackTop(rt);
}
