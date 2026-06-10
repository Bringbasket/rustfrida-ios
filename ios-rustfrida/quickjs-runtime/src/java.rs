use crate::context::JSContext;
use crate::ffi;
use crate::util::{add_cfunction_to_object, js_throw_internal_error};
use crate::value::JSValue;

const JAVA_UNSUPPORTED_REASON: &str =
    "Java/ART APIs are Android-only; use ObjC, Swift, Native, and Interceptor APIs on iOS";

const JAVA_UNSUPPORTED_METHODS: &[&str] = &[
    "perform",
    "performNow",
    "ready",
    "use",
    "hook",
    "unhook",
    "choose",
    "cast",
    "array",
    "retain",
    "dispose",
    "registerClass",
    "openClassFile",
    "enumerateMethods",
    "scheduleOnMainThread",
    "enumerateLoadedClasses",
    "classLoaders",
    "findClassWithLoader",
    "setClassLoader",
    "setStealth",
    "_classLoaders",
    "_findClassWithLoader",
    "_setClassLoader",
    "_updateClassLoader",
    "deopt",
    "deoptimizeBootImage",
    "deoptimizeEverything",
    "deoptimizeMethod",
    "_artRouterDebug",
    "_methods",
    "_invokeMethod",
    "_invokeStaticMethod",
    "_newObject",
    "_getFieldAuto",
    "_setFieldAuto",
    "getField",
    "_inspectArtMethod",
    "_setForcedInterpretOnly",
    "_initArtController",
];

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, object: &JSValue, name: &str, items: &[&str]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    object.set_property(ctx, name, JSValue(array));
}

unsafe fn java_status_object(ctx: *mut ffi::JSContext) -> JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "available", JSValue::bool(false));
    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "unsupported-ios"));
    result.set_property(ctx, "androidReferenceBackend", JSValue::string(ctx, "ART/JNI"));
    result.set_property(
        ctx,
        "androidReferencePath",
        JSValue::string(ctx, "rustFrida-master/quickjs-hook/src/jsapi/java"),
    );
    result.set_property(ctx, "iosAlternativeRuntime", JSValue::string(ctx, "ObjC/Swift"));
    result.set_property(ctx, "compatible", JSValue::bool(false));
    result.set_property(ctx, "classLoaderReady", JSValue::bool(false));
    result.set_property(ctx, "artRuntimeAvailable", JSValue::bool(false));
    result.set_property(ctx, "jniAvailable", JSValue::bool(false));
    result.set_property(ctx, "hookApiAvailable", JSValue::bool(false));
    result.set_property(ctx, "classLoaderEnumerationAvailable", JSValue::bool(false));
    result.set_property(ctx, "methodEnumerationAvailable", JSValue::bool(false));
    result.set_property(ctx, "fieldAccessAvailable", JSValue::bool(false));
    result.set_property(ctx, "objectInvocationAvailable", JSValue::bool(false));
    result.set_property(ctx, "deoptAvailable", JSValue::bool(false));
    result.set_property(ctx, "supportedMethodCount", JSValue::int(0));
    result.set_property(
        ctx,
        "unsupportedMethodCount",
        JSValue::int(JAVA_UNSUPPORTED_METHODS.len() as i32),
    );
    result.set_property(ctx, "recommendedPath", JSValue::string(ctx, "objc-swift-native"));
    result.set_property(ctx, "lastError", JSValue::string(ctx, JAVA_UNSUPPORTED_REASON));
    set_string_array_property(
        ctx,
        &result,
        "recommendedApis",
        &[
            "ObjC.classes",
            "ObjC.methods",
            "Swift.types",
            "Swift.methods",
            "Native.images",
            "Interceptor.attach",
        ],
    );
    set_string_array_property(ctx, &result, "unsupportedMethods", JAVA_UNSUPPORTED_METHODS);
    result
}

unsafe extern "C" fn js_java_status(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    java_status_object(ctx).raw()
}

unsafe extern "C" fn js_java_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, JAVA_UNSUPPORTED_REASON).raw()
}

unsafe extern "C" fn js_java_false(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(false).raw()
}

unsafe extern "C" fn js_java_empty_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_NewArray(ctx)
}

unsafe extern "C" fn js_java_get_stealth(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::int(0).raw()
}

unsafe extern "C" fn js_java_unsupported(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(ctx, JAVA_UNSUPPORTED_REASON)
}

pub(crate) fn register_java_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let java = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        java.set_property(ctx_ptr, "available", JSValue::bool(false));
        java.set_property(ctx_ptr, "platform", JSValue::string(ctx_ptr, "ios"));
        java.set_property(ctx_ptr, "backend", JSValue::string(ctx_ptr, "unsupported-ios"));
        java.set_property(ctx_ptr, "androidReferenceBackend", JSValue::string(ctx_ptr, "ART/JNI"));
        java.set_property(ctx_ptr, "iosAlternativeRuntime", JSValue::string(ctx_ptr, "ObjC/Swift"));
        java.set_property(ctx_ptr, "compatible", JSValue::bool(false));
        java.set_property(
            ctx_ptr,
            "lastErrorText",
            JSValue::string(ctx_ptr, JAVA_UNSUPPORTED_REASON),
        );

        add_cfunction_to_object(ctx_ptr, java.raw(), "status", js_java_status, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "info", js_java_status, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "lastError", js_java_last_error, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "isAvailable", js_java_false, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "_isClassLoaderReady", js_java_false, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "_reprobeClassLoader", js_java_false, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "getStealth", js_java_get_stealth, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "enumerateLoadedClasses", js_java_empty_array, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "enumerateClassLoaders", js_java_empty_array, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "classLoaders", js_java_empty_array, 0);
        add_cfunction_to_object(ctx_ptr, java.raw(), "_classLoaders", js_java_empty_array, 0);

        for name in JAVA_UNSUPPORTED_METHODS {
            if matches!(*name, "enumerateLoadedClasses" | "classLoaders" | "_classLoaders") {
                continue;
            }
            add_cfunction_to_object(ctx_ptr, java.raw(), name, js_java_unsupported, 0);
        }
    }

    global.set_property(ctx.as_ptr(), "Java", java);
    global.free(ctx.as_ptr());
}
