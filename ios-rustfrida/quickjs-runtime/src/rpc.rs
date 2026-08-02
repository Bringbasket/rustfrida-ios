//! Frida-compatible RPC export registry and host dispatch helper.

use crate::context::JSContext;

const RPC_BOOTSTRAP: &str = r#"
(function() {
    if (typeof globalThis.rpc === 'undefined' || globalThis.rpc === null) {
        globalThis.rpc = {};
    }
    if (typeof globalThis.rpc.exports === 'undefined' || globalThis.rpc.exports === null) {
        globalThis.rpc.exports = {};
    }
    if (typeof globalThis.rpc.export !== 'function') {
        Object.defineProperty(globalThis.rpc, 'export', {
            value: function(name, fn) {
                if (typeof name !== 'string') {
                    throw new TypeError('rpc.export: name must be a string');
                }
                if (typeof fn !== 'function') {
                    throw new TypeError('rpc.export: fn must be a function');
                }
                globalThis.rpc.exports[name] = fn;
            },
            writable: true,
            configurable: true,
            enumerable: false
        });
    }
    globalThis.__rpc_dispatch = function(method, argsJson) {
        var exports = globalThis.rpc && globalThis.rpc.exports;
        if (!exports || typeof exports[method] !== 'function') {
            throw new Error('RPC method not found: ' + method);
        }
        var args;
        if (argsJson === undefined || argsJson === null || argsJson === '') {
            args = [];
        } else {
            args = JSON.parse(argsJson);
            if (!Array.isArray(args)) {
                throw new TypeError('RPC args must be a JSON array');
            }
        }
        var result = exports[method].apply(null, args);
        if (result === undefined) {
            return 'null';
        }
        return JSON.stringify(result);
    };
})();
"#;

pub fn register_rpc(ctx: &JSContext) -> Result<(), String> {
    let value = ctx.eval(RPC_BOOTSTRAP, "<rpc-bootstrap>")?;
    value.free(ctx.as_ptr());
    Ok(())
}

pub(crate) fn rpc_dispatch_script(method: &str, args_json: &str) -> String {
    format!(
        "__rpc_dispatch({}, {})",
        js_string_literal(method),
        js_string_literal(args_json)
    )
}

fn js_string_literal(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            ch if (ch as u32) < 0x20 => output.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => output.push(ch),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::rpc_dispatch_script;

    #[test]
    fn dispatch_script_escapes_method_and_arguments() {
        assert_eq!(
            rpc_dispatch_script("quoted\"method\n", "[\"a\\\\b\"]"),
            "__rpc_dispatch(\"quoted\\\"method\\n\", \"[\\\"a\\\\\\\\b\\\"]\")"
        );
    }
}
