use crate::context::JSContext;

fn parse_json_string_array(json: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = json.chars().peekable();

    loop {
        match chars.peek() {
            Some(&c) if c.is_whitespace() || c == '[' => {
                chars.next();
            }
            _ => break,
        }
    }

    loop {
        loop {
            match chars.peek() {
                Some(&c) if c.is_whitespace() || c == ',' => {
                    chars.next();
                }
                _ => break,
            }
        }

        match chars.peek() {
            None | Some(&']') => break,
            Some(&'"') => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => break,
                        Some('\\') => match chars.next() {
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some('n') => s.push('\n'),
                            Some('r') => s.push('\r'),
                            Some('t') => s.push('\t'),
                            Some(c) => {
                                s.push('\\');
                                s.push(c);
                            }
                            None => break,
                        },
                        Some('"') => break,
                        Some(c) => s.push(c),
                    }
                }
                if !s.is_empty() {
                    result.push(s);
                }
            }
            _ => {
                chars.next();
            }
        }
    }

    result
}

pub fn complete_script(ctx: &JSContext, prefix: &str) -> Vec<String> {
    let (script, prop_prefix) = if let Some(dot_pos) = prefix.rfind('.') {
        let obj_path = &prefix[..dot_pos];
        let prop_part = &prefix[dot_pos + 1..];
        let escaped = obj_path
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");

        let js = format!(
            r#"(function() {{
                var names = [];
                var obj;
                try {{
                    obj = eval("({escaped})");
                }} catch(e) {{
                    return JSON.stringify([]);
                }}
                if (obj === null || obj === undefined) {{
                    return JSON.stringify([]);
                }}
                var seen = {{}};
                var cur = obj;
                while (cur !== null && cur !== undefined) {{
                    try {{
                        var keys = Object.getOwnPropertyNames(cur);
                        for (var i = 0; i < keys.length; i++) {{
                            if (!seen[keys[i]]) {{
                                seen[keys[i]] = true;
                                names.push(keys[i]);
                            }}
                        }}
                    }} catch(e) {{}}
                    cur = Object.getPrototypeOf(cur);
                }}
                return JSON.stringify(names);
            }})()"#
        );
        (js, prop_part.to_string())
    } else {
        let js = r#"(function() {
            var names = [];
            var obj = globalThis;
            while (obj !== null && obj !== undefined) {
                try {
                    var keys = Object.getOwnPropertyNames(obj);
                    for (var i = 0; i < keys.length; i++) { names.push(keys[i]); }
                } catch(e) {}
                obj = Object.getPrototypeOf(obj);
            }
            return JSON.stringify(names);
        })()"#
            .to_string();
        (js, prefix.to_string())
    };

    let result = match ctx.eval(&script, "<completion>") {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let json_str = match result.to_string(ctx.as_ptr()) {
        Some(s) => s,
        None => {
            result.free(ctx.as_ptr());
            return vec![];
        }
    };
    result.free(ctx.as_ptr());

    let prop_lower = prop_prefix.to_lowercase();
    let mut candidates: Vec<String> = parse_json_string_array(&json_str)
        .into_iter()
        .filter(|name| name.to_lowercase().starts_with(&prop_lower))
        .collect();

    candidates.sort();
    candidates.dedup();
    candidates
}
