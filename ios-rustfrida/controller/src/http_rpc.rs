//! Minimal HTTP/1.1 server for exposing controller RPC sessions.
//!
//! The transport is synchronous and uses one thread per connection. `RpcBackend`
//! keeps this module independent from any platform-specific session manager.

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use serde_json::{json, Value};

const MAX_REQUEST_LINE_LEN: usize = 8 * 1024;
const MAX_HEADERS_LEN: usize = 16 * 1024;
const MAX_BODY_LEN: usize = 4 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpcSession {
    pub id: String,
    pub pid: Option<i32>,
    pub label: String,
    pub status: String,
}

impl RpcSession {
    pub(crate) fn new(
        id: impl Into<String>,
        pid: Option<i32>,
        label: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            pid,
            label: label.into(),
            status: status.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RpcFailure {
    BadRequest(String),
    NotFound(String),
    Unavailable(String),
    Internal(String),
}

/// Adapter boundary for the controller's current session and command flow.
///
/// Implementations may serialize access internally, for example with a mutex
/// around the active UnixStream. `rpc_call` must honor the supplied timeout.
pub(crate) trait RpcBackend: Send + Sync {
    fn list_sessions(&self) -> Result<Vec<RpcSession>, RpcFailure>;

    fn rpc_call(&self, session: &str, method: &str, args: &Value, timeout: Duration) -> Result<Value, RpcFailure>;
}

/// Bind and start the HTTP server on a background thread.
///
/// The returned address contains the selected port when `bind_addr` uses port
/// zero. The listener and all backend references live on the server thread.
pub(crate) fn start(backend: Arc<dyn RpcBackend>, bind_addr: &str) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind_addr)?;
    let local_addr = listener.local_addr()?;
    thread::Builder::new()
        .name("iosrf-rpc-http".into())
        .spawn(move || accept_loop(listener, backend))?;
    Ok(local_addr)
}

fn accept_loop(listener: TcpListener, backend: Arc<dyn RpcBackend>) {
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                eprintln!("HTTP RPC accept failed: {err}");
                return;
            }
        };
        let backend = Arc::clone(&backend);
        if let Err(err) = thread::Builder::new()
            .name("iosrf-rpc-connection".into())
            .spawn(move || {
                if let Err(err) = handle_connection(stream, backend.as_ref()) {
                    eprintln!("HTTP RPC connection failed: {err}");
                }
            })
        {
            eprintln!("failed to spawn HTTP RPC connection thread: {err}");
        }
    }
}

fn handle_connection(mut stream: TcpStream, backend: &dyn RpcBackend) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    let request = {
        let mut reader = BufReader::new(&mut stream);
        read_request(&mut reader)
    };
    let response = match request {
        Ok(request) => route_request(request, backend),
        Err(failure) => failure.into_response(),
    };
    write_response(&mut stream, &response)
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct RequestFailure {
    status: u16,
    code: &'static str,
    message: String,
}

impl RequestFailure {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(400, code, message)
    }

    fn from_read_error(err: io::Error, context: &'static str) -> Self {
        if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
            Self::new(408, "request_timeout", format!("timed out while {context}"))
        } else {
            Self::bad_request("request_io_error", format!("failed while {context}: {err}"))
        }
    }

    fn into_response(self) -> HttpResponse {
        HttpResponse::error(self.status, self.code, self.message)
    }
}

fn read_request<R: BufRead>(reader: &mut R) -> Result<HttpRequest, RequestFailure> {
    let request_line = read_crlf_line(
        reader,
        MAX_REQUEST_LINE_LEN,
        414,
        "request_line_too_long",
        "reading the request line",
    )?
    .ok_or_else(|| RequestFailure::bad_request("empty_request", "request is empty"))?;
    let (method, target) = parse_request_line(&request_line)?;

    let mut content_length = None;
    let mut transfer_encoding = false;
    let mut host_seen = false;
    let mut headers_len = 0usize;

    loop {
        let line = read_crlf_line(
            reader,
            MAX_HEADERS_LEN,
            431,
            "headers_too_large",
            "reading request headers",
        )?
        .ok_or_else(|| RequestFailure::bad_request("incomplete_headers", "request headers are not terminated"))?;
        headers_len = headers_len
            .checked_add(line.len() + 2)
            .ok_or_else(|| RequestFailure::new(431, "headers_too_large", "request headers are too large"))?;
        if headers_len > MAX_HEADERS_LEN {
            return Err(RequestFailure::new(
                431,
                "headers_too_large",
                "request headers are too large",
            ));
        }
        if line.is_empty() {
            break;
        }

        let (name, value) = parse_header_line(&line)?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RequestFailure::bad_request(
                    "duplicate_content_length",
                    "Content-Length must not be repeated",
                ));
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RequestFailure::bad_request(
                    "invalid_content_length",
                    "Content-Length must be a non-negative decimal integer",
                ));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| RequestFailure::bad_request("invalid_content_length", "Content-Length is out of range"))?;
            if length > MAX_BODY_LEN {
                return Err(RequestFailure::new(
                    413,
                    "body_too_large",
                    format!("request body exceeds {MAX_BODY_LEN} bytes"),
                ));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        } else if name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err(RequestFailure::bad_request(
                    "duplicate_host",
                    "Host must not be repeated",
                ));
            }
            if value.is_empty() {
                return Err(RequestFailure::bad_request("invalid_host", "Host must not be empty"));
            }
            host_seen = true;
        }
    }

    if !host_seen {
        return Err(RequestFailure::bad_request(
            "missing_host",
            "HTTP/1.1 requests require a Host header",
        ));
    }
    if transfer_encoding && content_length.is_some() {
        return Err(RequestFailure::bad_request(
            "ambiguous_body_length",
            "Content-Length and Transfer-Encoding cannot be combined",
        ));
    }
    if transfer_encoding {
        return Err(RequestFailure::new(
            501,
            "unsupported_transfer_encoding",
            "Transfer-Encoding is not supported",
        ));
    }
    if method == "POST" && content_length.is_none() {
        return Err(RequestFailure::new(
            411,
            "content_length_required",
            "POST requests require Content-Length",
        ));
    }

    let length = content_length.unwrap_or(0);
    let mut body = vec![0; length];
    if let Err(err) = reader.read_exact(&mut body) {
        return if err.kind() == io::ErrorKind::UnexpectedEof {
            Err(RequestFailure::bad_request(
                "content_length_mismatch",
                "request body is shorter than Content-Length",
            ))
        } else {
            Err(RequestFailure::from_read_error(err, "reading the request body"))
        };
    }

    Ok(HttpRequest { method, target, body })
}

fn read_crlf_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    limit_status: u16,
    limit_code: &'static str,
    context: &'static str,
) -> Result<Option<Vec<u8>>, RequestFailure> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|err| RequestFailure::from_read_error(err, context))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(RequestFailure::bad_request(
                    "incomplete_line",
                    format!("connection closed while {context}"),
                ))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let available_len = available.len();
        let take = newline.map_or(available_len, |position| position + 1);
        let remaining = limit.saturating_sub(line.len());
        let consumed = take.min(remaining.saturating_add(1));
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);

        if line.len() > limit {
            return Err(RequestFailure::new(
                limit_status,
                limit_code,
                format!("line exceeds {limit} bytes while {context}"),
            ));
        }
        if newline.is_some() && consumed == take {
            break;
        }
    }

    if !line.ends_with(b"\r\n") {
        return Err(RequestFailure::bad_request(
            "invalid_line_ending",
            "HTTP lines must end with CRLF",
        ));
    }
    line.truncate(line.len() - 2);
    Ok(Some(line))
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), RequestFailure> {
    if !line.is_ascii() {
        return Err(RequestFailure::bad_request(
            "invalid_request_line",
            "request line must contain ASCII characters",
        ));
    }
    let line = std::str::from_utf8(line).expect("ASCII request line");
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() || version.is_empty() || parts.next().is_some() {
        return Err(RequestFailure::bad_request(
            "invalid_request_line",
            "request line must be METHOD target HTTP/1.1",
        ));
    }
    if !is_token(method.as_bytes()) {
        return Err(RequestFailure::bad_request(
            "invalid_method",
            "HTTP method contains invalid characters",
        ));
    }
    if version != "HTTP/1.1" {
        return Err(RequestFailure::new(
            505,
            "unsupported_http_version",
            "only HTTP/1.1 is supported",
        ));
    }
    if !target.starts_with('/') || target.contains('#') {
        return Err(RequestFailure::bad_request(
            "invalid_request_target",
            "request target must use origin-form without a fragment",
        ));
    }
    Ok((method.to_string(), target.to_string()))
}

fn parse_header_line(line: &[u8]) -> Result<(&str, &str), RequestFailure> {
    if !line.is_ascii() {
        return Err(RequestFailure::bad_request(
            "invalid_header",
            "header lines must contain ASCII characters",
        ));
    }
    let separator = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| RequestFailure::bad_request("invalid_header", "header line is missing ':'"))?;
    let name = &line[..separator];
    if !is_token(name) {
        return Err(RequestFailure::bad_request(
            "invalid_header_name",
            "header name contains invalid characters",
        ));
    }
    let value = trim_header_value(&line[separator + 1..]);
    if value
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(RequestFailure::bad_request(
            "invalid_header_value",
            "header value contains control characters",
        ));
    }
    Ok((
        std::str::from_utf8(name).expect("ASCII header name"),
        std::str::from_utf8(value).expect("ASCII header value"),
    ))
}

fn trim_header_value(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn route_request(request: HttpRequest, backend: &dyn RpcBackend) -> HttpResponse {
    let segments = match decode_path(&request.target) {
        Ok(segments) => segments,
        Err(failure) => return failure.into_response(),
    };

    if segments.is_empty() {
        return if request.method == "GET" {
            HttpResponse::json(200, json!({ "status": "ok" }))
        } else {
            HttpResponse::method_not_allowed("GET")
        };
    }
    if segments.len() == 1 && segments[0] == "health" {
        return if request.method == "GET" {
            HttpResponse::json(200, json!({ "status": "ok" }))
        } else {
            HttpResponse::method_not_allowed("GET")
        };
    }
    if segments.len() == 1 && segments[0] == "sessions" {
        return if request.method == "GET" {
            list_sessions(backend)
        } else {
            HttpResponse::method_not_allowed("GET")
        };
    }
    if segments.first().is_some_and(|segment| segment == "rpc") {
        if request.method != "POST" {
            return HttpResponse::method_not_allowed("POST");
        }
        if segments.len() != 3 || segments[1].is_empty() || segments[2].is_empty() {
            return HttpResponse::error(400, "invalid_rpc_path", "URL must be /rpc/<session>/<method>");
        }
        return call_rpc(backend, &segments[1], &segments[2], &request.body);
    }

    HttpResponse::error(404, "not_found", "route not found")
}

fn list_sessions(backend: &dyn RpcBackend) -> HttpResponse {
    match backend.list_sessions() {
        Ok(sessions) => {
            let sessions = sessions
                .into_iter()
                .map(|session| {
                    json!({
                        "id": session.id,
                        "pid": session.pid,
                        "label": session.label,
                        "status": session.status,
                    })
                })
                .collect::<Vec<_>>();
            HttpResponse::json(200, Value::Array(sessions))
        }
        Err(failure) => backend_failure_response(failure),
    }
}

fn call_rpc(backend: &dyn RpcBackend, session: &str, method: &str, body: &[u8]) -> HttpResponse {
    let args = if body.iter().all(u8::is_ascii_whitespace) {
        Value::Array(Vec::new())
    } else {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Array(args)) => Value::Array(args),
            Ok(_) => return HttpResponse::error(400, "invalid_rpc_args", "request body must be a JSON array"),
            Err(err) => {
                return HttpResponse::error(400, "invalid_json", format!("request body is not valid JSON: {err}"))
            }
        }
    };

    match backend.rpc_call(session, method, &args, RPC_CALL_TIMEOUT) {
        Ok(result) => HttpResponse::json(200, json!({ "ok": true, "result": result })),
        Err(failure) => backend_failure_response(failure),
    }
}

fn backend_failure_response(failure: RpcFailure) -> HttpResponse {
    match failure {
        RpcFailure::BadRequest(message) => HttpResponse::error(400, "rpc_bad_request", message),
        RpcFailure::NotFound(message) => HttpResponse::error(404, "session_not_found", message),
        RpcFailure::Unavailable(message) => HttpResponse::error(503, "session_unavailable", message),
        RpcFailure::Internal(message) => HttpResponse::error(500, "rpc_internal_error", message),
    }
}

fn decode_path(target: &str) -> Result<Vec<String>, RequestFailure> {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let path = path
        .strip_prefix('/')
        .ok_or_else(|| RequestFailure::bad_request("invalid_request_target", "request path must start with '/'"))?;
    if path.is_empty() {
        return Ok(Vec::new());
    }
    path.split('/').map(decode_path_segment).collect()
}

fn decode_path_segment(segment: &str) -> Result<String, RequestFailure> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(invalid_path_encoding("incomplete percent escape"));
            }
            let high = decode_hex(bytes[index + 1])
                .ok_or_else(|| invalid_path_encoding("percent escape contains a non-hex digit"))?;
            let low = decode_hex(bytes[index + 2])
                .ok_or_else(|| invalid_path_encoding("percent escape contains a non-hex digit"))?;
            index += 3;
            (high << 4) | low
        } else {
            let byte = bytes[index];
            index += 1;
            byte
        };
        if byte == b'/' {
            return Err(invalid_path_encoding("encoded path separators are not allowed"));
        }
        if byte < b' ' || byte == 0x7f {
            return Err(invalid_path_encoding(
                "path segments must not contain control characters",
            ));
        }
        decoded.push(byte);
    }
    String::from_utf8(decoded).map_err(|_| invalid_path_encoding("decoded path segment is not UTF-8"))
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_path_encoding(message: &'static str) -> RequestFailure {
    RequestFailure::bad_request("invalid_path_encoding", message)
}

#[derive(Debug, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    extra_headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            extra_headers: Vec::new(),
            body: value.to_string().into_bytes(),
        }
    }

    fn error(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self::json(
            status,
            json!({
                "ok": false,
                "code": code,
                "error": message.into(),
            }),
        )
    }

    fn method_not_allowed(allow: &'static str) -> Self {
        let mut response = Self::error(405, "method_not_allowed", "method is not allowed for this route");
        response.extra_headers.push(("Allow", allow));
        response
    }
}

fn write_response<W: Write>(writer: &mut W, response: &HttpResponse) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason_phrase(response.status),
        response.body.len()
    )?;
    for (name, value) in &response.extra_headers {
        write!(writer, "{name}: {value}\r\n")?;
    }
    writer.write_all(b"\r\n")?;
    writer.write_all(&response.body)?;
    writer.flush()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Response",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use serde_json::{json, Value};

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct RecordedCall {
        session: String,
        method: String,
        args: Value,
        timeout: Duration,
    }

    #[derive(Default)]
    struct TestBackend {
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl RpcBackend for TestBackend {
        fn list_sessions(&self) -> Result<Vec<RpcSession>, RpcFailure> {
            Ok(vec![RpcSession::new("primary", Some(42), "Demo", "connected")])
        }

        fn rpc_call(&self, session: &str, method: &str, args: &Value, timeout: Duration) -> Result<Value, RpcFailure> {
            self.calls.lock().expect("calls lock").push(RecordedCall {
                session: session.into(),
                method: method.into(),
                args: args.clone(),
                timeout,
            });
            Ok(json!({ "echo": args }))
        }
    }

    struct FailingBackend(RpcFailure);

    impl RpcBackend for FailingBackend {
        fn list_sessions(&self) -> Result<Vec<RpcSession>, RpcFailure> {
            Err(self.0.clone())
        }

        fn rpc_call(
            &self,
            _session: &str,
            _method: &str,
            _args: &Value,
            _timeout: Duration,
        ) -> Result<Value, RpcFailure> {
            Err(self.0.clone())
        }
    }

    fn parse(raw: impl AsRef<[u8]>) -> Result<HttpRequest, RequestFailure> {
        read_request(&mut Cursor::new(raw.as_ref()))
    }

    fn request(method: &str, target: &str, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            target: target.into(),
            body: body.to_vec(),
        }
    }

    fn response_json(response: &HttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("response JSON")
    }

    #[test]
    fn parses_get_and_post_requests() {
        let get = parse(b"GET /health?probe=1 HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("GET request");
        assert_eq!(get.method, "GET");
        assert_eq!(get.target, "/health?probe=1");
        assert!(get.body.is_empty());

        let post = parse(b"POST /rpc/main/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n[1,2]")
            .expect("POST request");
        assert_eq!(post.body, b"[1,2]");
    }

    #[test]
    fn rejects_invalid_request_line_and_http_version() {
        let bad_spacing = parse(b"GET  / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect_err("spacing");
        assert_eq!(bad_spacing.code, "invalid_request_line");

        let version = parse(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").expect_err("version");
        assert_eq!(version.status, 505);

        let lf_only = parse(b"GET / HTTP/1.1\nHost: localhost\n\n").expect_err("line endings");
        assert_eq!(lf_only.code, "invalid_line_ending");
    }

    #[test]
    fn enforces_request_line_and_header_limits() {
        let long_target = format!(
            "GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "a".repeat(MAX_REQUEST_LINE_LEN)
        );
        let line_failure = parse(long_target).expect_err("long request line");
        assert_eq!(line_failure.status, 414);

        let long_header = format!("GET / HTTP/1.1\r\nX-Large: {}\r\n\r\n", "a".repeat(MAX_HEADERS_LEN));
        let header_failure = parse(long_header).expect_err("large headers");
        assert_eq!(header_failure.status, 431);
    }

    #[test]
    fn validates_host_and_header_syntax() {
        let missing_host = parse(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n").expect_err("missing Host");
        assert_eq!(missing_host.code, "missing_host");

        let malformed = parse(b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n").expect_err("malformed header");
        assert_eq!(malformed.code, "invalid_header");

        let duplicate = parse(b"GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n").expect_err("duplicate Host");
        assert_eq!(duplicate.code, "duplicate_host");
    }

    #[test]
    fn validates_content_length_and_body_size() {
        let invalid = parse(b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1x\r\n\r\nx")
            .expect_err("invalid length");
        assert_eq!(invalid.code, "invalid_content_length");

        let duplicate =
            parse(b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n")
                .expect_err("duplicate length");
        assert_eq!(duplicate.code, "duplicate_content_length");

        let missing = parse(b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\n\r\n").expect_err("missing length");
        assert_eq!(missing.status, 411);

        let too_large = format!(
            "POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_LEN + 1
        );
        assert_eq!(parse(too_large).expect_err("large body").status, 413);

        let truncated = parse(b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n[]")
            .expect_err("truncated body");
        assert_eq!(truncated.code, "content_length_mismatch");
    }

    #[test]
    fn rejects_transfer_encoding_and_ambiguous_framing() {
        let chunked = parse(b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect_err("chunked body");
        assert_eq!(chunked.status, 501);

        let ambiguous = parse(
            b"POST /rpc/a/b HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        )
        .expect_err("ambiguous framing");
        assert_eq!(ambiguous.code, "ambiguous_body_length");
    }

    #[test]
    fn routes_health_and_sessions() {
        let backend = TestBackend::default();
        for target in ["/", "/health", "/health?verbose=1"] {
            let response = route_request(request("GET", target, b""), &backend);
            assert_eq!(response.status, 200);
            assert_eq!(response_json(&response)["status"], "ok");
        }

        let sessions = route_request(request("GET", "/sessions", b""), &backend);
        assert_eq!(sessions.status, 200);
        assert_eq!(response_json(&sessions)[0]["id"], "primary");
        assert_eq!(response_json(&sessions)[0]["pid"], 42);
    }

    #[test]
    fn routes_rpc_and_decodes_path_segments() {
        let backend = Arc::new(TestBackend::default());
        let args = json!([
            "text",
            null,
            true,
            42.5,
            { "nested": [1, "two", false] },
            [null, { "deep": true }]
        ]);
        let body = serde_json::to_vec(&args).expect("encode RPC args");
        let response = route_request(request("POST", "/rpc/%70rimary/say%20hello", &body), backend.as_ref());
        assert_eq!(response.status, 200);
        assert_eq!(
            response_json(&response),
            json!({ "ok": true, "result": { "echo": args.clone() } })
        );

        let calls = backend.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].session, "primary");
        assert_eq!(calls[0].method, "say hello");
        assert_eq!(calls[0].args, args);
        assert_eq!(calls[0].timeout, RPC_CALL_TIMEOUT);
    }

    #[test]
    fn decodes_utf8_segments_and_rejects_illegal_percent_encoding() {
        assert_eq!(
            decode_path_segment("%E6%B5%8B%E8%AF%95").expect("UTF-8 segment"),
            "\u{6d4b}\u{8bd5}"
        );

        for target in ["/rpc/a/b%", "/rpc/a/%GG", "/rpc/a/a%2Fb", "/rpc/a/%FF"] {
            let response = route_request(request("POST", target, b"[]"), &TestBackend::default());
            assert_eq!(response.status, 400, "target: {target}");
            assert_eq!(response_json(&response)["code"], "invalid_path_encoding");
        }
    }

    #[test]
    fn validates_rpc_route_and_json_arguments() {
        let backend = TestBackend::default();
        let bad_path = route_request(request("POST", "/rpc/a", b"[]"), &backend);
        assert_eq!(bad_path.status, 400);

        let invalid_json = route_request(request("POST", "/rpc/a/b", b"["), &backend);
        assert_eq!(response_json(&invalid_json)["code"], "invalid_json");

        let not_array = route_request(request("POST", "/rpc/a/b", br#"{"x":1}"#), &backend);
        assert_eq!(response_json(&not_array)["code"], "invalid_rpc_args");

        let empty = route_request(request("POST", "/rpc/a/b", b" \t\r\n"), &backend);
        assert_eq!(empty.status, 200);
        assert_eq!(
            backend.calls.lock().expect("calls lock").last().expect("call").args,
            json!([])
        );
    }

    #[test]
    fn returns_json_for_missing_routes_and_wrong_methods() {
        let backend = TestBackend::default();
        let missing = route_request(request("GET", "/missing", b""), &backend);
        assert_eq!(missing.status, 404);
        assert_eq!(response_json(&missing)["ok"], false);

        let wrong_method = route_request(request("POST", "/health", b""), &backend);
        assert_eq!(wrong_method.status, 405);
        assert_eq!(wrong_method.extra_headers, vec![("Allow", "GET")]);
    }

    #[test]
    fn maps_backend_failures_to_http_errors() {
        let cases = [
            (RpcFailure::BadRequest("bad args".into()), 400),
            (RpcFailure::NotFound("no session".into()), 404),
            (RpcFailure::Unavailable("disconnected".into()), 503),
            (RpcFailure::Internal("transport failed".into()), 500),
        ];
        for (failure, status) in cases {
            let response = route_request(request("POST", "/rpc/a/b", b"[]"), &FailingBackend(failure));
            assert_eq!(response.status, status);
            assert_eq!(response_json(&response)["ok"], false);
        }
    }

    #[test]
    fn serializes_http_response_with_exact_content_length() {
        let response = HttpResponse::error(400, "invalid_request", "bad request");
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response).expect("write response");
        let separator = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("header separator");
        let headers = std::str::from_utf8(&bytes[..separator]).expect("headers");
        let body = &bytes[separator + 4..];
        assert!(headers.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
        assert_eq!(serde_json::from_slice::<Value>(body).expect("body JSON")["ok"], false);
    }

    #[test]
    fn parser_failures_render_as_json() {
        let failure = parse(b"GET / HTTP/1.1\r\n\r\n").expect_err("missing Host");
        let response = failure.into_response();
        assert_eq!(response.status, 400);
        assert_eq!(response_json(&response)["code"], "missing_host");
    }
}
