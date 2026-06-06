use crate::state::AppState;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{connect_info::ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, Request, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

const REDACTED: &str = "***";
const DEFAULT_BODY_CAPTURE_LIMIT: usize = 8192;

pub async fn request_response_logging_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let started_at = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let version = request.version();
    let headers = request.headers().clone();
    let client_ip = extract_client_ip(
        &headers,
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr),
        state.config.trust_proxy_headers,
    );
    let max_body_bytes = state.config.http_log_body_max_bytes;

    let (parts, body) = request.into_parts();
    let (request, request_body) =
        match collect_body_for_logging(body, &headers, max_body_bytes, "request").await {
            BodyLogResult::Collected { body, log } => {
                (Request::from_parts(parts, Body::from(body)), log)
            }
            BodyLogResult::Skipped { body, log } => (Request::from_parts(parts, body), log),
            BodyLogResult::Failed { error } => {
                tracing::warn!(
                    client_ip = %client_ip,
                    method = %method,
                    uri = %redact_uri(&uri),
                    error = %error,
                    "Failed to read HTTP request body for logging"
                );
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
    let request_headers = format_headers_for_log(&headers);

    let response = next.run(request).await;
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_body_logging_allowed = should_log_response_body(&uri, &response_headers);
    let (response_parts, response_body) = response.into_parts();
    let (response, response_body) = if response_body_logging_allowed {
        match collect_body_for_logging(response_body, &response_headers, max_body_bytes, "response")
            .await
        {
            BodyLogResult::Collected { body, log } => {
                (Response::from_parts(response_parts, Body::from(body)), log)
            }
            BodyLogResult::Skipped { body, log } => {
                (Response::from_parts(response_parts, body), log)
            }
            BodyLogResult::Failed { error } => {
                tracing::warn!(
                    client_ip = %client_ip,
                    method = %method,
                    uri = %redact_uri(&uri),
                    status = status.as_u16(),
                    error = %error,
                    "Failed to read HTTP response body for logging"
                );
                (
                    Response::from_parts(response_parts, Body::empty()),
                    format!("[response body unavailable: {error}]"),
                )
            }
        }
    } else {
        (
            Response::from_parts(response_parts, response_body),
            "[response body omitted: static/front-end asset]".to_string(),
        )
    };
    let response_headers = format_headers_for_log(&response_headers);
    let duration_ms = started_at.elapsed().as_millis();

    tracing::info!(
        client_ip = %client_ip,
        method = %method,
        uri = %redact_uri(&uri),
        version = ?version,
        status = status.as_u16(),
        duration_ms = duration_ms,
        request_headers = %request_headers,
        request_body = %request_body,
        response_headers = %response_headers,
        response_body = %response_body,
        "HTTP request completed"
    );

    response
}

enum BodyLogResult {
    Collected { body: Bytes, log: String },
    Skipped { body: Body, log: String },
    Failed { error: String },
}

async fn collect_body_for_logging(
    body: Body,
    headers: &HeaderMap,
    max_body_bytes: usize,
    label: &str,
) -> BodyLogResult {
    if max_body_bytes == 0 {
        return BodyLogResult::Skipped {
            body,
            log: "[body logging disabled]".to_string(),
        };
    }

    let capture_limit = max_body_bytes.max(DEFAULT_BODY_CAPTURE_LIMIT);
    let Some(upper) = body.size_hint().upper() else {
        return BodyLogResult::Skipped {
            body,
            log: format!("[{label} body omitted: unknown size]"),
        };
    };

    if upper > capture_limit as u64 {
        return BodyLogResult::Skipped {
            body,
            log: format!(
                "[{label} body omitted: {} bytes exceeds capture limit {}]",
                upper, capture_limit
            ),
        };
    }

    match body.collect().await {
        Ok(collected) => {
            let body = collected.to_bytes();
            let log = format_body_for_log(headers, &body, max_body_bytes);
            BodyLogResult::Collected { body, log }
        }
        Err(err) => BodyLogResult::Failed {
            error: err.to_string(),
        },
    }
}

fn extract_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() && ip.parse::<IpAddr>().is_ok() {
                    return ip.to_string();
                }
            }
        }

        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let ip = value.trim();
            if !ip.is_empty() && ip.parse::<IpAddr>().is_ok() {
                return ip.to_string();
            }
        }
    }

    peer_addr
        .map(|addr| normalize_ip(addr.ip()).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        IpAddr::V4(value) => IpAddr::V4(value),
    }
}

fn redact_uri(uri: &Uri) -> String {
    let Some(query) = uri.query() else {
        return uri.path().to_string();
    };

    format!("{}?{}", uri.path(), redact_query_or_form_body(query))
}

fn format_headers_for_log(headers: &HeaderMap) -> String {
    let mut values = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let value = if is_sensitive_header(name) {
            REDACTED.to_string()
        } else {
            value
                .to_str()
                .map(|value| truncate_for_log(value, 512))
                .unwrap_or_else(|_| "[non-utf8]".to_string())
        };
        values.insert(name.as_str().to_string(), Value::String(value));
    }

    Value::Object(values).to_string()
}

fn format_body_for_log(headers: &HeaderMap, body: &Bytes, max_body_bytes: usize) -> String {
    if body.is_empty() {
        return String::new();
    }
    if max_body_bytes == 0 {
        return "[body logging disabled]".to_string();
    }

    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let formatted = if content_type.contains("json") {
        match serde_json::from_slice::<Value>(body) {
            Ok(mut value) => {
                redact_json_value(&mut value);
                serde_json::to_string(&value).unwrap_or_else(|_| "[invalid json]".to_string())
            }
            Err(_) => text_body(body).unwrap_or_else(|| non_text_body(body.len())),
        }
    } else if content_type.contains("application/x-www-form-urlencoded") {
        text_body(body)
            .map(|body| redact_query_or_form_body(&body))
            .unwrap_or_else(|| non_text_body(body.len()))
    } else if content_type.starts_with("text/")
        || content_type.contains("xml")
        || content_type.is_empty()
    {
        text_body(body).unwrap_or_else(|| non_text_body(body.len()))
    } else {
        non_text_body(body.len())
    };

    truncate_for_log(&formatted, max_body_bytes)
}

fn should_log_response_body(uri: &Uri, headers: &HeaderMap) -> bool {
    if uri.path().starts_with("/setup/assets/") {
        return false;
    }

    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    !(content_type.contains("javascript")
        || content_type.contains("text/css")
        || content_type.contains("text/html"))
}

fn text_body(body: &Bytes) -> Option<String> {
    std::str::from_utf8(body).ok().map(str::to_string)
}

fn non_text_body(len: usize) -> String {
    format!("[non-text body: {len} bytes]")
}

fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *value = Value::String(REDACTED.to_string());
                } else {
                    redact_json_value(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value(value);
            }
        }
        _ => {}
    }
}

fn redact_query_or_form_body(body: &str) -> String {
    body.split('&')
        .map(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                return if is_sensitive_query_or_form_key(pair) {
                    format!("{pair}={REDACTED}")
                } else {
                    pair.to_string()
                };
            };
            if is_sensitive_query_or_form_key(key) {
                format!("{key}={REDACTED}")
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn is_sensitive_header(name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization" | "cookie" | "set-cookie" | "x-api-key" | "api-key"
    ) || lower.contains("token")
        || lower.contains("secret")
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let lower = lower.trim_end_matches("[]");

    matches!(
        lower,
        "access_token"
            | "refresh_token"
            | "id_token"
            | "token"
            | "jwt"
            | "client_secret"
            | "service_secret"
            | "new_secret"
            | "admin_client_secret"
            | "password"
            | "current_password"
            | "new_password"
            | "database_password"
            | "redis_password"
            | "code_verifier"
            | "credential"
    ) || lower.ends_with("_password")
        || lower.ends_with("_secret")
        || lower.ends_with("_token")
        || lower.contains("cookie")
        || lower.contains("credential")
        || lower.contains("private_key")
        || lower.contains("api_key")
        || lower.contains("apikey")
}

fn is_sensitive_query_or_form_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let lower = lower.trim_end_matches("[]");

    is_sensitive_key(lower) || matches!(lower, "code" | "authorization_code")
}

fn truncate_for_log(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}...[truncated, original_bytes={}]",
        &value[..end],
        value.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn client_ip_ignores_forwarded_headers_when_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        let peer = SocketAddr::from(([192, 0, 2, 10], 3000));

        assert_eq!(extract_client_ip(&headers, Some(peer), false), "192.0.2.10");
    }

    #[test]
    fn client_ip_uses_forwarded_headers_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 198.51.100.2"),
        );

        assert_eq!(extract_client_ip(&headers, None, true), "203.0.113.7");
    }

    #[test]
    fn uri_query_is_redacted() {
        let uri = "/v1/auth/callback?code=abc&access_token=secret&token_url=https://idp.example/token&state=ok"
            .parse::<Uri>()
            .unwrap();

        assert_eq!(
            redact_uri(&uri),
            "/v1/auth/callback?code=***&access_token=***&token_url=https://idp.example/token&state=ok"
        );
    }

    #[test]
    fn json_body_is_redacted_recursively() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = Bytes::from(
            r#"{"client_id":"cli","client_secret":"secret","code":"resource:code","admin_client_secret_configured":true,"service_token_endpoint":"/v1/service/token","authorization_url":"https://idp.example/auth","data":{"refresh_token":"token"}}"#,
        );

        let formatted = format_body_for_log(&headers, &body, 2048);

        assert!(formatted.contains(r#""client_secret":"***""#));
        assert!(formatted.contains(r#""refresh_token":"***""#));
        assert!(formatted.contains(r#""code":"resource:code""#));
        assert!(formatted.contains(r#""admin_client_secret_configured":true"#));
        assert!(formatted.contains(r#""service_token_endpoint":"/v1/service/token""#));
        assert!(formatted.contains(r#""authorization_url":"https://idp.example/auth""#));
        assert!(!formatted.contains(r#":"secret""#));
        assert!(!formatted.contains(r#":"token""#));
    }

    #[test]
    fn form_body_is_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let body = Bytes::from("client_id=cli&client_secret=secret&code=oauth-code&scope=read");

        assert_eq!(
            format_body_for_log(&headers, &body, 2048),
            "client_id=cli&client_secret=***&code=***&scope=read"
        );
    }

    #[test]
    fn static_frontend_assets_do_not_log_response_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        );
        let uri = "/setup/assets/index.js".parse::<Uri>().unwrap();

        assert!(!should_log_response_body(&uri, &headers));
    }
}
