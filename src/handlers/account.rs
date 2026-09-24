use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY};
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse, Response};
use std::path::Path;

const SETUP_DIST_DIR: &str = "web/dist";
const ACCOUNT_PAGE_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Serve the shared frontend shell with headers that keep one-time recovery
/// fragments out of caches, referrers, frames, and unexpected resource origins.
fn account_page_html() -> Response {
    let mut response = match std::fs::read_to_string(Path::new(SETUP_DIST_DIR).join("index.html")) {
        Ok(html) => Html(html).into_response(),
        Err(_) => Html(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>Keylo Account Recovery</title></head>
<body><h1>Keylo Account Recovery UI is not built</h1><p>Run <code>cd web && npm install && npm run build</code>, or use <code>npm run dev</code> during frontend development.</p></body></html>"#,
        )
        .into_response(),
    };

    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ACCOUNT_PAGE_POLICY),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

/// Return the password recovery shell; token consumption remains in the
/// existing JSON API and keeps its rate limits and audit behavior.
pub async fn password_reset_page() -> Response {
    account_page_html()
}
