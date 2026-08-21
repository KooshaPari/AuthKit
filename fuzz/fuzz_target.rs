//! libFuzzer target for AuthKit's PKCE state-session middleware.
//!
//! This target exercises the `query_param` and `cookie_value` parsing
//! functions indirectly by constructing HTTP requests with fuzzed URI query
//! strings and Cookie headers, then running them through
//! `enforce_pkce_state_session`.
//!
//! The goal is to find panics, UB, or unexpected rejections in the parsing
//! code when fed arbitrary input.

#![no_main]

use authkit::{enforce_pkce_state_session, InMemorySessionStore, SessionStore};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::routing::get;
use axum::Router;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use tower::ServiceExt;

/// Interpret fuzz input as two strings: one for the query parameter value
/// (passed as `?state=<s1>`) and one for the cookie value (passed as
/// `session_id=<s2>`).  This exercises `query_param` and `cookie_value`
/// with arbitrary byte sequences interpreted as UTF-8.
fuzz_target!(|data: &[u8]| {
    // Require valid UTF-8 so we get meaningful string parsing.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Split at a pivot point — first half goes into the query string,
    // second half goes into the cookie value.  Using a midpoint gives
    // coverage of both short and long inputs.
    if s.is_empty() {
        return;
    }
    let pivot = s.len() / 2;
    let (query_val, cookie_val) = s.split_at(pivot);

    // Pre-bind the state so the middleware has something to match against
    // (otherwise it always returns UNAUTHORIZED for valid bindings too,
    // which is less interesting for fuzzing).
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let _ = store.bind_state(query_val, cookie_val);

    let uri = format!("/oauth/callback?state={}", query_val);
    let cookie = format!("session_id={}", cookie_val);

    let request = Request::builder()
        .uri(&uri)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();

    // Build a minimal router with the middleware under test and send the
    // fuzzed request through it via `oneshot`.  The response status is
    // checked only to ensure we don't panic; any status code is acceptable.
    let app = Router::new()
        .route(
            "/oauth/callback",
            get(|| async { (StatusCode::OK, "ok") }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            store,
            enforce_pkce_state_session,
        ));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let response = rt.block_on(async { app.oneshot(request).await });

    match response {
        Ok(resp) => {
            // Simply consuming the response is sufficient for fuzzing.
            let _ = resp;
        }
        // oneshot can return an error if the service fails; that is
        // acceptable during fuzzing and should not cause a panic.
        Err(_) => {}
    }
});
