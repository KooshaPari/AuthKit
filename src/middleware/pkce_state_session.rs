//! Tower middleware for binding OAuth PKCE state to a server session.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use percent_encoding::percent_decode_str;
use serde::Serialize;

use crate::domain::session_store::SessionStore;

const INVALID_STATE_DESCRIPTION: &str = "CSRF check failed — state not bound to session";

/// Maximum allowed length (bytes) for a URL-decoded OAuth `state` parameter.
///
/// OAuth 2.0 (RFC 6749 §4.1.1) leaves the value opaque; a 1 KiB hard ceiling
/// prevents hash-DoS and stack-exhaustion via crafted oversized inputs.
const STATE_MAX_LEN: usize = 1024;

#[derive(Debug, Serialize)]
struct InvalidStateBody {
    error: &'static str,
    description: &'static str,
}

fn invalid_state_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(InvalidStateBody {
            error: "invalid_state",
            description: INVALID_STATE_DESCRIPTION,
        }),
    )
        .into_response()
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn cookie_value<'a>(cookie_header: &'a str, key: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name.trim() == key).then_some(value.trim())
    })
}

fn extract_session_id(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| {
            cookie_value(cookie, "session_id")
                .or_else(|| cookie_value(cookie, "authkit_session"))
                .or_else(|| cookie_value(cookie, "authvault_session"))
                .or_else(|| cookie_value(cookie, "sid"))
        })
}

/// Extract and URL-decode the `state` query parameter, rejecting values that
/// exceed [`STATE_MAX_LEN`] bytes after decoding.
fn extract_state_token(request: &Request) -> Option<String> {
    let raw = request
        .uri()
        .query()
        .and_then(|query| query_param(query, "state"))?;

    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())?;

    if decoded.len() > STATE_MAX_LEN {
        return None;
    }

    Some(decoded)
}

/// Middleware that rejects OAuth callbacks when `state` is not bound to the session cookie.
pub async fn enforce_pkce_state_session(
    State(store): State<Arc<dyn SessionStore>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(state_token) = extract_state_token(&request) else {
        return invalid_state_response();
    };
    let Some(session_id) = extract_session_id(&request) else {
        return invalid_state_response();
    };

    match store.verify_state(&state_token, session_id) {
        Ok(true) => next.run(request).await,
        Ok(false) | Err(_) => invalid_state_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::routing::get;
    use axum::Router;
    use chrono::Duration;
    use tower::ServiceExt;

    use super::*;
    use crate::domain::session_store::{InMemorySessionStore, SessionStore};

    fn router(store: Arc<dyn SessionStore>) -> Router {
        Router::new()
            .route("/oauth/callback", get(|| async { (StatusCode::OK, "ok") }))
            .route_layer(axum::middleware::from_fn_with_state(
                store,
                enforce_pkce_state_session,
            ))
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn valid_binding_allows_callback() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        store.bind_state("state-1", "session-1").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=state-1")
                    .header(header::COOKIE, "session_id=session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "ok");
    }

    #[tokio::test]
    async fn missing_state_is_rejected() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback")
                    .header(header::COOKIE, "session_id=session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_text(response).await;
        assert!(body.contains("invalid_state"));
        assert!(body.contains("CSRF check failed"));
    }

    #[tokio::test]
    async fn missing_cookie_is_rejected() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        store.bind_state("state-1", "session-1").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_session_binding_is_rejected() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        store.bind_state("state-1", "session-1").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=state-1")
                    .header(header::COOKIE, "session_id=session-2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_state_is_rejected() {
        let store: Arc<dyn SessionStore> =
            Arc::new(InMemorySessionStore::with_ttl(Duration::seconds(-1)));
        store.bind_state("state-1", "session-1").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=state-1")
                    .header(header::COOKIE, "session_id=session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --- new tests for security fixes ---

    #[tokio::test]
    async fn percent_encoded_state_matches_decoded_binding() {
        // state token stored as "hello world"; arrives percent-encoded as "hello%20world"
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        store.bind_state("hello world", "session-1").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=hello%20world")
                    .header(header::COOKIE, "session_id=session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_state_is_rejected() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        // Build a state value just over STATE_MAX_LEN bytes.
        let big_state: String = "x".repeat(STATE_MAX_LEN + 1);
        let store_clone = Arc::clone(&store);
        store_clone.bind_state(&big_state, "session-1").unwrap();
        let uri = format!("/oauth/callback?state={big_state}");
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri(uri.as_str())
                    .header(header::COOKIE, "session_id=session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Oversized input must be rejected regardless of store contents.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Constant-time path: verify that a mismatched session id of the same
    /// length as a valid one is still rejected (exercises the ct_eq branch).
    #[tokio::test]
    async fn constant_time_compare_rejects_same_length_mismatch() {
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        store.bind_state("state-ct", "aaaaaaaaaaaa").unwrap();
        let response = router(store)
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?state=state-ct")
                    .header(header::COOKIE, "session_id=bbbbbbbbbbbb")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
