//! Integration tests for the AuthKit public API.
//!
//! These tests exercise `SessionStore` trait, `InMemorySessionStore`, and the
//! `enforce_pkce_state_session` middleware through `authkit::*` — i.e. only
//! the public surface that downstream consumers see.

use std::sync::Arc;

use authkit::*;
use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use chrono::Duration;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn oauth_router(store: Arc<dyn SessionStore>) -> Router {
    Router::new()
        .route(
            "/oauth/callback",
            get(|| async { (StatusCode::OK, "callback_ok") }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            store,
            enforce_pkce_state_session,
        ))
}

fn make_request(uri: &str, cookie: &str) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if !cookie.is_empty() {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).unwrap()
}

async fn body_string(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

/// Full happy-path OAuth callback flow: bind a state token to a session,
/// send a callback request with matching `?state=` and `session_id` cookie,
/// and verify the middleware lets it through.
#[tokio::test]
async fn integration_valid_callback_passes_through() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

    // Simulate the initial auth redirect: server binds a state token to
    // the user's session cookie value before redirecting to the IdP.
    store.bind_state("abc-123-state", "user-session-42").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=abc-123-state",
            "session_id=user-session-42",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "callback_ok");
}

/// Middleware rejects an OAuth callback when the `state` query parameter
/// is not bound to the session cookie — simulates a CSRF attack where the
/// attacker omits or forges the state parameter.
#[tokio::test]
async fn integration_unbound_state_rejected() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    // No bind_state call — the state token was never created by this server.

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=forged-state",
            "session_id=user-session-42",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_string(response).await;
    assert!(
        body.contains("invalid_state"),
        "Body should contain error type: {body}"
    );
    assert!(
        body.contains("CSRF check failed"),
        "Body should contain CSRF description: {body}"
    );
}

/// Middleware rejects the callback when the state token is valid but bound
/// to a *different* session — simulates session fixation or cross-user
/// state reuse.
#[tokio::test]
async fn integration_wrong_session_rejected() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-abc", "session-A").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=state-abc",
            "session_id=session-B", // different session
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Middleware rejects when state query param is missing entirely.
#[tokio::test]
async fn integration_missing_state_rejected() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-abc", "session-1").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback", // no ?state=
            "session_id=session-1",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Middleware rejects when the session cookie is missing entirely.
#[tokio::test]
async fn integration_missing_cookie_rejected() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-abc", "session-1").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=state-abc",
            "", // no cookie header
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// SessionStore trait full lifecycle: bind, verify (positive + negative),
/// revoke, verify-after-revoke, plus TTL expiry and rebinding semantics.
/// Uses `SessionStore` as a trait object to confirm the trait is object-safe
/// and usable through dynamic dispatch.
#[tokio::test]
async fn integration_session_store_trait_lifecycle() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

    // Bind and verify
    store.bind_state("s1", "sess-1").unwrap();
    assert!(store.verify_state("s1", "sess-1").unwrap());
    assert!(!store.verify_state("s1", "sess-other").unwrap());
    assert!(!store.verify_state("unknown", "sess-1").unwrap());

    // Rebind overwrites
    store.bind_state("s1", "sess-2").unwrap();
    assert!(store.verify_state("s1", "sess-2").unwrap());
    assert!(!store.verify_state("s1", "sess-1").unwrap());

    // Revoke
    store.revoke_state("s1").unwrap();
    assert!(!store.verify_state("s1", "sess-2").unwrap());

    // Revoking a non-existent state is a no-op (no error)
    store.revoke_state("already-gone").unwrap();
}

/// Verify that entries with an expired TTL are automatically evicted when
/// the store is accessed.
#[tokio::test]
async fn integration_expired_entries_evicted() {
    let store: Arc<dyn SessionStore> =
        Arc::new(InMemorySessionStore::with_ttl(Duration::seconds(-1)));

    store.bind_state("expired-state", "sess-1").unwrap();

    // The entry was created with a TTL in the past — it should already be
    // expired and evicted on the next access.
    assert!(
        !store.verify_state("expired-state", "sess-1").unwrap(),
        "Expired entry should not verify"
    );
}

/// Middleware recognizes the `authkit_session` cookie name as an alias for
/// `session_id`, confirming backward compatibility.
#[tokio::test]
async fn integration_authkit_session_cookie_alias() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-x", "sess-x").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=state-x",
            "authkit_session=sess-x",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Middleware also recognizes the `authvault_session` cookie name (legacy
/// backward compatibility from the archived Authvault repo).
#[tokio::test]
async fn integration_authvault_session_cookie_alias() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-y", "sess-y").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=state-y",
            "authvault_session=sess-y",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Middleware recognizes the `sid` cookie name as another alias.
#[tokio::test]
async fn integration_sid_cookie_alias() {
    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    store.bind_state("state-z", "sess-z").unwrap();

    let response = oauth_router(store)
        .oneshot(make_request(
            "/oauth/callback?state=state-z",
            "sid=sess-z",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
