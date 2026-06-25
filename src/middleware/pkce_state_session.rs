//! Tower middleware for binding OAuth PKCE state to a server session.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::domain::session_store::SessionStore;

const INVALID_STATE_DESCRIPTION: &str = "CSRF check failed — state not bound to session";

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

fn extract_state_token(request: &Request) -> Option<&str> {
    request
        .uri()
        .query()
        .and_then(|query| query_param(query, "state"))
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

    match store.verify_state(state_token, session_id) {
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
}
