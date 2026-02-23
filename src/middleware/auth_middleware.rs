use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::services::auth_service::AuthService;

/// Extension type to store authenticated user ID in request
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

/// Auth middleware that validates JWT tokens and adds user_id to request extensions
pub async fn auth_middleware(
    State(auth_service): State<Arc<dyn AuthService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    // Parse Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidTokenFormat)?;

    // Validate token and extract user_id
    let user_id = auth_service
        .validate_token(token)
        .await
        .map_err(|e| match e {
            crate::services::auth_service::AuthError::InvalidToken => AuthError::InvalidToken,
            crate::services::auth_service::AuthError::TokenExpired => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        })?;

    // Add user_id to request extensions
    request
        .extensions_mut()
        .insert(AuthenticatedUser { user_id });

    // Continue to next handler
    Ok(next.run(request).await)
}

/// Auth middleware errors
#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidTokenFormat,
    InvalidToken,
    TokenExpired,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization token"),
            AuthError::InvalidTokenFormat => (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization header format. Expected: Bearer <token>",
            ),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or malformed token"),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token has expired"),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::{AuthToken, LoginRequest};
    use crate::models::user::{CreateUserRequest, User};
    use crate::repositories::user_repository::{RepositoryError, UserRepository};
    use crate::services::auth_service::{AuthService, AuthServiceImpl};
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    // Mock repository for testing
    struct MockUserRepository {
        users: Mutex<HashMap<String, User>>,
    }

    impl MockUserRepository {
        fn new() -> Self {
            Self {
                users: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn create(
            &self,
            user: CreateUserRequest,
            password_hash: String,
        ) -> Result<User, RepositoryError> {
            let mut users = self.users.lock().unwrap();

            if users.contains_key(&user.email) {
                return Err(RepositoryError::ConstraintViolation(
                    "Email already exists".to_string(),
                ));
            }

            let new_user = User {
                id: Uuid::new_v4(),
                name: user.name,
                email: user.email.clone(),
                password_hash,
                default_currency: user.default_currency.unwrap_or_else(|| "USD".to_string()),
                created_at: Utc::now(),
            };

            users.insert(new_user.email.clone(), new_user.clone());
            Ok(new_user)
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, RepositoryError> {
            let users = self.users.lock().unwrap();
            Ok(users.get(email).cloned())
        }

        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, RepositoryError> {
            let users = self.users.lock().unwrap();
            Ok(users.values().find(|u| u.id == id).cloned())
        }
    }

    // Test handler that requires authentication
    async fn protected_handler(
        axum::Extension(user): axum::Extension<AuthenticatedUser>,
    ) -> impl IntoResponse {
        Json(json!({
            "user_id": user.user_id.to_string(),
            "message": "Access granted"
        }))
    }

    fn create_test_app(auth_service: Arc<dyn AuthService>) -> Router {
        Router::new()
            .route("/protected", get(protected_handler))
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            ))
            .with_state(auth_service)
    }

    async fn create_test_user_and_token(auth_service: &Arc<dyn AuthService>) -> (User, AuthToken) {
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        let user = auth_service.register(register_request).await.unwrap();

        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let token = auth_service.login(login_request).await.unwrap();

        (user, token)
    }

    #[tokio::test]
    async fn test_middleware_with_valid_token() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let (user, token) = create_test_user_and_token(&auth_service).await;

        let app = create_test_app(auth_service);

        let request = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {}", token.token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body_json["user_id"], user.id.to_string());
        assert_eq!(body_json["message"], "Access granted");
    }

    #[tokio::test]
    async fn test_middleware_without_token() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let app = create_test_app(auth_service);

        let request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            body_json["error"]
                .as_str()
                .unwrap()
                .contains("Missing authorization token")
        );
    }

    #[tokio::test]
    async fn test_middleware_with_invalid_token() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let app = create_test_app(auth_service);

        let request = Request::builder()
            .uri("/protected")
            .header("Authorization", "Bearer invalid_token_here")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            body_json["error"]
                .as_str()
                .unwrap()
                .contains("Invalid or malformed token")
        );
    }

    #[tokio::test]
    async fn test_middleware_with_malformed_header() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let app = create_test_app(auth_service);

        // Test without "Bearer " prefix
        let request = Request::builder()
            .uri("/protected")
            .header("Authorization", "some_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            body_json["error"]
                .as_str()
                .unwrap()
                .contains("Invalid authorization header format")
        );
    }
}
