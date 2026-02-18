use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

use crate::models::auth::{AuthToken, LoginRequest};
use crate::models::user::{CreateUserRequest, User};
use crate::services::auth_service::{AuthError, AuthService};

/// Error response structure
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl ErrorResponse {
    fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }
}

/// Convert AuthError to HTTP response
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            AuthError::DuplicateEmail => (
                StatusCode::CONFLICT,
                "duplicate_email",
                "Email already exists",
            ),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid email or password",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid authentication token",
            ),
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "token_expired",
                "Authentication token has expired",
            ),
            AuthError::DatabaseError(ref msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                msg.as_str(),
            ),
        };

        let error_response = ErrorResponse::new(error_type, message);
        (status, Json(error_response)).into_response()
    }
}

/// Handler for user registration
///
/// Creates a new user account with the provided credentials.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User successfully registered", body = User),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 409, description = "Email already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn register_handler(
    State(auth_service): State<Arc<dyn AuthService>>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<User>), Response> {
    // Validate request body
    if let Err(validation_errors) = request.validate() {
        let error_message = validation_errors
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let messages: Vec<String> = errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(|m| m.to_string()))
                    .collect();
                format!("{}: {}", field, messages.join(", "))
            })
            .collect::<Vec<_>>()
            .join("; ");

        let error_response = ErrorResponse::new("validation_error", &error_message);
        return Err((StatusCode::BAD_REQUEST, Json(error_response)).into_response());
    }

    // Call auth service to register user
    match auth_service.register(request).await {
        Ok(user) => Ok((StatusCode::CREATED, Json(user))),
        Err(e) => Err(e.into_response()),
    }
}

/// Handler for user login
///
/// Authenticates a user and returns a JWT token.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthToken),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn login_handler(
    State(auth_service): State<Arc<dyn AuthService>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthToken>, Response> {
    // Call auth service to login user
    match auth_service.login(request).await {
        Ok(token) => Ok(Json(token)),
        Err(e) => Err(e.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::CreateUserRequest;
    use crate::repositories::user_repository::{RepositoryError, UserRepository};
    use crate::services::auth_service::AuthServiceImpl;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

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

    #[tokio::test]
    async fn test_register_handler_success() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        let result = register_handler(State(auth_service), Json(request)).await;
        assert!(result.is_ok());

        let (status, Json(user)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_register_handler_validation_error() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        // Invalid email format
        let request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "invalid-email".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        let result = register_handler(State(auth_service), Json(request)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_handler_duplicate_email() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        let request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        // First registration should succeed
        let _ = register_handler(State(auth_service.clone()), Json(request.clone())).await;

        // Second registration with same email should fail
        let result = register_handler(State(auth_service), Json(request)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_handler_success() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        // Register a user first
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        let _ = register_handler(State(auth_service.clone()), Json(register_request)).await;

        // Now try to login
        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = login_handler(State(auth_service), Json(login_request)).await;
        assert!(result.is_ok());

        let Json(token) = result.unwrap();
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_login_handler_invalid_credentials() {
        let repo = Arc::new(MockUserRepository::new());
        let auth_service: Arc<dyn AuthService> =
            Arc::new(AuthServiceImpl::new(repo, "test_secret".to_string()));

        // Register a user first
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        let _ = register_handler(State(auth_service.clone()), Json(register_request)).await;

        // Try to login with wrong password
        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = login_handler(State(auth_service), Json(login_request)).await;
        assert!(result.is_err());
    }
}
