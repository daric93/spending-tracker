use async_trait::async_trait;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::models::auth::{AuthToken, LoginRequest};
use crate::models::user::{CreateUserRequest, User};
use crate::repositories::user_repository::{RepositoryError, UserRepository};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user_id
    exp: i64,    // expiration timestamp
}

/// Authentication service errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Email already exists")]
    DuplicateEmail,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Trait defining authentication service operations
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Register a new user
    async fn register(&self, request: CreateUserRequest) -> Result<User, AuthError>;

    /// Authenticate user and return JWT token
    async fn login(&self, request: LoginRequest) -> Result<AuthToken, AuthError>;

    /// Validate JWT token and return user_id
    async fn validate_token(&self, token: &str) -> Result<Uuid, AuthError>;
}

/// Implementation of AuthService
pub struct AuthServiceImpl {
    user_repository: Arc<dyn UserRepository>,
    jwt_secret: String,
}

impl AuthServiceImpl {
    pub fn new(user_repository: Arc<dyn UserRepository>, jwt_secret: String) -> Self {
        Self {
            user_repository,
            jwt_secret,
        }
    }

    /// Hash a password using bcrypt
    fn hash_password(password: &str) -> Result<String, AuthError> {
        hash(password, DEFAULT_COST)
            .map_err(|e| AuthError::DatabaseError(format!("Password hashing failed: {}", e)))
    }

    /// Verify a password against a hash
    fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
        verify(password, hash)
            .map_err(|e| AuthError::DatabaseError(format!("Password verification failed: {}", e)))
    }

    /// Generate a JWT token for a user
    fn generate_jwt(&self, user_id: Uuid) -> Result<AuthToken, AuthError> {
        let expiration = Utc::now() + Duration::hours(24);

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::DatabaseError(format!("Token generation failed: {}", e)))?;

        Ok(AuthToken {
            token,
            expires_at: expiration,
        })
    }

    /// Decode and validate a JWT token
    fn decode_jwt(&self, token: &str) -> Result<Uuid, AuthError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            if e.to_string().contains("ExpiredSignature") {
                AuthError::TokenExpired
            } else {
                AuthError::InvalidToken
            }
        })?;

        Uuid::parse_str(&token_data.claims.sub).map_err(|_| AuthError::InvalidToken)
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn register(&self, request: CreateUserRequest) -> Result<User, AuthError> {
        // Hash the password
        let password_hash = Self::hash_password(&request.password)?;

        // Create user in repository
        let user = self
            .user_repository
            .create(request, password_hash)
            .await
            .map_err(|e| match e {
                RepositoryError::ConstraintViolation(_) => AuthError::DuplicateEmail,
                RepositoryError::DatabaseError(msg) => AuthError::DatabaseError(msg),
                RepositoryError::NotFound => {
                    AuthError::DatabaseError("Unexpected error".to_string())
                }
            })?;

        Ok(user)
    }

    async fn login(&self, request: LoginRequest) -> Result<AuthToken, AuthError> {
        // Find user by email
        let user = self
            .user_repository
            .find_by_email(&request.email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        let is_valid = Self::verify_password(&request.password, &user.password_hash)?;
        if !is_valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate JWT token
        self.generate_jwt(user.id)
    }

    async fn validate_token(&self, token: &str) -> Result<Uuid, AuthError> {
        self.decode_jwt(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::user_repository::UserRepository;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

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
    async fn test_register_success() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        let request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        let result = service.register(request).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_register_duplicate_email() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        let request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };

        // First registration should succeed
        service.register(request.clone()).await.unwrap();

        // Second registration with same email should fail
        let result = service.register(request).await;
        assert!(matches!(result, Err(AuthError::DuplicateEmail)));
    }

    #[tokio::test]
    async fn test_login_success() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        // Register a user first
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        service.register(register_request).await.unwrap();

        // Now try to login
        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = service.login(login_request).await;
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        // Register a user first
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        service.register(register_request).await.unwrap();

        // Try to login with wrong password
        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = service.login(login_request).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_validate_token_success() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        // Register and login to get a token
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        let user = service.register(register_request).await.unwrap();

        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };
        let auth_token = service.login(login_request).await.unwrap();

        // Validate the token
        let result = service.validate_token(&auth_token.token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user.id);
    }

    #[tokio::test]
    async fn test_validate_token_invalid() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        let result = service.validate_token("invalid_token").await;
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    // Feature: spending-tracker-api, Property 3: Authentication Token Generation
    // For any registered user with valid credentials, authentication should return a valid JWT token
    // that can be used for subsequent requests.

    #[tokio::test]
    async fn test_token_generation_returns_valid_jwt() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo.clone(), "test_secret".to_string());

        // Register a user
        let register_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            default_currency: Some("USD".to_string()),
        };
        let user = service.register(register_request).await.unwrap();

        // Login to get token
        let login_request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };
        let auth_token = service.login(login_request).await.unwrap();

        // Verify token format (JWT has 3 parts: header.payload.signature)
        let parts: Vec<&str> = auth_token.token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        assert!(!parts[0].is_empty(), "Header should not be empty");
        assert!(!parts[1].is_empty(), "Payload should not be empty");
        assert!(!parts[2].is_empty(), "Signature should not be empty");

        // Verify token can be validated
        let validated_user_id = service.validate_token(&auth_token.token).await.unwrap();
        assert_eq!(validated_user_id, user.id, "Token should contain correct user_id");
    }

    #[tokio::test]
    async fn test_token_contains_correct_user_id() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo.clone(), "test_secret".to_string());

        // Register multiple users
        let user1 = service
            .register(CreateUserRequest {
                name: "User 1".to_string(),
                email: "user1@example.com".to_string(),
                password: "password123".to_string(),
                default_currency: Some("USD".to_string()),
            })
            .await
            .unwrap();

        let user2 = service
            .register(CreateUserRequest {
                name: "User 2".to_string(),
                email: "user2@example.com".to_string(),
                password: "password123".to_string(),
                default_currency: Some("USD".to_string()),
            })
            .await
            .unwrap();

        // Login as user1
        let token1 = service
            .login(LoginRequest {
                email: "user1@example.com".to_string(),
                password: "password123".to_string(),
            })
            .await
            .unwrap();

        // Login as user2
        let token2 = service
            .login(LoginRequest {
                email: "user2@example.com".to_string(),
                password: "password123".to_string(),
            })
            .await
            .unwrap();

        // Validate tokens return correct user IDs
        let validated_id1 = service.validate_token(&token1.token).await.unwrap();
        let validated_id2 = service.validate_token(&token2.token).await.unwrap();

        assert_eq!(validated_id1, user1.id);
        assert_eq!(validated_id2, user2.id);
        assert_ne!(validated_id1, validated_id2, "Different users should have different IDs");
    }

    #[tokio::test]
    async fn test_token_expiration_is_set() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo.clone(), "test_secret".to_string());

        // Register and login
        service
            .register(CreateUserRequest {
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                default_currency: Some("USD".to_string()),
            })
            .await
            .unwrap();

        let auth_token = service
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
            })
            .await
            .unwrap();

        // Verify expiration is in the future (24 hours from now)
        let now = Utc::now();
        assert!(
            auth_token.expires_at > now,
            "Token expiration should be in the future"
        );

        // Verify expiration is approximately 24 hours from now (with 1 minute tolerance)
        let expected_expiration = now + Duration::hours(24);
        let diff = (auth_token.expires_at - expected_expiration).num_seconds().abs();
        assert!(
            diff < 60,
            "Token should expire in approximately 24 hours (diff: {} seconds)",
            diff
        );
    }

    #[tokio::test]
    async fn test_token_with_different_secrets_are_invalid() {
        let repo = Arc::new(MockUserRepository::new());
        let service1 = AuthServiceImpl::new(repo.clone(), "secret1".to_string());
        let service2 = AuthServiceImpl::new(repo.clone(), "secret2".to_string());

        // Register and login with service1
        service1
            .register(CreateUserRequest {
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                default_currency: Some("USD".to_string()),
            })
            .await
            .unwrap();

        let auth_token = service1
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
            })
            .await
            .unwrap();

        // Try to validate token with service2 (different secret)
        let result = service2.validate_token(&auth_token.token).await;
        assert!(
            matches!(result, Err(AuthError::InvalidToken)),
            "Token signed with different secret should be invalid"
        );
    }

    #[tokio::test]
    async fn test_malformed_token_is_rejected() {
        let repo = Arc::new(MockUserRepository::new());
        let service = AuthServiceImpl::new(repo, "test_secret".to_string());

        // Test various malformed tokens
        let malformed_tokens = vec![
            "not.a.token",
            "invalid",
            "",
            "header.payload", // Missing signature
            "a.b.c.d",        // Too many parts
        ];

        for token in malformed_tokens {
            let result = service.validate_token(token).await;
            assert!(
                matches!(result, Err(AuthError::InvalidToken)),
                "Malformed token '{}' should be rejected",
                token
            );
        }
    }
}

