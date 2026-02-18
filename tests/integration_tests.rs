use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

use spending_tracker::handlers::auth_handlers::{login_handler, register_handler};
use spending_tracker::repositories::user_repository::{PostgresUserRepository, UserRepository};
use spending_tracker::services::auth_service::{AuthService, AuthServiceImpl};

/// Global counter for generating unique test emails
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique email for each test to avoid conflicts
fn unique_email(prefix: &str) -> String {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}{}_{}@test.example.com", prefix, count, timestamp)
}

/// Test fixture that manages database lifecycle
struct TestContext {
    pool: sqlx::PgPool,
}

impl TestContext {
    /// Create a new test context with database connection
    async fn new() -> Self {
        dotenv::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/spending_tracker".to_string());

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to connect to database");

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        Self { pool }
    }

    /// Get the database pool
    fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

/// Helper function to create test app router
fn create_test_app(auth_service: Arc<dyn AuthService>) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .with_state(auth_service)
}

/// Helper function to parse JSON response body
async fn parse_json_body(body: Body) -> Value {
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("Failed to read response body");
    serde_json::from_slice(&bytes).expect("Failed to parse JSON")
}

#[tokio::test]
async fn test_health_check() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_register_success() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("register_success");
    let request_body = json!({
        "name": "Test User",
        "email": email,
        "password": "password123",
        "default_currency": "USD"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["name"], "Test User");
    assert_eq!(body["email"], email);
    assert_eq!(body["default_currency"], "USD");
    assert!(body["id"].is_string());
    assert!(body["created_at"].is_string());
    assert!(body.get("password_hash").is_none()); // Should not be serialized

    // Verify user exists in database
    let user = user_repository.find_by_email(&email).await.unwrap();
    assert!(user.is_some());
    let user = user.unwrap();
    assert_eq!(user.name, "Test User");
    assert_eq!(user.email, email);
}

#[tokio::test]
async fn test_register_validation_error_invalid_email() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let request_body = json!({
        "name": "Test User",
        "email": "invalid-email",
        "password": "password123",
        "default_currency": "USD"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["error"], "validation_error");
    assert!(body["message"].as_str().unwrap().contains("email"));
}

#[tokio::test]
async fn test_register_validation_error_short_password() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("short_password");
    let request_body = json!({
        "name": "Test User",
        "email": email,
        "password": "short",
        "default_currency": "USD"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["error"], "validation_error");
    assert!(body["message"].as_str().unwrap().contains("password"));
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("duplicate");
    let request_body = json!({
        "name": "Test User",
        "email": email,
        "password": "password123",
        "default_currency": "USD"
    });

    // First registration should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Second registration with same email should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["error"], "duplicate_email");
    assert_eq!(body["message"], "Email already exists");
}

#[tokio::test]
async fn test_login_success() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("login_success");
    // First register a user
    let register_body = json!({
        "name": "Test User",
        "email": email,
        "password": "password123",
        "default_currency": "USD"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&register_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Now try to login
    let login_body = json!({
        "email": email,
        "password": "password123"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = parse_json_body(response.into_body()).await;
    assert!(body["token"].is_string());
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_login_invalid_credentials_wrong_password() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("wrong_password");
    // First register a user
    let register_body = json!({
        "name": "Test User",
        "email": email,
        "password": "password123",
        "default_currency": "USD"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&register_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Try to login with wrong password
    let login_body = json!({
        "email": email,
        "password": "wrongpassword"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["error"], "invalid_credentials");
    assert_eq!(body["message"], "Invalid email or password");
}

#[tokio::test]
async fn test_login_invalid_credentials_nonexistent_user() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository,
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("nonexistent");
    // Try to login with non-existent user
    let login_body = json!({
        "email": email,
        "password": "password123"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = parse_json_body(response.into_body()).await;
    assert_eq!(body["error"], "invalid_credentials");
    assert_eq!(body["message"], "Invalid email or password");
}

#[tokio::test]
async fn test_register_and_login_flow() {
    let ctx = TestContext::new().await;
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));

    let app = create_test_app(auth_service);

    let email = unique_email("integration_flow");
    // Step 1: Register a new user
    let register_body = json!({
        "name": "Integration Test User",
        "email": email,
        "password": "securepassword123",
        "default_currency": "EUR"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&register_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let register_response = parse_json_body(response.into_body()).await;
    let user_id = register_response["id"].as_str().unwrap();

    // Step 2: Verify user exists in database
    let db_user = user_repository
        .find_by_email(&email)
        .await
        .unwrap()
        .expect("User should exist in database");

    assert_eq!(db_user.id.to_string(), user_id);
    assert_eq!(db_user.name, "Integration Test User");
    assert_eq!(db_user.email, email);
    assert_eq!(db_user.default_currency, "EUR");
    assert!(!db_user.password_hash.is_empty());

    // Step 3: Login with the registered user
    let login_body = json!({
        "email": email,
        "password": "securepassword123"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let login_response = parse_json_body(response.into_body()).await;

    // Step 4: Verify token is valid
    let token = login_response["token"].as_str().unwrap();
    assert!(!token.is_empty());
    assert!(token.contains('.')); // JWT tokens have dots
}
