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
use spending_tracker::handlers::spending_handlers::create_entry_handler;
use spending_tracker::repositories::category_repository::PostgresCategoryRepository;
use spending_tracker::repositories::spending_repository::PostgresSpendingRepository;
use spending_tracker::repositories::user_repository::{PostgresUserRepository, UserRepository};
use spending_tracker::services::auth_service::{AuthService, AuthServiceImpl};
use spending_tracker::services::category_service::{CategoryService, CategoryServiceImpl};
use spending_tracker::services::spending_service::{SpendingService, SpendingServiceImpl};

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

#[tokio::test]
async fn test_create_spending_entry_success() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    // Create app with only spending service state
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .with_state(spending_service);

    let email = unique_email("spending_test");
    
    // Step 1: Register a user directly using the auth service (not via HTTP)
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Spending Test User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // Step 2: Create a spending entry with valid data
    let spending_body = json!({
        "amount": 42.50,
        "date": "2024-01-15",
        "categories": ["groceries"],  // Just the string, not {"Name": "groceries"}
        "is_recurring": false,
        "currency_code": "USD"
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
        .unwrap();

    // Manually insert the AuthenticatedUser extension to bypass middleware
    request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let response = app
        .oneshot(request)
        .await
        .unwrap();

    // Verify response
    assert_eq!(response.status(), StatusCode::CREATED);
    
    let body = parse_json_body(response.into_body()).await;
    assert!(body["id"].is_string());
    assert_eq!(body["amount"], "42.50");
    assert_eq!(body["date"], "2024-01-15");
    assert_eq!(body["currency_code"], "USD");
    assert_eq!(body["is_recurring"], false);
    assert!(body["category_ids"].is_array());
    assert_eq!(body["category_ids"].as_array().unwrap().len(), 1);
    assert!(body["created_at"].is_string());
    assert!(body["updated_at"].is_string());
}

#[tokio::test]
async fn test_create_spending_entry_negative_amount() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    // Create app with only spending service state
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .with_state(spending_service);

    let email = unique_email("negative_amount_test");
    
    // Step 1: Register a user directly using the auth service (not via HTTP)
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Negative Amount Test User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // Step 2: Attempt to create a spending entry with negative amount
    let spending_body = json!({
        "amount": -50.00,
        "date": "2024-01-15",
        "categories": ["groceries"],
        "is_recurring": false,
        "currency_code": "USD"
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
        .unwrap();

    // Manually insert the AuthenticatedUser extension to bypass middleware
    request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let response = app
        .oneshot(request)
        .await
        .unwrap();

    // Verify response - should return 400 Bad Request
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body = parse_json_body(response.into_body()).await;
    assert!(body["error"].is_string());
    assert!(body["message"].is_string());
    // The error message should indicate the amount validation issue
    let message = body["message"].as_str().unwrap().to_lowercase();
    assert!(message.contains("amount") || message.contains("positive") || message.contains("greater"));
}

#[tokio::test]
async fn test_create_spending_entry_with_new_custom_category() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository.clone(),
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service.clone(),
    ));

    // Create app with only spending service state
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .with_state(spending_service);

    let email = unique_email("custom_category_test");
    
    // Step 1: Register a user directly using the auth service (not via HTTP)
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Custom Category Test User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // Step 2: Create a spending entry with a new custom category name
    let custom_category_name = format!("my_custom_category_{}", TEST_COUNTER.fetch_add(1, Ordering::SeqCst));
    let spending_body = json!({
        "amount": 75.25,
        "date": "2024-01-20",
        "categories": [custom_category_name.clone()],
        "is_recurring": false,
        "currency_code": "USD"
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
        .unwrap();

    // Manually insert the AuthenticatedUser extension to bypass middleware
    request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let response = app
        .oneshot(request)
        .await
        .unwrap();

    // Verify response - should return 201 Created
    assert_eq!(response.status(), StatusCode::CREATED);
    
    let body = parse_json_body(response.into_body()).await;
    assert!(body["id"].is_string());
    assert_eq!(body["amount"], "75.25");
    assert_eq!(body["date"], "2024-01-20");
    assert_eq!(body["currency_code"], "USD");
    assert_eq!(body["is_recurring"], false);
    assert!(body["category_ids"].is_array());
    assert_eq!(body["category_ids"].as_array().unwrap().len(), 1);
    
    // Step 3: Verify the custom category was auto-created
    let categories = category_service.get_categories(user.id).await.unwrap();
    let custom_category = categories.iter().find(|c| c.name == custom_category_name);
    assert!(custom_category.is_some(), "Custom category should have been auto-created");
    
    let custom_category = custom_category.unwrap();
    assert_eq!(custom_category.name, custom_category_name);
    assert_eq!(custom_category.user_id, Some(user.id));
    
    // Verify the category ID in the spending entry matches the auto-created category
    let category_id_from_entry = body["category_ids"][0].as_str().unwrap();
    assert_eq!(category_id_from_entry, custom_category.id.to_string());
}

#[tokio::test]
async fn test_create_spending_entry_without_auth_token() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    // Create app with auth middleware applied to the spending route
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_service.clone(),
            spending_tracker::middleware::auth_middleware::auth_middleware,
        ))
        .with_state(spending_service);

    // Attempt to create a spending entry without providing an auth token
    let spending_body = json!({
        "amount": 100.00,
        "date": "2024-01-15",
        "categories": ["groceries"],
        "is_recurring": false,
        "currency_code": "USD"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
        .unwrap();

    let response = app
        .oneshot(request)
        .await
        .unwrap();

    // Verify response - should return 401 Unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    
    let body = parse_json_body(response.into_body()).await;
    assert!(body["error"].is_string());
    let error_message = body["error"].as_str().unwrap();
    assert!(error_message.contains("Missing authorization token") || error_message.contains("authorization"));
}

#[tokio::test]
async fn test_list_entries_user_isolation() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    // Import the list handler
    use spending_tracker::handlers::spending_handlers::list_entries_handler;

    // Create app with spending routes
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .route("/api/spending", axum::routing::get(list_entries_handler))
        .with_state(spending_service);

    // Step 1: Register two users
    let email1 = unique_email("user_isolation_1");
    let email2 = unique_email("user_isolation_2");
    
    let register_request1 = spending_tracker::models::user::CreateUserRequest {
        name: "User One".to_string(),
        email: email1.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let register_request2 = spending_tracker::models::user::CreateUserRequest {
        name: "User Two".to_string(),
        email: email2.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user1 = auth_service.register(register_request1).await.unwrap();
    let user2 = auth_service.register(register_request2).await.unwrap();

    // Step 2: Create spending entries for user1
    let spending_body1 = json!({
        "amount": 50.00,
        "date": "2024-01-15",
        "categories": ["groceries"],
        "is_recurring": false,
        "currency_code": "USD"
    });
    
    let mut request1 = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body1).unwrap()))
        .unwrap();
    
    request1.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user1.id,
        }
    );

    let response1 = app.clone()
        .oneshot(request1)
        .await
        .unwrap();
    
    assert_eq!(response1.status(), StatusCode::CREATED);

    // Step 3: Create spending entries for user2
    let spending_body2 = json!({
        "amount": 100.00,
        "date": "2024-01-20",
        "categories": ["restaurant"],
        "is_recurring": false,
        "currency_code": "USD"
    });
    
    let mut request2 = Request::builder()
        .method("POST")
        .uri("/api/spending")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&spending_body2).unwrap()))
        .unwrap();
    
    request2.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user2.id,
        }
    );

    let response2 = app.clone()
        .oneshot(request2)
        .await
        .unwrap();
    
    assert_eq!(response2.status(), StatusCode::CREATED);

    // Step 4: List entries for user1 - should only see user1's entries
    let mut list_request1 = Request::builder()
        .method("GET")
        .uri("/api/spending")
        .body(Body::empty())
        .unwrap();
    
    list_request1.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user1.id,
        }
    );

    let list_response1 = app.clone()
        .oneshot(list_request1)
        .await
        .unwrap();
    
    assert_eq!(list_response1.status(), StatusCode::OK);
    
    let body1 = parse_json_body(list_response1.into_body()).await;
    assert!(body1.is_array());
    let entries1 = body1.as_array().unwrap();
    assert_eq!(entries1.len(), 1, "User 1 should only see their own entry");
    assert_eq!(entries1[0]["amount"], "50.00");
    assert_eq!(entries1[0]["user_id"], user1.id.to_string());

    // Step 5: List entries for user2 - should only see user2's entries
    let mut list_request2 = Request::builder()
        .method("GET")
        .uri("/api/spending")
        .body(Body::empty())
        .unwrap();
    
    list_request2.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user2.id,
        }
    );

    let list_response2 = app
        .oneshot(list_request2)
        .await
        .unwrap();
    
    assert_eq!(list_response2.status(), StatusCode::OK);
    
    let body2 = parse_json_body(list_response2.into_body()).await;
    assert!(body2.is_array());
    let entries2 = body2.as_array().unwrap();
    assert_eq!(entries2.len(), 1, "User 2 should only see their own entry");
    assert_eq!(entries2[0]["amount"], "100.00");
    assert_eq!(entries2[0]["user_id"], user2.id.to_string());
}

#[tokio::test]
async fn test_list_entries_empty() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    use spending_tracker::handlers::spending_handlers::list_entries_handler;

    // Create app with spending routes
    let app = Router::new()
        .route("/api/spending", axum::routing::get(list_entries_handler))
        .with_state(spending_service);

    // Register a user
    let email = unique_email("empty_list");
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Empty List User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // List entries for user with no entries
    let mut list_request = Request::builder()
        .method("GET")
        .uri("/api/spending")
        .body(Body::empty())
        .unwrap();
    
    list_request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let list_response = app
        .oneshot(list_request)
        .await
        .unwrap();
    
    assert_eq!(list_response.status(), StatusCode::OK);
    
    let body = parse_json_body(list_response.into_body()).await;
    assert!(body.is_array());
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 0, "User with no entries should get empty array");
}

#[tokio::test]
async fn test_list_entries_multiple_entries() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    use spending_tracker::handlers::spending_handlers::list_entries_handler;

    // Create app with spending routes
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .route("/api/spending", axum::routing::get(list_entries_handler))
        .with_state(spending_service);

    // Register a user
    let email = unique_email("multiple_entries");
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Multiple Entries User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // Create multiple spending entries
    let entries_data = vec![
        (25.50, "2024-01-10", "groceries"),
        (150.00, "2024-01-15", "restaurant"),
        (75.25, "2024-01-20", "transportation"),
    ];

    for (amount, date, category) in entries_data {
        let spending_body = json!({
            "amount": amount,
            "date": date,
            "categories": [category],
            "is_recurring": false,
            "currency_code": "USD"
        });
        
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/spending")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
            .unwrap();
        
        request.extensions_mut().insert(
            spending_tracker::middleware::auth_middleware::AuthenticatedUser {
                user_id: user.id,
            }
        );

        let response = app.clone()
            .oneshot(request)
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // List all entries
    let mut list_request = Request::builder()
        .method("GET")
        .uri("/api/spending")
        .body(Body::empty())
        .unwrap();
    
    list_request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let list_response = app
        .oneshot(list_request)
        .await
        .unwrap();
    
    assert_eq!(list_response.status(), StatusCode::OK);
    
    let body = parse_json_body(list_response.into_body()).await;
    assert!(body.is_array());
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 3, "Should return all 3 entries");
    
    // Verify all entries have required fields
    for entry in entries {
        assert!(entry["id"].is_string());
        assert!(entry["user_id"].is_string());
        assert!(entry["amount"].is_string());
        assert!(entry["date"].is_string());
        assert!(entry["currency_code"].is_string());
        assert!(entry["is_recurring"].is_boolean());
        assert!(entry["category_ids"].is_array());
        assert!(entry["created_at"].is_string());
        assert!(entry["updated_at"].is_string());
    }
}

#[tokio::test]
async fn test_list_entries_descending_date_sort() {
    let ctx = TestContext::new().await;
    
    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(ctx.pool().clone()));
    let category_repository = Arc::new(PostgresCategoryRepository::new(ctx.pool().clone()));
    let spending_repository = Arc::new(PostgresSpendingRepository::new(ctx.pool().clone()));
    
    // Initialize services
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(
        user_repository.clone(),
        "test_secret".to_string(),
    ));
    let category_service: Arc<dyn CategoryService> = Arc::new(CategoryServiceImpl::new(
        category_repository,
    ));
    let spending_service: Arc<dyn SpendingService> = Arc::new(SpendingServiceImpl::new(
        spending_repository,
        category_service,
    ));

    use spending_tracker::handlers::spending_handlers::list_entries_handler;

    // Create app with spending routes
    let app = Router::new()
        .route("/api/spending", post(create_entry_handler))
        .route("/api/spending", axum::routing::get(list_entries_handler))
        .with_state(spending_service);

    // Register a user
    let email = unique_email("date_sort");
    let register_request = spending_tracker::models::user::CreateUserRequest {
        name: "Date Sort User".to_string(),
        email: email.clone(),
        password: "password123".to_string(),
        default_currency: Some("USD".to_string()),
    };
    
    let user = auth_service.register(register_request).await.unwrap();

    // Create entries with different dates (not in chronological order)
    let entries_data = vec![
        (50.00, "2024-01-15", "groceries"),
        (100.00, "2024-01-25", "restaurant"),
        (25.00, "2024-01-05", "transportation"),
        (75.00, "2024-01-20", "entertainment"),
    ];

    for (amount, date, category) in entries_data {
        let spending_body = json!({
            "amount": amount,
            "date": date,
            "categories": [category],
            "is_recurring": false,
            "currency_code": "USD"
        });
        
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/spending")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&spending_body).unwrap()))
            .unwrap();
        
        request.extensions_mut().insert(
            spending_tracker::middleware::auth_middleware::AuthenticatedUser {
                user_id: user.id,
            }
        );

        let response = app.clone()
            .oneshot(request)
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // List all entries
    let mut list_request = Request::builder()
        .method("GET")
        .uri("/api/spending")
        .body(Body::empty())
        .unwrap();
    
    list_request.extensions_mut().insert(
        spending_tracker::middleware::auth_middleware::AuthenticatedUser {
            user_id: user.id,
        }
    );

    let list_response = app
        .oneshot(list_request)
        .await
        .unwrap();
    
    assert_eq!(list_response.status(), StatusCode::OK);
    
    let body = parse_json_body(list_response.into_body()).await;
    assert!(body.is_array());
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 4);
    
    // Verify entries are sorted by date in descending order (most recent first)
    assert_eq!(entries[0]["date"], "2024-01-25", "First entry should be most recent");
    assert_eq!(entries[0]["amount"], "100.00");
    
    assert_eq!(entries[1]["date"], "2024-01-20");
    assert_eq!(entries[1]["amount"], "75.00");
    
    assert_eq!(entries[2]["date"], "2024-01-15");
    assert_eq!(entries[2]["amount"], "50.00");
    
    assert_eq!(entries[3]["date"], "2024-01-05", "Last entry should be oldest");
    assert_eq!(entries[3]["amount"], "25.00");
}
