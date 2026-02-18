use axum::{
    Router,
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use spending_tracker::handlers::auth_handlers::{ErrorResponse, login_handler, register_handler};
use spending_tracker::models::auth::{AuthToken, LoginRequest};
use spending_tracker::models::user::{CreateUserRequest, User};
use spending_tracker::repositories::user_repository::PostgresUserRepository;
use spending_tracker::services::auth_service::{AuthService, AuthServiceImpl};

/// OpenAPI documentation structure
#[derive(OpenApi)]
#[openapi(
    paths(
        spending_tracker::handlers::auth_handlers::register_handler,
        spending_tracker::handlers::auth_handlers::login_handler,
    ),
    components(
        schemas(User, CreateUserRequest, LoginRequest, AuthToken, ErrorResponse)
    ),
    tags(
        (name = "auth", description = "Authentication endpoints")
    ),
    info(
        title = "Spending Tracker API",
        version = "0.1.0",
        description = "REST API for tracking personal spending",
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Get configuration from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    println!("✓ Connected to database");

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("✓ Migrations completed");

    // Initialize repositories
    let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));

    // Initialize services
    let auth_service: Arc<dyn AuthService> =
        Arc::new(AuthServiceImpl::new(user_repository, jwt_secret));

    // Build router with routes
    let app = Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        // Authentication routes
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        // Add auth service to state
        .with_state(auth_service)
        // Merge Swagger UI
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        // Add CORS middleware
        .layer(CorsLayer::permissive());

    // Start server
    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("✓ Server running on http://{}", addr);
    println!("  - Health check: http://{}/health", addr);
    println!("  - Register: POST http://{}/api/auth/register", addr);
    println!("  - Login: POST http://{}/api/auth/login", addr);
    println!("  - API Docs: http://{}/api/docs", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
