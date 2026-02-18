use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::user::{CreateUserRequest, User};

/// Repository errors for database operations
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Resource not found")]
    NotFound,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
}

/// Trait defining user repository operations
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Create a new user
    async fn create(
        &self,
        user: CreateUserRequest,
        password_hash: String,
    ) -> Result<User, RepositoryError>;

    /// Find a user by email
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, RepositoryError>;

    /// Find a user by ID
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, RepositoryError>;
}

/// PostgreSQL implementation of UserRepository
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create(
        &self,
        user: CreateUserRequest,
        password_hash: String,
    ) -> Result<User, RepositoryError> {
        let default_currency = user.default_currency.unwrap_or_else(|| "USD".to_string());

        let result = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password_hash, default_currency)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, password_hash, default_currency, created_at
            "#,
            user.name,
            user.email,
            password_hash,
            default_currency
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(sqlx::Error::Database(db_err)) => {
                // Check for unique constraint violation (duplicate email)
                if db_err.is_unique_violation() {
                    Err(RepositoryError::ConstraintViolation(
                        "Email already exists".to_string(),
                    ))
                } else {
                    Err(RepositoryError::DatabaseError(db_err.to_string()))
                }
            }
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, RepositoryError> {
        let result: Result<Option<User>, sqlx::Error> = sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password_hash, default_currency, created_at
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, RepositoryError> {
        let result: Result<Option<User>, sqlx::Error> = sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password_hash, default_currency, created_at
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }
}
