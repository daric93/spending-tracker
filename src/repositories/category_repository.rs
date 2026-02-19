use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::category::{Category, CategoryType};

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

/// Trait defining category repository operations
#[async_trait]
pub trait CategoryRepository: Send + Sync {
    /// Create a new category
    async fn create(&self, category: Category) -> Result<Category, RepositoryError>;

    /// Find a category by ID
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Category>, RepositoryError>;

    /// Find a category by name for a specific user (or predefined if user_id is None)
    async fn find_by_name(
        &self,
        user_id: Option<Uuid>,
        name: &str,
    ) -> Result<Option<Category>, RepositoryError>;

    /// Find all categories available to a user (predefined + user's custom categories)
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Category>, RepositoryError>;
}

/// PostgreSQL implementation of CategoryRepository
pub struct PostgresCategoryRepository {
    pool: PgPool,
}

impl PostgresCategoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CategoryRepository for PostgresCategoryRepository {
    async fn create(&self, category: Category) -> Result<Category, RepositoryError> {
        let category_type_str = match category.category_type {
            CategoryType::Predefined => "predefined",
            CategoryType::Custom => "custom",
        };

        let result = sqlx::query_as!(
            Category,
            r#"
            INSERT INTO categories (id, name, category_type, user_id)
            VALUES ($1, $2, $3, $4)
            RETURNING 
                id, 
                name, 
                category_type as "category_type: CategoryType", 
                user_id, 
                created_at
            "#,
            category.id,
            category.name,
            category_type_str,
            category.user_id
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(category) => Ok(category),
            Err(sqlx::Error::Database(db_err)) => {
                if db_err.is_unique_violation() {
                    Err(RepositoryError::ConstraintViolation(
                        "Category with this name already exists for user".to_string(),
                    ))
                } else {
                    Err(RepositoryError::DatabaseError(db_err.to_string()))
                }
            }
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Category>, RepositoryError> {
        let result = sqlx::query_as!(
            Category,
            r#"
            SELECT 
                id, 
                name, 
                category_type as "category_type: CategoryType", 
                user_id, 
                created_at
            FROM categories
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(category) => Ok(category),
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn find_by_name(
        &self,
        user_id: Option<Uuid>,
        name: &str,
    ) -> Result<Option<Category>, RepositoryError> {
        let result = sqlx::query_as!(
            Category,
            r#"
            SELECT 
                id, 
                name, 
                category_type as "category_type: CategoryType", 
                user_id, 
                created_at
            FROM categories
            WHERE name = $1 
                AND (user_id = $2 OR (user_id IS NULL AND $2 IS NULL))
            "#,
            name,
            user_id
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(category) => Ok(category),
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Category>, RepositoryError> {
        let result = sqlx::query_as!(
            Category,
            r#"
            SELECT 
                id, 
                name, 
                category_type as "category_type: CategoryType", 
                user_id, 
                created_at
            FROM categories
            WHERE user_id IS NULL OR user_id = $1
            ORDER BY name ASC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await;

        match result {
            Ok(categories) => Ok(categories),
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }
}
