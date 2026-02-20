use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::spending::{RecurrencePattern, SpendingEntry};

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

/// Trait defining spending repository operations
#[async_trait]
pub trait SpendingRepository: Send + Sync {
    /// Create a new spending entry
    async fn create(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError>;

    /// Update an existing spending entry
    async fn update(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError>;

    /// Find a spending entry by ID
    async fn find_by_id(&self, id: Uuid) -> Result<Option<SpendingEntry>, RepositoryError>;

    /// Find all spending entries for a user, sorted by date descending
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<SpendingEntry>, RepositoryError>;
}

/// PostgreSQL implementation of SpendingRepository
pub struct PostgresSpendingRepository {
    pool: PgPool,
}

impl PostgresSpendingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SpendingRepository for PostgresSpendingRepository {
    async fn create(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError> {
        // Start a transaction to handle both spending_entry and junction table inserts
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        // Convert recurrence pattern to string for database storage
        let recurrence_pattern_str = entry.recurrence_pattern.as_ref().map(|p| p.to_db_string());

        // Insert the spending entry
        let result = sqlx::query!(
            r#"
            INSERT INTO spending_entries (
                id, user_id, amount, date, is_recurring, 
                recurrence_pattern, currency_code, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, user_id, amount, date, is_recurring, 
                      recurrence_pattern, currency_code, created_at, updated_at
            "#,
            entry.id,
            entry.user_id,
            entry.amount,
            entry.date,
            entry.is_recurring,
            recurrence_pattern_str,
            entry.currency_code,
            entry.created_at,
            entry.updated_at
        )
        .fetch_one(&mut *tx)
        .await;

        let spending_entry = match result {
            Ok(row) => {
                // Parse recurrence pattern back from string
                let recurrence_pattern = row
                    .recurrence_pattern
                    .as_deref()
                    .and_then(RecurrencePattern::from_db_string);

                SpendingEntry {
                    id: row.id,
                    user_id: row.user_id,
                    amount: row.amount,
                    date: row.date,
                    is_recurring: row.is_recurring,
                    recurrence_pattern,
                    currency_code: row.currency_code,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    category_ids: entry.category_ids.clone(), // Will be populated after junction inserts
                }
            }
            Err(sqlx::Error::Database(db_err)) => {
                return Err(RepositoryError::DatabaseError(db_err.to_string()));
            }
            Err(e) => {
                return Err(RepositoryError::DatabaseError(e.to_string()));
            }
        };

        // Insert category associations into junction table
        for category_id in &entry.category_ids {
            let junction_result = sqlx::query!(
                r#"
                INSERT INTO spending_entry_categories (spending_entry_id, category_id)
                VALUES ($1, $2)
                "#,
                entry.id,
                category_id
            )
            .execute(&mut *tx)
            .await;

            if let Err(e) = junction_result {
                return Err(RepositoryError::DatabaseError(e.to_string()));
            }
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(spending_entry)
    }
    async fn update(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError> {
        // Start a transaction to handle both spending_entry update and junction table updates
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        // Convert recurrence pattern to string for database storage
        let recurrence_pattern_str = entry.recurrence_pattern.as_ref().map(|p| p.to_db_string());

        // Update the spending entry with updated_at set to NOW()
        let result = sqlx::query!(
            r#"
            UPDATE spending_entries
            SET amount = $2,
                date = $3,
                is_recurring = $4,
                recurrence_pattern = $5,
                currency_code = $6,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, user_id, amount, date, is_recurring,
                      recurrence_pattern, currency_code, created_at, updated_at
            "#,
            entry.id,
            entry.amount,
            entry.date,
            entry.is_recurring,
            recurrence_pattern_str,
            entry.currency_code
        )
        .fetch_optional(&mut *tx)
        .await;

        let spending_entry = match result {
            Ok(Some(row)) => {
                // Parse recurrence pattern back from string
                let recurrence_pattern = row
                    .recurrence_pattern
                    .as_deref()
                    .and_then(RecurrencePattern::from_db_string);

                SpendingEntry {
                    id: row.id,
                    user_id: row.user_id,
                    amount: row.amount,
                    date: row.date,
                    is_recurring: row.is_recurring,
                    recurrence_pattern,
                    currency_code: row.currency_code,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    category_ids: entry.category_ids.clone(),
                }
            }
            Ok(None) => {
                return Err(RepositoryError::NotFound);
            }
            Err(sqlx::Error::Database(db_err)) => {
                return Err(RepositoryError::DatabaseError(db_err.to_string()));
            }
            Err(e) => {
                return Err(RepositoryError::DatabaseError(e.to_string()));
            }
        };

        // Delete existing category associations
        let delete_result = sqlx::query!(
            r#"
            DELETE FROM spending_entry_categories
            WHERE spending_entry_id = $1
            "#,
            entry.id
        )
        .execute(&mut *tx)
        .await;

        if let Err(e) = delete_result {
            return Err(RepositoryError::DatabaseError(e.to_string()));
        }

        // Insert new category associations
        for category_id in &entry.category_ids {
            let junction_result = sqlx::query!(
                r#"
                INSERT INTO spending_entry_categories (spending_entry_id, category_id)
                VALUES ($1, $2)
                "#,
                entry.id,
                category_id
            )
            .execute(&mut *tx)
            .await;

            if let Err(e) = junction_result {
                return Err(RepositoryError::DatabaseError(e.to_string()));
            }
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(spending_entry)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<SpendingEntry>, RepositoryError> {
        // Fetch the spending entry
        let entry_result = sqlx::query!(
            r#"
            SELECT id, user_id, amount, date, is_recurring, 
                   recurrence_pattern, currency_code, created_at, updated_at
            FROM spending_entries
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await;

        let entry_row = match entry_result {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(None),
            Err(e) => return Err(RepositoryError::DatabaseError(e.to_string())),
        };

        // Fetch associated category IDs from junction table
        let category_ids_result = sqlx::query!(
            r#"
            SELECT category_id
            FROM spending_entry_categories
            WHERE spending_entry_id = $1
            "#,
            id
        )
        .fetch_all(&self.pool)
        .await;

        let category_ids = match category_ids_result {
            Ok(rows) => rows.into_iter().map(|row| row.category_id).collect(),
            Err(e) => return Err(RepositoryError::DatabaseError(e.to_string())),
        };

        // Parse recurrence pattern back from string
        let recurrence_pattern = entry_row
            .recurrence_pattern
            .as_deref()
            .and_then(RecurrencePattern::from_db_string);

        Ok(Some(SpendingEntry {
            id: entry_row.id,
            user_id: entry_row.user_id,
            amount: entry_row.amount,
            date: entry_row.date,
            is_recurring: entry_row.is_recurring,
            recurrence_pattern,
            currency_code: entry_row.currency_code,
            created_at: entry_row.created_at,
            updated_at: entry_row.updated_at,
            category_ids,
        }))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<SpendingEntry>, RepositoryError> {
        // Fetch all spending entries for the user, sorted by date descending
        let entries_result = sqlx::query!(
            r#"
            SELECT id, user_id, amount, date, is_recurring, 
                   recurrence_pattern, currency_code, created_at, updated_at
            FROM spending_entries
            WHERE user_id = $1
            ORDER BY date DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await;

        let entry_rows = match entries_result {
            Ok(rows) => rows,
            Err(e) => return Err(RepositoryError::DatabaseError(e.to_string())),
        };

        // For each entry, fetch associated category IDs
        let mut spending_entries = Vec::new();
        for entry_row in entry_rows {
            let category_ids_result = sqlx::query!(
                r#"
                SELECT category_id
                FROM spending_entry_categories
                WHERE spending_entry_id = $1
                "#,
                entry_row.id
            )
            .fetch_all(&self.pool)
            .await;

            let category_ids = match category_ids_result {
                Ok(rows) => rows.into_iter().map(|row| row.category_id).collect(),
                Err(e) => return Err(RepositoryError::DatabaseError(e.to_string())),
            };

            // Parse recurrence pattern back from string
            let recurrence_pattern = entry_row
                .recurrence_pattern
                .as_deref()
                .and_then(RecurrencePattern::from_db_string);

            spending_entries.push(SpendingEntry {
                id: entry_row.id,
                user_id: entry_row.user_id,
                amount: entry_row.amount,
                date: entry_row.date,
                is_recurring: entry_row.is_recurring,
                recurrence_pattern,
                currency_code: entry_row.currency_code,
                created_at: entry_row.created_at,
                updated_at: entry_row.updated_at,
                category_ids,
            });
        }

        Ok(spending_entries)
    }
}
