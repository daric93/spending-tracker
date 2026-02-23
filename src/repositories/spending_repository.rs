use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::filters::SpendingFilters;
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
/// Trait defining spending repository operations
#[async_trait]
pub trait SpendingRepository: Send + Sync {
    /// Create a new spending entry
    async fn create(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError>;

    /// Update an existing spending entry
    async fn update(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError>;

    /// Find a spending entry by ID
    async fn find_by_id(&self, id: Uuid) -> Result<Option<SpendingEntry>, RepositoryError>;

    /// Find all spending entries for a user with optional filters, sorted by date descending
    async fn find_by_user(
        &self,
        user_id: Uuid,
        filters: SpendingFilters,
    ) -> Result<Vec<SpendingEntry>, RepositoryError>;

    /// Delete a spending entry by ID
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;

    /// Calculate total spending for a user with optional filters
    async fn calculate_total(
        &self,
        user_id: Uuid,
        filters: SpendingFilters,
    ) -> Result<rust_decimal::Decimal, RepositoryError>;

    /// Group spending by category with optional date range filter
    async fn group_by_category(
        &self,
        user_id: Uuid,
        date_range: Option<crate::models::filters::DateRange>,
    ) -> Result<Vec<crate::models::filters::CategorySpending>, RepositoryError>;
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

    async fn find_by_user(
        &self,
        user_id: Uuid,
        filters: SpendingFilters,
    ) -> Result<Vec<SpendingEntry>, RepositoryError> {
        // Build dynamic SQL query based on provided filters
        let mut query = String::from(
            r#"
            SELECT id, user_id, amount, date, is_recurring, 
                   recurrence_pattern, currency_code, created_at, updated_at
            FROM spending_entries
            WHERE user_id = $1
            "#,
        );

        let mut param_count = 1;
        let mut conditions = Vec::new();

        // Add date filter (exact date match)
        if filters.date.is_some() {
            param_count += 1;
            conditions.push(format!("date = ${}", param_count));
        }

        // Add date_range filter (inclusive)
        if filters.date_range.is_some() {
            param_count += 1;
            let start_param = param_count;
            param_count += 1;
            let end_param = param_count;
            conditions.push(format!("date BETWEEN ${} AND ${}", start_param, end_param));
        }

        // Add category_id filter
        if filters.category_id.is_some() {
            param_count += 1;
            conditions.push(format!(
                "id IN (SELECT spending_entry_id FROM spending_entry_categories WHERE category_id = ${})",
                param_count
            ));
        }

        // Add is_recurring filter
        if filters.is_recurring.is_some() {
            param_count += 1;
            conditions.push(format!("is_recurring = ${}", param_count));
        }

        // Add currency_code filter
        if filters.currency_code.is_some() {
            param_count += 1;
            conditions.push(format!("currency_code = ${}", param_count));
        }

        // Append conditions to query
        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        // Add ORDER BY clause
        query.push_str(" ORDER BY date DESC");

        // Add pagination if provided
        if filters.page_size.is_some() {
            param_count += 1;
            query.push_str(&format!(" LIMIT ${}", param_count));

            if filters.page.is_some() {
                param_count += 1;
                query.push_str(&format!(" OFFSET ${}", param_count));
            }
        }

        // Build the query with parameters
        let mut sqlx_query = sqlx::query_as::<
            _,
            (
                uuid::Uuid,
                uuid::Uuid,
                rust_decimal::Decimal,
                chrono::NaiveDate,
                bool,
                Option<String>,
                String,
                chrono::DateTime<chrono::Utc>,
                chrono::DateTime<chrono::Utc>,
            ),
        >(&query)
        .bind(user_id);

        // Bind parameters in order
        if let Some(date) = filters.date {
            sqlx_query = sqlx_query.bind(date);
        }

        if let Some(date_range) = &filters.date_range {
            sqlx_query = sqlx_query.bind(date_range.start);
            sqlx_query = sqlx_query.bind(date_range.end);
        }

        if let Some(category_id) = filters.category_id {
            sqlx_query = sqlx_query.bind(category_id);
        }

        if let Some(is_recurring) = filters.is_recurring {
            sqlx_query = sqlx_query.bind(is_recurring);
        }

        if let Some(currency_code) = &filters.currency_code {
            sqlx_query = sqlx_query.bind(currency_code);
        }

        if let Some(page_size) = filters.page_size {
            sqlx_query = sqlx_query.bind(page_size as i64);

            if let Some(page) = filters.page {
                let offset = (page.saturating_sub(1)) * page_size;
                sqlx_query = sqlx_query.bind(offset as i64);
            }
        }

        // Execute query
        let entry_rows = sqlx_query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        // For each entry, fetch associated category IDs
        let mut spending_entries = Vec::new();
        for entry_row in entry_rows {
            let category_ids_result = sqlx::query!(
                r#"
                SELECT category_id
                FROM spending_entry_categories
                WHERE spending_entry_id = $1
                "#,
                entry_row.0
            )
            .fetch_all(&self.pool)
            .await;

            let category_ids = match category_ids_result {
                Ok(rows) => rows.into_iter().map(|row| row.category_id).collect(),
                Err(e) => return Err(RepositoryError::DatabaseError(e.to_string())),
            };

            // Parse recurrence pattern back from string
            let recurrence_pattern = entry_row
                .5
                .as_deref()
                .and_then(RecurrencePattern::from_db_string);

            spending_entries.push(SpendingEntry {
                id: entry_row.0,
                user_id: entry_row.1,
                amount: entry_row.2,
                date: entry_row.3,
                is_recurring: entry_row.4,
                recurrence_pattern,
                currency_code: entry_row.6,
                created_at: entry_row.7,
                updated_at: entry_row.8,
                category_ids,
            });
        }

        Ok(spending_entries)
    }

    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        // Delete the spending entry
        // The CASCADE constraint on spending_entry_categories will automatically
        // delete associated category relationships
        let result = sqlx::query!(
            r#"
            DELETE FROM spending_entries
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(query_result) => {
                if query_result.rows_affected() == 0 {
                    Err(RepositoryError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(RepositoryError::DatabaseError(e.to_string())),
        }
    }

    async fn calculate_total(
        &self,
        user_id: Uuid,
        filters: SpendingFilters,
    ) -> Result<rust_decimal::Decimal, RepositoryError> {
        // Build dynamic SQL query based on provided filters
        let mut query = String::from(
            r#"
            SELECT COALESCE(SUM(amount), 0) as total
            FROM spending_entries
            WHERE user_id = $1
            "#,
        );

        let mut param_count = 1;
        let mut conditions = Vec::new();

        // Add date filter (exact date match)
        if filters.date.is_some() {
            param_count += 1;
            conditions.push(format!("date = ${}", param_count));
        }

        // Add date_range filter (inclusive)
        if filters.date_range.is_some() {
            param_count += 1;
            let start_param = param_count;
            param_count += 1;
            let end_param = param_count;
            conditions.push(format!("date BETWEEN ${} AND ${}", start_param, end_param));
        }

        // Add category_id filter
        if filters.category_id.is_some() {
            param_count += 1;
            conditions.push(format!(
                "id IN (SELECT spending_entry_id FROM spending_entry_categories WHERE category_id = ${})",
                param_count
            ));
        }

        // Add is_recurring filter
        if filters.is_recurring.is_some() {
            param_count += 1;
            conditions.push(format!("is_recurring = ${}", param_count));
        }

        // Add currency_code filter
        if filters.currency_code.is_some() {
            param_count += 1;
            conditions.push(format!("currency_code = ${}", param_count));
        }

        // Append conditions to query
        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        // Build the query with parameters
        let mut sqlx_query = sqlx::query_scalar::<_, rust_decimal::Decimal>(&query).bind(user_id);

        // Bind parameters in order
        if let Some(date) = filters.date {
            sqlx_query = sqlx_query.bind(date);
        }

        if let Some(date_range) = &filters.date_range {
            sqlx_query = sqlx_query.bind(date_range.start);
            sqlx_query = sqlx_query.bind(date_range.end);
        }

        if let Some(category_id) = filters.category_id {
            sqlx_query = sqlx_query.bind(category_id);
        }

        if let Some(is_recurring) = filters.is_recurring {
            sqlx_query = sqlx_query.bind(is_recurring);
        }

        if let Some(currency_code) = &filters.currency_code {
            sqlx_query = sqlx_query.bind(currency_code);
        }

        // Execute query
        let total = sqlx_query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(total)
    }

    async fn group_by_category(
        &self,
        user_id: Uuid,
        date_range: Option<crate::models::filters::DateRange>,
    ) -> Result<Vec<crate::models::filters::CategorySpending>, RepositoryError> {
        // Build SQL query to group spending by category
        let mut query = String::from(
            r#"
            SELECT 
                c.id as category_id,
                c.name as category_name,
                SUM(se.amount) as total,
                se.currency_code
            FROM spending_entries se
            JOIN spending_entry_categories sec ON se.id = sec.spending_entry_id
            JOIN categories c ON sec.category_id = c.id
            WHERE se.user_id = $1
            "#,
        );

        let mut param_count = 1;

        // Add date_range filter if provided
        if date_range.is_some() {
            param_count += 1;
            let start_param = param_count;
            param_count += 1;
            let end_param = param_count;
            query.push_str(&format!(
                " AND se.date BETWEEN ${} AND ${}",
                start_param, end_param
            ));
        }

        // Group by category and currency, exclude zero spending, order by total descending
        query.push_str(
            r#"
            GROUP BY c.id, c.name, se.currency_code
            HAVING SUM(se.amount) > 0
            ORDER BY total DESC
            "#,
        );

        // Build the query with parameters
        let mut sqlx_query =
            sqlx::query_as::<_, (uuid::Uuid, String, rust_decimal::Decimal, String)>(&query)
                .bind(user_id);

        // Bind date range parameters if provided
        if let Some(range) = &date_range {
            sqlx_query = sqlx_query.bind(range.start);
            sqlx_query = sqlx_query.bind(range.end);
        }

        // Execute query
        let rows = sqlx_query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        // Map rows to CategorySpending structs
        let category_spending = rows
            .into_iter()
            .map(|(category_id, category_name, total, currency)| {
                crate::models::filters::CategorySpending {
                    category_id,
                    category_name,
                    total,
                    currency,
                }
            })
            .collect();

        Ok(category_spending)
    }
}
