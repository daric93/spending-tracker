use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::models::spending::{CreateSpendingRequest, SpendingEntry, UpdateSpendingRequest};
use crate::repositories::spending_repository::{RepositoryError, SpendingRepository};
use crate::services::category_service::{CategoryError, CategoryService};

/// Spending service errors
#[derive(Debug, thiserror::Error)]
pub enum SpendingError {
    #[error("Invalid amount: amount must be positive")]
    InvalidAmount,

    #[error("Invalid date format")]
    InvalidDate,

    #[error("Category not found")]
    CategoryNotFound,

    #[error("Spending entry not found")]
    EntryNotFound,

    #[error("Unauthorized to access this entry")]
    Unauthorized,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Trait defining spending service operations
#[async_trait]
pub trait SpendingService: Send + Sync {
    /// Create a new spending entry
    async fn create_entry(
        &self,
        user_id: Uuid,
        request: CreateSpendingRequest,
    ) -> Result<SpendingEntry, SpendingError>;

    /// Get all spending entries for a user, sorted by date descending
    async fn get_entries(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SpendingEntry>, SpendingError>;

    /// Update an existing spending entry
    async fn update_entry(
        &self,
        user_id: Uuid,
        entry_id: Uuid,
        request: UpdateSpendingRequest,
    ) -> Result<SpendingEntry, SpendingError>;

    /// Delete a spending entry
    async fn delete_entry(
        &self,
        user_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), SpendingError>;
}

/// Implementation of SpendingService
pub struct SpendingServiceImpl {
    spending_repository: Arc<dyn SpendingRepository>,
    category_service: Arc<dyn CategoryService>,
}

impl SpendingServiceImpl {
    pub fn new(
        spending_repository: Arc<dyn SpendingRepository>,
        category_service: Arc<dyn CategoryService>,
    ) -> Self {
        Self {
            spending_repository,
            category_service,
        }
    }
}

#[async_trait]
impl SpendingService for SpendingServiceImpl {
    async fn create_entry(
        &self,
        user_id: Uuid,
        request: CreateSpendingRequest,
    ) -> Result<SpendingEntry, SpendingError> {
        // Validate amount is positive
        if request.amount <= rust_decimal::Decimal::ZERO {
            return Err(SpendingError::InvalidAmount);
        }

        // Resolve categories (by ID or name using get_or_create_by_name)
        let mut category_ids = Vec::new();
        for category_identifier in &request.categories {
            let category = match category_identifier {
                crate::models::spending::CategoryIdentifier::Id(id) => {
                    // For ID-based lookup, we need to verify the category exists
                    // This would require a find_by_id method on CategoryService
                    // For now, we'll just use the ID directly
                    *id
                }
                crate::models::spending::CategoryIdentifier::Name(name) => {
                    // Auto-create category if it doesn't exist
                    let category = self
                        .category_service
                        .get_or_create_by_name(user_id, name)
                        .await
                        .map_err(|e| match e {
                            CategoryError::CategoryNotFound => SpendingError::CategoryNotFound,
                            CategoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                            _ => SpendingError::DatabaseError(e.to_string()),
                        })?;
                    category.id
                }
            };
            category_ids.push(category);
        }

        // Set default currency if not provided (default to USD)
        let currency_code = request.currency_code.unwrap_or_else(|| "USD".to_string());

        // Create spending entry
        let entry = SpendingEntry {
            id: Uuid::new_v4(),
            user_id,
            amount: request.amount,
            date: request.date,
            category_ids,
            is_recurring: request.is_recurring.unwrap_or(false),
            recurrence_pattern: request.recurrence_pattern,
            currency_code,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Call repository to persist the entry
        self.spending_repository
            .create(entry)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })
    }

    async fn get_entries(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SpendingEntry>, SpendingError> {
        // Call repository to fetch all entries for the user
        // Repository already returns entries sorted by date descending
        self.spending_repository
            .find_by_user(user_id)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })
    }

    async fn update_entry(
        &self,
        user_id: Uuid,
        entry_id: Uuid,
        request: UpdateSpendingRequest,
    ) -> Result<SpendingEntry, SpendingError> {
        // Find existing entry
        let existing_entry = self
            .spending_repository
            .find_by_id(entry_id)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })?
            .ok_or(SpendingError::EntryNotFound)?;

        // Verify user owns the entry
        if existing_entry.user_id != user_id {
            return Err(SpendingError::Unauthorized);
        }

        // Validate amount if provided
        if let Some(amount) = request.amount {
            if amount <= rust_decimal::Decimal::ZERO {
                return Err(SpendingError::InvalidAmount);
            }
        }

        // Resolve categories if provided
        let category_ids = if let Some(categories) = request.categories {
            let mut resolved_ids = Vec::new();
            for category_identifier in &categories {
                let category_id = match category_identifier {
                    crate::models::spending::CategoryIdentifier::Id(id) => {
                        // For ID-based lookup, use the ID directly
                        *id
                    }
                    crate::models::spending::CategoryIdentifier::Name(name) => {
                        // Auto-create category if it doesn't exist
                        let category = self
                            .category_service
                            .get_or_create_by_name(user_id, name)
                            .await
                            .map_err(|e| match e {
                                CategoryError::CategoryNotFound => SpendingError::CategoryNotFound,
                                CategoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                                _ => SpendingError::DatabaseError(e.to_string()),
                            })?;
                        category.id
                    }
                };
                resolved_ids.push(category_id);
            }
            resolved_ids
        } else {
            existing_entry.category_ids.clone()
        };

        // Build updated entry
        let updated_entry = SpendingEntry {
            id: entry_id,
            user_id,
            amount: request.amount.unwrap_or(existing_entry.amount),
            date: request.date.unwrap_or(existing_entry.date),
            category_ids,
            is_recurring: request.is_recurring.unwrap_or(existing_entry.is_recurring),
            recurrence_pattern: request.recurrence_pattern.or(existing_entry.recurrence_pattern),
            currency_code: request.currency_code.unwrap_or(existing_entry.currency_code),
            created_at: existing_entry.created_at,
            updated_at: chrono::Utc::now(),
        };

        // Call repository to persist the update
        self.spending_repository
            .update(updated_entry)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })
    }

    async fn delete_entry(
        &self,
        user_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), SpendingError> {
        // Find existing entry
        let existing_entry = self
            .spending_repository
            .find_by_id(entry_id)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })?
            .ok_or(SpendingError::EntryNotFound)?;

        // Verify user owns the entry
        if existing_entry.user_id != user_id {
            return Err(SpendingError::Unauthorized);
        }

        // Call repository to delete the entry
        self.spending_repository
            .delete(entry_id)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => SpendingError::EntryNotFound,
                RepositoryError::DatabaseError(msg) => SpendingError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => SpendingError::DatabaseError(msg),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::category::{Category, CategoryType};
    use crate::models::spending::{CategoryIdentifier, RecurrencePattern};
    use async_trait::async_trait;
    use chrono::{NaiveDate, Utc};
    use rust_decimal::Decimal;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Mutex;

    // Mock SpendingRepository for testing
    struct MockSpendingRepository {
        entries: Mutex<HashMap<Uuid, SpendingEntry>>,
        should_fail: bool,
    }

    impl MockSpendingRepository {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl SpendingRepository for MockSpendingRepository {
        async fn create(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError(
                    "Database connection failed".to_string(),
                ));
            }

            let mut entries = self.entries.lock().unwrap();
            entries.insert(entry.id, entry.clone());
            Ok(entry)
        }

        async fn update(&self, entry: SpendingEntry) -> Result<SpendingEntry, RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError(
                    "Database connection failed".to_string(),
                ));
            }

            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(&entry.id) {
                entries.insert(entry.id, entry.clone());
                Ok(entry)
            } else {
                Err(RepositoryError::NotFound)
            }
        }

        async fn find_by_id(&self, id: Uuid) -> Result<Option<SpendingEntry>, RepositoryError> {
            let entries = self.entries.lock().unwrap();
            Ok(entries.get(&id).cloned())
        }

        async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<SpendingEntry>, RepositoryError> {
            let entries = self.entries.lock().unwrap();
            let mut user_entries: Vec<SpendingEntry> = entries
                .values()
                .filter(|e| e.user_id == user_id)
                .cloned()
                .collect();
            
            // Sort by date descending (most recent first)
            user_entries.sort_by(|a, b| b.date.cmp(&a.date));
            
            Ok(user_entries)
        }

        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError(
                    "Database connection failed".to_string(),
                ));
            }

            let mut entries = self.entries.lock().unwrap();
            if entries.remove(&id).is_some() {
                Ok(())
            } else {
                Err(RepositoryError::NotFound)
            }
        }
    }

    // Mock CategoryService for testing
    struct MockCategoryService {
        categories: Mutex<HashMap<String, Category>>,
        should_fail: bool,
    }

    impl MockCategoryService {
        fn new() -> Self {
            let mut categories = HashMap::new();

            // Add predefined categories
            let groceries_id = Uuid::new_v4();
            categories.insert(
                "groceries".to_string(),
                Category {
                    id: groceries_id,
                    name: "groceries".to_string(),
                    category_type: CategoryType::Predefined,
                    user_id: None,
                    created_at: Utc::now(),
                },
            );

            Self {
                categories: Mutex::new(categories),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                categories: Mutex::new(HashMap::new()),
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl CategoryService for MockCategoryService {
        async fn get_categories(&self, _user_id: Uuid) -> Result<Vec<Category>, CategoryError> {
            let categories = self.categories.lock().unwrap();
            Ok(categories.values().cloned().collect())
        }

        async fn get_or_create_by_name(
            &self,
            user_id: Uuid,
            name: &str,
        ) -> Result<Category, CategoryError> {
            if self.should_fail {
                return Err(CategoryError::DatabaseError(
                    "Database error".to_string(),
                ));
            }

            let mut categories = self.categories.lock().unwrap();

            if let Some(category) = categories.get(name) {
                return Ok(category.clone());
            }

            // Create new custom category
            let new_category = Category {
                id: Uuid::new_v4(),
                name: name.to_string(),
                category_type: CategoryType::Custom,
                user_id: Some(user_id),
                created_at: Utc::now(),
            };
            categories.insert(name.to_string(), new_category.clone());
            Ok(new_category)
        }
    }

    #[tokio::test]
    async fn test_create_entry_success() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.amount, Decimal::from_str("42.50").unwrap());
        assert_eq!(entry.user_id, user_id);
        assert_eq!(entry.currency_code, "USD");
        assert_eq!(entry.is_recurring, false);
        assert_eq!(entry.category_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_create_entry_negative_amount() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("-10.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_create_entry_zero_amount() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::ZERO,
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_create_entry_auto_creates_custom_category() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("25.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("custom_category".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.category_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_create_entry_with_category_id() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let category_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("30.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Id(category_id)],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.category_ids.len(), 1);
        assert_eq!(entry.category_ids[0], category_id);
    }

    #[tokio::test]
    async fn test_create_entry_multiple_categories() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![
                CategoryIdentifier::Name("groceries".to_string()),
                CategoryIdentifier::Name("household".to_string()),
            ],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.category_ids.len(), 2);
    }

    #[tokio::test]
    async fn test_create_entry_default_currency() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: None, // No currency specified
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.currency_code, "USD"); // Should default to USD
    }

    #[tokio::test]
    async fn test_create_entry_with_recurring_pattern() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(true),
            recurrence_pattern: Some(RecurrencePattern::Monthly),
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.is_recurring, true);
        assert!(entry.recurrence_pattern.is_some());
        assert_eq!(entry.recurrence_pattern.unwrap(), RecurrencePattern::Monthly);
    }

    #[tokio::test]
    async fn test_create_entry_repository_error() {
        let repo = Arc::new(MockSpendingRepository::with_failure());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpendingError::DatabaseError(_)
        ));
    }

    #[tokio::test]
    async fn test_create_entry_category_service_error() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::with_failure());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("new_category".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = service.create_entry(user_id, request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpendingError::DatabaseError(_)
        ));
    }

    #[tokio::test]
    async fn test_get_entries_success() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user_id = Uuid::new_v4();

        // Create multiple entries
        let request1 = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let request2 = CreateSpendingRequest {
            amount: Decimal::from_str("100.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
            categories: vec![CategoryIdentifier::Name("restaurant".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        service.create_entry(user_id, request1).await.unwrap();
        service.create_entry(user_id, request2).await.unwrap();

        // Get all entries
        let result = service.get_entries(user_id).await;
        assert!(result.is_ok());

        let entries = result.unwrap();
        assert_eq!(entries.len(), 2);
        
        // Verify entries are sorted by date descending (most recent first)
        assert_eq!(entries[0].date, NaiveDate::from_ymd_opt(2024, 1, 20).unwrap());
        assert_eq!(entries[1].date, NaiveDate::from_ymd_opt(2024, 1, 15).unwrap());
    }

    #[tokio::test]
    async fn test_get_entries_empty() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user_id = Uuid::new_v4();

        // Get entries for user with no entries
        let result = service.get_entries(user_id).await;
        assert!(result.is_ok());

        let entries = result.unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn test_get_entries_user_isolation() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo, category_service);

        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        // Create entry for user1
        let request1 = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        // Create entry for user2
        let request2 = CreateSpendingRequest {
            amount: Decimal::from_str("100.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
            categories: vec![CategoryIdentifier::Name("restaurant".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        service.create_entry(user1_id, request1).await.unwrap();
        service.create_entry(user2_id, request2).await.unwrap();

        // Get entries for user1
        let user1_entries = service.get_entries(user1_id).await.unwrap();
        assert_eq!(user1_entries.len(), 1);
        assert_eq!(user1_entries[0].user_id, user1_id);

        // Get entries for user2
        let user2_entries = service.get_entries(user2_id).await.unwrap();
        assert_eq!(user2_entries.len(), 1);
        assert_eq!(user2_entries[0].user_id, user2_id);
    }

    #[tokio::test]
    async fn test_update_entry_with_valid_data() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user_id = Uuid::new_v4();

        // Step 1: Create an initial entry
        let create_request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let created_entry = service.create_entry(user_id, create_request).await.unwrap();
        let entry_id = created_entry.id;

        // Step 2: Update the entry with valid data
        let update_request = UpdateSpendingRequest {
            amount: Some(Decimal::from_str("75.50").unwrap()),
            date: Some(NaiveDate::from_ymd_opt(2024, 1, 20).unwrap()),
            categories: Some(vec![CategoryIdentifier::Name("restaurant".to_string())]),
            is_recurring: Some(true),
            recurrence_pattern: Some(RecurrencePattern::Monthly),
            currency_code: Some("EUR".to_string()),
        };

        let result = service.update_entry(user_id, entry_id, update_request).await;
        assert!(result.is_ok());

        let updated_entry = result.unwrap();

        // Step 3: Verify all fields were updated correctly
        assert_eq!(updated_entry.id, entry_id);
        assert_eq!(updated_entry.user_id, user_id);
        assert_eq!(updated_entry.amount, Decimal::from_str("75.50").unwrap());
        assert_eq!(updated_entry.date, NaiveDate::from_ymd_opt(2024, 1, 20).unwrap());
        assert_eq!(updated_entry.is_recurring, true);
        assert!(updated_entry.recurrence_pattern.is_some());
        assert_eq!(updated_entry.recurrence_pattern.unwrap(), RecurrencePattern::Monthly);
        assert_eq!(updated_entry.currency_code, "EUR");
        assert_eq!(updated_entry.category_ids.len(), 1);
        
        // Verify created_at is preserved but updated_at is changed
        assert_eq!(updated_entry.created_at, created_entry.created_at);
        assert!(updated_entry.updated_at > created_entry.updated_at);
    }

    #[tokio::test]
    async fn test_update_entry_with_negative_amount() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user_id = Uuid::new_v4();

        // Step 1: Create an initial entry
        let create_request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let created_entry = service.create_entry(user_id, create_request).await.unwrap();
        let entry_id = created_entry.id;

        // Step 2: Try to update with negative amount
        let update_request = UpdateSpendingRequest {
            amount: Some(Decimal::from_str("-10.00").unwrap()),
            date: None,
            categories: None,
            is_recurring: None,
            recurrence_pattern: None,
            currency_code: None,
        };

        let result = service.update_entry(user_id, entry_id, update_request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_update_entry_with_zero_amount() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user_id = Uuid::new_v4();

        // Step 1: Create an initial entry
        let create_request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let created_entry = service.create_entry(user_id, create_request).await.unwrap();
        let entry_id = created_entry.id;

        // Step 2: Try to update with zero amount
        let update_request = UpdateSpendingRequest {
            amount: Some(Decimal::ZERO),
            date: None,
            categories: None,
            is_recurring: None,
            recurrence_pattern: None,
            currency_code: None,
        };

        let result = service.update_entry(user_id, entry_id, update_request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_update_entry_unauthorized_different_user() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        // Step 1: User 1 creates an entry
        let create_request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let created_entry = service.create_entry(user1_id, create_request).await.unwrap();
        let entry_id = created_entry.id;

        // Step 2: User 2 tries to update User 1's entry
        let update_request = UpdateSpendingRequest {
            amount: Some(Decimal::from_str("100.00").unwrap()),
            date: None,
            categories: None,
            is_recurring: None,
            recurrence_pattern: None,
            currency_code: None,
        };

        let result = service.update_entry(user2_id, entry_id, update_request).await;
        
        // Step 3: Verify the update is rejected with Unauthorized error
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::Unauthorized));
    }

    #[tokio::test]
    async fn test_update_entry_non_existent() {
        let repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let service = SpendingServiceImpl::new(repo.clone(), category_service);

        let user_id = Uuid::new_v4();
        let non_existent_entry_id = Uuid::new_v4(); // Random UUID that doesn't exist

        // Try to update an entry that doesn't exist
        let update_request = UpdateSpendingRequest {
            amount: Some(Decimal::from_str("100.00").unwrap()),
            date: Some(NaiveDate::from_ymd_opt(2024, 1, 20).unwrap()),
            categories: Some(vec![CategoryIdentifier::Name("groceries".to_string())]),
            is_recurring: None,
            recurrence_pattern: None,
            currency_code: None,
        };

        let result = service.update_entry(user_id, non_existent_entry_id, update_request).await;
        
        // Verify the update is rejected with EntryNotFound error
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpendingError::EntryNotFound));
    }
}
