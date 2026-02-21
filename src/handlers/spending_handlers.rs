use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::middleware::auth_middleware::AuthenticatedUser;
use crate::models::spending::{CreateSpendingRequest, SpendingEntry, UpdateSpendingRequest};
use crate::services::spending_service::{SpendingError, SpendingService};

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

/// Convert SpendingError to HTTP response
impl IntoResponse for SpendingError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            SpendingError::InvalidAmount => (
                StatusCode::BAD_REQUEST,
                "invalid_amount",
                "Amount must be positive",
            ),
            SpendingError::InvalidDate => (
                StatusCode::BAD_REQUEST,
                "invalid_date",
                "Invalid date format",
            ),
            SpendingError::CategoryNotFound => (
                StatusCode::NOT_FOUND,
                "category_not_found",
                "Category not found",
            ),
            SpendingError::EntryNotFound => (
                StatusCode::NOT_FOUND,
                "entry_not_found",
                "Spending entry not found",
            ),
            SpendingError::Unauthorized => (
                StatusCode::FORBIDDEN,
                "unauthorized",
                "Unauthorized to access this entry",
            ),
            SpendingError::DatabaseError(ref msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                msg.as_str(),
            ),
        };

        let error_response = ErrorResponse::new(error_type, message);
        (status, Json(error_response)).into_response()
    }
}

/// Handler for creating a spending entry
///
/// Creates a new spending entry for the authenticated user.
#[utoipa::path(
    post,
    path = "/api/spending",
    request_body = CreateSpendingRequest,
    responses(
        (status = 201, description = "Spending entry successfully created", body = SpendingEntry),
        (status = 400, description = "Validation error (negative amount, invalid date)", body = ErrorResponse),
        (status = 404, description = "Category not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "spending"
)]
pub async fn create_entry_handler(
    State(spending_service): State<Arc<dyn SpendingService>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(request): Json<CreateSpendingRequest>,
) -> Result<(StatusCode, Json<SpendingEntry>), Response> {
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

    // Call spending service to create entry
    match spending_service.create_entry(auth_user.user_id, request).await {
        Ok(entry) => Ok((StatusCode::CREATED, Json(entry))),
        Err(e) => Err(e.into_response()),
    }
}
/// Handler for listing spending entries
///
/// Retrieves all spending entries for the authenticated user, sorted by date descending.
#[utoipa::path(
    get,
    path = "/api/spending",
    responses(
        (status = 200, description = "List of spending entries", body = Vec<SpendingEntry>),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "spending"
)]
pub async fn list_entries_handler(
    State(spending_service): State<Arc<dyn SpendingService>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<SpendingEntry>>, Response> {
    // Call spending service to get all entries for the user
    match spending_service.get_entries(auth_user.user_id).await {
        Ok(entries) => Ok(Json(entries)),
        Err(e) => Err(e.into_response()),
    }
}

/// Handler for updating a spending entry
///
/// Updates an existing spending entry for the authenticated user.
#[utoipa::path(
    put,
    path = "/api/spending/{id}",
    params(
        ("id" = Uuid, Path, description = "Spending entry ID")
    ),
    request_body = UpdateSpendingRequest,
    responses(
        (status = 200, description = "Spending entry successfully updated", body = SpendingEntry),
        (status = 400, description = "Validation error (negative amount, invalid date)", body = ErrorResponse),
        (status = 403, description = "User doesn't own the entry", body = ErrorResponse),
        (status = 404, description = "Entry not found or category not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "spending"
)]
pub async fn update_entry_handler(
    State(spending_service): State<Arc<dyn SpendingService>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    axum::extract::Path(entry_id): axum::extract::Path<Uuid>,
    Json(request): Json<UpdateSpendingRequest>,
) -> Result<(StatusCode, Json<SpendingEntry>), Response> {
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

    // Call spending service to update entry
    match spending_service
        .update_entry(auth_user.user_id, entry_id, request)
        .await
    {
        Ok(entry) => Ok((StatusCode::OK, Json(entry))),
        Err(e) => Err(e.into_response()),
    }
}

/// Handler for deleting a spending entry
///
/// Deletes an existing spending entry for the authenticated user.
#[utoipa::path(
    delete,
    path = "/api/spending/{id}",
    params(
        ("id" = Uuid, Path, description = "Spending entry ID")
    ),
    responses(
        (status = 204, description = "Spending entry successfully deleted"),
        (status = 403, description = "User doesn't own the entry", body = ErrorResponse),
        (status = 404, description = "Entry not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "spending"
)]
pub async fn delete_entry_handler(
    State(spending_service): State<Arc<dyn SpendingService>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    axum::extract::Path(entry_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, Response> {
    // Call spending service to delete entry
    match spending_service
        .delete_entry(auth_user.user_id, entry_id)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(e.into_response()),
    }
}

/// Handler for getting spending total
///
/// Calculates the total spending for the authenticated user.
#[utoipa::path(
    get,
    path = "/api/spending/total",
    responses(
        (status = 200, description = "Spending total", body = crate::models::SpendingTotal),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "spending"
)]
pub async fn get_total_handler(
    State(spending_service): State<Arc<dyn SpendingService>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<crate::models::SpendingTotal>, Response> {
    // Call spending service to get total
    match spending_service.get_total(auth_user.user_id).await {
        Ok(total) => Ok(Json(total)),
        Err(e) => Err(e.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::category::Category;
    use crate::models::spending::CategoryIdentifier;
    use crate::repositories::spending_repository::{RepositoryError, SpendingRepository};
    use crate::services::category_service::{CategoryError, CategoryService};
    use async_trait::async_trait;
    use chrono::{NaiveDate, Utc};
    use rust_decimal::Decimal;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Mutex;
    use uuid::Uuid;

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

        async fn calculate_total(&self, user_id: Uuid) -> Result<rust_decimal::Decimal, RepositoryError> {
            let entries = self.entries.lock().unwrap();
            let total = entries
                .values()
                .filter(|e| e.user_id == user_id)
                .map(|e| e.amount)
                .sum();
            Ok(total)
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
            
            // Add a predefined category
            let groceries_category = Category {
                id: Uuid::new_v4(),
                name: "groceries".to_string(),
                category_type: crate::models::category::CategoryType::Predefined,
                user_id: None,
                created_at: Utc::now(),
            };
            categories.insert("groceries".to_string(), groceries_category);

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
                category_type: crate::models::category::CategoryType::Custom,
                user_id: Some(user_id),
                created_at: Utc::now(),
            };
            categories.insert(name.to_string(), new_category.clone());
            Ok(new_category)
        }
    }

    #[tokio::test]
    async fn test_create_entry_handler_success() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_ok());
        let (status, Json(entry)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(entry.amount, Decimal::from_str("42.50").unwrap());
        assert_eq!(entry.user_id, user_id);
        assert_eq!(entry.currency_code, "USD");
    }

    #[tokio::test]
    async fn test_create_entry_handler_validation_error_negative_amount() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("-10.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_entry_handler_validation_error_empty_categories() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![], // Empty categories should fail validation
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_entry_handler_auto_creates_custom_category() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("25.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("custom_category".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_ok());
        let (status, Json(entry)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(entry.category_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_create_entry_handler_database_error() {
        let spending_repo = Arc::new(MockSpendingRepository::with_failure());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_entry_handler_category_service_error() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::with_failure());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("new_category".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_entry_handler_with_recurring_pattern() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(true),
            recurrence_pattern: Some(crate::models::spending::RecurrencePattern::Monthly),
            currency_code: Some("USD".to_string()),
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_ok());
        let (status, Json(entry)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(entry.is_recurring, true);
        assert!(entry.recurrence_pattern.is_some());
    }

    #[tokio::test]
    async fn test_create_entry_handler_default_currency() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let request = CreateSpendingRequest {
            amount: Decimal::from_str("42.50").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            categories: vec![CategoryIdentifier::Name("groceries".to_string())],
            is_recurring: Some(false),
            recurrence_pattern: None,
            currency_code: None, // No currency specified, should default to USD
        };

        let result = create_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            Json(request),
        )
        .await;

        assert!(result.is_ok());
        let (status, Json(entry)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(entry.currency_code, "USD");
    }

    #[tokio::test]
    async fn test_list_entries_handler_empty_list() {
        // Create mock repository and services
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let auth_user = AuthenticatedUser { user_id };

        // Call the handler with a user that has no spending entries
        let result = list_entries_handler(
            State(spending_service),
            Extension(auth_user),
        )
        .await;

        // Verify the result is Ok and contains an empty vector
        assert!(result.is_ok(), "Handler should return Ok for empty list");
        let entries = result.unwrap().0;
        assert_eq!(entries.len(), 0, "Should return empty list when no entries exist");
    }

    #[tokio::test]
    async fn test_spending_error_into_response() {
        // Test InvalidAmount error
        let error = SpendingError::InvalidAmount;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test InvalidDate error
        let error = SpendingError::InvalidDate;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test CategoryNotFound error
        let error = SpendingError::CategoryNotFound;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Test EntryNotFound error
        let error = SpendingError::EntryNotFound;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Test Unauthorized error
        let error = SpendingError::Unauthorized;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Test DatabaseError
        let error = SpendingError::DatabaseError("Connection failed".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_delete_entry_handler_success() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo.clone(),
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        // First create an entry
        let entry = SpendingEntry {
            id: entry_id,
            user_id,
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            category_ids: vec![Uuid::new_v4()],
            is_recurring: false,
            recurrence_pattern: None,
            currency_code: "USD".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        spending_repo.create(entry).await.unwrap();

        // Now delete it
        let result = delete_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            axum::extract::Path(entry_id),
        )
        .await;

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_entry_handler_not_found() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo,
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let non_existent_id = Uuid::new_v4();

        let result = delete_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            axum::extract::Path(non_existent_id),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_entry_handler_unauthorized() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo.clone(),
                category_service,
            ),
        );

        let owner_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        // Create an entry owned by owner_id
        let entry = SpendingEntry {
            id: entry_id,
            user_id: owner_id,
            amount: Decimal::from_str("50.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            category_ids: vec![Uuid::new_v4()],
            is_recurring: false,
            recurrence_pattern: None,
            currency_code: "USD".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        spending_repo.create(entry).await.unwrap();

        // Try to delete with a different user
        let result = delete_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id: other_user_id }),
            axum::extract::Path(entry_id),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_entry_handler_verifies_removal() {
        let spending_repo = Arc::new(MockSpendingRepository::new());
        let category_service = Arc::new(MockCategoryService::new());
        let spending_service: Arc<dyn SpendingService> = Arc::new(
            crate::services::spending_service::SpendingServiceImpl::new(
                spending_repo.clone(),
                category_service,
            ),
        );

        let user_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        // Create an entry
        let entry = SpendingEntry {
            id: entry_id,
            user_id,
            amount: Decimal::from_str("75.00").unwrap(),
            date: NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
            category_ids: vec![Uuid::new_v4()],
            is_recurring: false,
            recurrence_pattern: None,
            currency_code: "USD".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        spending_repo.create(entry).await.unwrap();

        // Verify entry exists before deletion
        let found_entry = spending_repo.find_by_id(entry_id).await.unwrap();
        assert!(found_entry.is_some(), "Entry should exist before deletion");

        // Delete the entry
        let result = delete_entry_handler(
            State(spending_service),
            Extension(AuthenticatedUser { user_id }),
            axum::extract::Path(entry_id),
        )
        .await;

        assert!(result.is_ok(), "Deletion should succeed");
        assert_eq!(result.unwrap(), StatusCode::NO_CONTENT);

        // Verify entry is removed after deletion
        let found_entry = spending_repo.find_by_id(entry_id).await.unwrap();
        assert!(found_entry.is_none(), "Entry should be removed after deletion");
    }
}
