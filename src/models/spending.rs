use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::validation::{validate_currency_code, validate_positive_amount};

/// Recurrence pattern for recurring expenses
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecurrencePattern {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// Category identifier - can be either a UUID or a category name
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum CategoryIdentifier {
    Id(Uuid),
    Name(String),
}

/// Spending entry entity representing a single spending transaction
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpendingEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub amount: Decimal,
    pub date: NaiveDate,
    /// Multiple categories can be associated with a spending entry
    pub category_ids: Vec<Uuid>,
    pub is_recurring: bool,
    pub recurrence_pattern: Option<RecurrencePattern>,
    pub currency_code: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request payload for creating a new spending entry
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
#[schema(example = json!({
    "amount": 42.50,
    "date": "2024-01-15",
    "categories": [
        {"Id": "550e8400-e29b-41d4-a716-446655440000"},
        {"Name": "groceries"}
    ],
    "is_recurring": false,
    "currency_code": "USD"
}))]
pub struct CreateSpendingRequest {
    #[validate(custom(function = "validate_positive_amount"))]
    #[schema(minimum = 0.01, example = 42.50)]
    pub amount: Decimal,

    #[schema(format = "date", example = "2024-01-15")]
    pub date: NaiveDate,

    #[validate(length(min = 1, message = "At least one category is required"))]
    pub categories: Vec<CategoryIdentifier>,

    #[schema(default = false)]
    pub is_recurring: Option<bool>,

    #[schema(example = "monthly")]
    pub recurrence_pattern: Option<RecurrencePattern>,

    #[validate(custom(function = "validate_currency_code"))]
    #[schema(min_length = 3, max_length = 3, example = "USD")]
    pub currency_code: Option<String>,
}

/// Request payload for updating an existing spending entry
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
#[schema(example = json!({
    "amount": 45.00,
    "date": "2024-01-16",
    "categories": [
        {"Name": "restaurant"}
    ]
}))]
pub struct UpdateSpendingRequest {
    #[validate(custom(function = "validate_positive_amount"))]
    #[schema(minimum = 0.01, example = 45.00)]
    pub amount: Option<Decimal>,

    #[schema(format = "date", example = "2024-01-16")]
    pub date: Option<NaiveDate>,

    pub categories: Option<Vec<CategoryIdentifier>>,

    pub is_recurring: Option<bool>,

    pub recurrence_pattern: Option<RecurrencePattern>,

    #[validate(custom(function = "validate_currency_code"))]
    #[schema(min_length = 3, max_length = 3, example = "EUR")]
    pub currency_code: Option<String>,
}
