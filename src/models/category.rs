use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Type;
use utoipa::ToSchema;
use uuid::Uuid;

/// Predefined category names available to all users
pub const PREDEFINED_CATEGORIES: &[&str] = &[
    "groceries",
    "restaurant",
    "travel",
    "transportation",
    "entertainment",
    "utilities",
    "healthcare",
    "shopping",
    "education",
    "personal_care",
    "housing",
    "debt_payment",
    "savings",
    "clothing",
    "household_supplies",
    "insurance",
    "kids",
];

/// Type of category - either predefined (system-provided) or custom (user-created)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CategoryType {
    Predefined,
    Custom,
}

/// Category entity representing a spending classification
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub category_type: CategoryType,
    /// User ID for custom categories, None for predefined categories
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
