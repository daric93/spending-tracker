use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::validation::validate_currency_code;

/// User entity representing a registered user in the system
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub default_currency: String,
    pub created_at: DateTime<Utc>,
}

/// Request payload for user registration
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
#[schema(example = json!({
    "name": "John Doe",
    "email": "john.doe@example.com",
    "password": "securepassword123",
    "default_currency": "USD"
}))]
pub struct CreateUserRequest {
    #[validate(length(
        min = 3,
        max = 100,
        message = "Name must be between 3 and 100 characters"
    ))]
    pub name: String,

    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(custom(function = "validate_currency_code"))]
    pub default_currency: Option<String>,
}
