use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request payload for user login
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "email": "john.doe@example.com",
    "password": "securepassword123"
}))]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Authentication token response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": "2024-01-16T12:00:00Z"
}))]
pub struct AuthToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}
