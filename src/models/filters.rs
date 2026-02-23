use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpendingTotal {
    pub total: Decimal,
    pub currency: String,
}

/// Date range for filtering spending entries
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DateRange {
    pub start: NaiveDate,
    pub end: NaiveDate,
}

impl DateRange {
    /// Validate that end date is >= start date
    pub fn is_valid(&self) -> bool {
        self.end >= self.start
    }
}

/// Filters for querying spending entries
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct SpendingFilters {
    /// Filter by exact date
    pub date: Option<NaiveDate>,

    /// Filter by date range (inclusive)
    pub date_range: Option<DateRange>,

    /// Filter by category ID
    pub category_id: Option<Uuid>,

    /// Filter by recurring status
    pub is_recurring: Option<bool>,

    /// Filter by currency code
    pub currency_code: Option<String>,

    /// Page number for pagination (1-indexed)
    pub page: Option<u32>,

    /// Page size for pagination
    pub page_size: Option<u32>,
}

/// Category spending data for chart visualization
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CategorySpending {
    pub category_id: Uuid,
    pub category_name: String,
    pub total: Decimal,
    pub currency: String,
}

/// Chart data containing category spending breakdown
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChartData {
    pub categories: Vec<CategorySpending>,
    pub date_range: Option<DateRange>,
    pub grouped_by_currency: bool,
}
