use iso_currency::Currency;
use validator::ValidationError;

/// Validates that a currency code is a valid ISO 4217 currency code
pub fn validate_currency_code(code: &str) -> Result<(), ValidationError> {
    Currency::from_code(code).ok_or_else(|| {
        let mut error = ValidationError::new("invalid_currency");
        error.message = Some(format!("'{}' is not a valid ISO 4217 currency code", code).into());
        error
    })?;
    Ok(())
}
