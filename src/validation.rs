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
/// Validates that an amount is positive (greater than 0)
pub fn validate_positive_amount(amount: &rust_decimal::Decimal) -> Result<(), ValidationError> {
    if *amount <= rust_decimal::Decimal::ZERO {
        let mut error = ValidationError::new("invalid_amount");
        error.message = Some("Amount must be greater than 0".into());
        return Err(error);
    }
    Ok(())
}
