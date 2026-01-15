use crate::errors::AuthError;
use crate::models::Claims;

pub async fn index() -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok("Welcome to the index :)".to_string())
}

pub async fn protected(claims: Claims) -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    ))
}