pub enum AppError {
    IdentityStoreError(String),
    ApiError(String),
    AuditSerializationError(serde_json::Error),
    PasswordHashError(String),
    AuthenticationError(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::IdentityStoreError(msg) => write!(f, "Identity Store Error: {}", msg),
            AppError::ApiError(msg) => write!(f, "API Error: {}", msg),
            AppError::AuditSerializationError(err) => {
                write!(f, "Audit Serialization Error: {}", err)
            }
            AppError::PasswordHashError(msg) => write!(f, "Password Hash Error: {}", msg),
            AppError::AuthenticationError(msg) => write!(f, "Authentication Error: {}", msg),
        }
    }
}
