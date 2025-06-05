use argon2::{Argon2, PasswordHash, PasswordVerifier};
use crate::errors::AppError;
use crate::errors::AppError::IdentityStoreError;
use crate::store::models::IdentityModel;
use crate::store::types::{Identity, IdentityUpdate};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait IdentityStore: Send + Sync + 'static {
    async fn create_identity(&self, model: IdentityModel) -> Result<Identity, AppError>;
    async fn get_identity_by_id(&self, id: Uuid) -> Result<Option<Identity>, AppError>;
    async fn get_identity_by_username(&self, username: &str) -> Result<Option<Identity>, AppError>;
    async fn get_identity_by_email(&self, email: &str) -> Result<Option<Identity>, AppError>;
    async fn update_identity(&self, id:Uuid, model: IdentityUpdate) -> Result<Identity, AppError>;
    async fn delete_identity(&self, id: Uuid) -> Result<(), AppError>;
    async fn authenticate_identity(&self, id: Uuid, password: &str) -> Result<Option<Identity>, AppError>;
    async fn increment_password_attempts(&self, id: Uuid) -> Result<Identity, AppError>;
    async fn reset_password_attempts(&self, id: Uuid) -> Result<Identity, AppError>;
    async fn set_active(&self, id: Uuid, is_active: bool) -> Result<Identity, AppError>;
    async fn set_enabled(&self, id: Uuid, is_enabled: bool) -> Result<Identity, AppError>;
    async fn set_verified(&self, id: Uuid, is_verified: bool) -> Result<Identity, AppError>;
    async fn change_password(
        &self,
        id: Uuid,
        new_password_hash: &str,
    ) -> Result<Identity, AppError>;
    async fn change_email(&self, id: Uuid, new_email: &str) -> Result<Identity, AppError>;
    async fn change_username(&self, id: Uuid, new_username: &str) -> Result<Identity, AppError>;
}

#[derive(Clone)]
pub struct PgIdentityStore {
    pool: PgPool,
}

impl PgIdentityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IdentityStore for PgIdentityStore {
    async fn create_identity(&self, model: IdentityModel) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            INSERT INTO identities (id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            model.id,
            model.first_name,
            model.last_name,
            model.username,
            model.email,
            model.password_hash,
            model.password_attempts,
            model.last_authenticated_at,
            model.is_active,
            model.is_verified,
            model.is_enabled,
        )
        .fetch_one(&self.pool)
        .await;
        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn get_identity_by_id(&self, id: Uuid) -> Result<Option<Identity>, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            SELECT id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            FROM identities
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(identity)) => Ok(Some(Identity::from(identity))),
            Ok(None) => Ok(None),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn get_identity_by_username(&self, username: &str) -> Result<Option<Identity>, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            SELECT id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            FROM identities
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(identity)) => Ok(Some(Identity::from(identity))),
            Ok(None) => Ok(None),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn get_identity_by_email(&self, email: &str) -> Result<Option<Identity>, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            SELECT id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            FROM identities
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(identity)) => Ok(Some(Identity::from(identity))),
            Ok(None) => Ok(None),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn update_identity(&self, id: Uuid, model: IdentityUpdate) -> Result<Identity, AppError> {
        let existing_identity = self.get_identity_by_id(id).await?;
        if existing_identity.is_none() {
            return Err(IdentityStoreError("Identity not found".to_string()));
        }
        let existing_identity = existing_identity.unwrap();

        let updated_identity = IdentityModel {
            id,
            first_name: model.first_name.unwrap_or(existing_identity.first_name),
            last_name: model.last_name.unwrap_or(existing_identity.last_name),
            username: model.username.unwrap_or(existing_identity.username),
            email: model.email.unwrap_or(existing_identity.email),
            password_hash: "".to_string(), // Password hash should not be updated here
            password_attempts: existing_identity.password_attempts,
            last_authenticated_at: existing_identity.last_authenticated_at,
            is_active: model.is_active.unwrap_or(existing_identity.is_active),
            is_verified: model.is_verified.unwrap_or(existing_identity.is_verified),
            is_enabled: model.is_enabled.unwrap_or(existing_identity.is_enabled),
            created_at: existing_identity.created_at,
            updated_at: Some(chrono::Utc::now()),
        };

        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET first_name = $2, last_name = $3, username = $4, email = $5, is_active = $6, is_verified = $7, is_enabled = $8, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            updated_identity.id,
            updated_identity.first_name,
            updated_identity.last_name,
            updated_identity.username,
            updated_identity.email,
            updated_identity.is_active,
            updated_identity.is_verified,
            updated_identity.is_enabled
        )
        .fetch_one(&self.pool)
        .await;
        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn delete_identity(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM identities
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn authenticate_identity(&self, id: Uuid, password: &str) -> Result<Option<Identity>, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            SELECT id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            FROM identities
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await;
        
        match result {
            Ok(identity) => {
                let parsed_hash = PasswordHash::new(&identity.password_hash)
                    .map_err(|e| IdentityStoreError(e.to_string()))?;
                if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
                    // Reset password attempts on successful authentication
                    self.reset_password_attempts(id).await?;
                    Ok(Some(Identity::from(identity)))
                } else {
                    // Increment password attempts on failure
                    self.increment_password_attempts(id).await?;
                    Ok(None)
                }
            },
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn increment_password_attempts(&self, id: Uuid) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET password_attempts = password_attempts + 1, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn reset_password_attempts(&self, id: Uuid) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET password_attempts = 0, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn set_active(&self, id: Uuid, is_active: bool) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET is_active = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            is_active
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn set_enabled(&self, id: Uuid, is_enabled: bool) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET is_enabled = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            is_enabled
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn set_verified(&self, id: Uuid, is_verified: bool) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET is_verified = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            is_verified
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }

    async fn change_password(
        &self,
        id: Uuid,
        new_password_hash: &str,
    ) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET password_hash = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            new_password_hash
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }
    async fn change_email(&self, id: Uuid, new_email: &str) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET email = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            new_email
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }
    async fn change_username(&self, id: Uuid, new_username: &str) -> Result<Identity, AppError> {
        let result = sqlx::query_as!(
            IdentityModel,
            r#"
            UPDATE identities
            SET username = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, first_name, last_name, username, email, password_hash, password_attempts, last_authenticated_at, is_active, is_verified, is_enabled, created_at, updated_at
            "#,
            id,
            new_username
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(identity) => Ok(Identity::from(identity)),
            Err(e) => Err(IdentityStoreError(e.to_string())),
        }
    }
}
