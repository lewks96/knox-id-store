use crate::audit::audit::AuditStore;
use crate::audit::types::IdentityAuditEventData::IdentityCreated;
use crate::audit::types::IdentityAuditEventType::Created;
use crate::errors::AppError;
use crate::store::identity_store::IdentityStore;
use crate::store::types::{CreateIdentityPayload, Identity, IdentityUpdate};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use log::info;

pub async fn create_identity_from_dto(
    payload: CreateIdentityPayload,
    store: &impl IdentityStore,
    audit: &impl AuditStore,
) -> Result<Identity, AppError> {

    let payload = {
        if let Some(password) = payload.password.clone() {
            let salt = SaltString::generate(&mut OsRng);
            let hashed = hash_password(&password, &salt)?;
            let mut payload = payload;
            payload.password = Some(hashed.to_string());
            payload
        } else {
            payload
        }
    };


    match store.create_identity(payload.into()).await {
        Ok(identity) => {
            info!("Identity created: {:?}", identity);
            audit
                .record_identity_event(identity.id, Created, IdentityCreated(identity.clone()))
                .await
                .map_err(|e| {
                    tracing::error!("Failed to record audit event: {}", e);
                    AppError::ApiError(format!("Failed to record audit event: {}", e))
                })?;
            Ok(identity)
        }
        Err(e) => {
            tracing::error!("Error creating identity: {}", e);
            Err(AppError::IdentityStoreError(format!(
                "Failed to create identity: {}",
                e
            )))
        }
    }
}

fn hash_password<'a>(password: &String, salt_string: &'a SaltString) -> Result<PasswordHash<'a>, AppError> {
    let m_cost_kib = 19 * 1024;  // Memory cost: 19 MiB (Argon2 takes KiB)
    let t_cost_iterations = 2;  // Time cost (iterations): OWASP often recommends 2 or more.
    let p_cost_parallelism = 1; // Parallelism cost (lanes).
    let output_len_bytes = 32;  // Desired hash length in bytes (optional, default is often 32)
    let params = Params::new(m_cost_kib, t_cost_iterations, p_cost_parallelism, Some(output_len_bytes))
        .map_err(|e| AppError::PasswordHashError(format!("Failed to create Argon2 params: {}", e)))?;

    let argon2_custom = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hashed = argon2_custom
        .hash_password(password.as_bytes(), salt_string)
        .map_err(|e| {
            AppError::PasswordHashError(format!("Failed to hash password: {}", e))
        })?;
    Ok(hashed)
}

pub async fn get_identity_by_id(
    id: uuid::Uuid,
    store: &impl IdentityStore,
) -> Result<Option<Identity>, AppError> {
    store
        .get_identity_by_id(id)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to get identity: {}", e)))
}

pub async fn get_identity_by_username(
    username: &str,
    store: &impl IdentityStore,
) -> Result<Option<Identity>, AppError> {
    store
        .get_identity_by_username(username)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to get identity: {}", e)))
}

pub async fn get_identity_by_email(
    email: &str,
    store: &impl IdentityStore,
) -> Result<Option<Identity>, AppError> {
    store
        .get_identity_by_email(email)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to get identity: {}", e)))
}

pub async fn update_identity(
    id: uuid::Uuid,
    identity: IdentityUpdate,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .update_identity(id, identity.into())
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to update identity: {}", e)))?;

    info!("Identity updated: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn delete_identity(
    id: uuid::Uuid,
    store: &impl IdentityStore,
) -> Result<(), AppError> {
    store
        .delete_identity(id)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to delete identity: {}", e)))?;

    info!("Identity deleted: {}", id);
    Ok(())
}

pub async fn authenticate(
    id: uuid::Uuid,
    password_hash: &str,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    // Ideally, this logic should be here outside the store, but for simplicity, we keep it here.
    match store.authenticate_identity(id, password_hash).await {
        Ok(identity) => {
            match identity {
                Some(identity) => {
                    info!("Identity authenticated: {:?}", identity);
                    Ok(identity)
                }
                None => {
                    tracing::warn!("Authentication failed for identity {}", id);
                    Err(AppError::AuthenticationError(format!(
                        "Identity with ID {} not found or password mismatch",
                        id
                    )))
                }
            }
        }
        Err(e) => {
            tracing::error!("Authentication failed for identity {}: {}", id, e);
            Err(AppError::AuthenticationError(format!(
                "Failed to authenticate identity: {}",
                e
            )))
        }
    }
}

pub async fn set_active(
    id: uuid::Uuid,
    is_active: bool,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .set_active(id, is_active)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to set active status: {}", e)))?;

    info!("Identity active status updated: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn set_verified(
    id: uuid::Uuid,
    is_verified: bool,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .set_verified(id, is_verified)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to set verified status: {}", e)))?;

    info!("Identity verified status updated: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn set_enabled(
    id: uuid::Uuid,
    is_enabled: bool,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .set_enabled(id, is_enabled)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to set enabled status: {}", e)))?;

    info!("Identity enabled status updated: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn reset_password(
    id: uuid::Uuid,
    new_password: &str,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let new_password = new_password.to_string();
    let salt = SaltString::generate(&mut OsRng);
    let hashed = hash_password(&new_password, &salt)
        .map_err(|e| AppError::PasswordHashError(format!("Failed to hash new password: {}", e)))?;

    let updated_identity = store
        .change_password(id, hashed.to_string().as_str())
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to reset password: {}", e)))?;

    info!("Password reset for identity: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn change_email(
    id: uuid::Uuid,
    email: &str,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .change_email(id, email)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to change email: {}", e)))?;

    info!("Email changed for identity: {:?}", updated_identity);
    Ok(updated_identity)
}

pub async fn change_username(
    id: uuid::Uuid,
    username: &str,
    store: &impl IdentityStore,
) -> Result<Identity, AppError> {
    let updated_identity = store
        .change_username(id, username)
        .await
        .map_err(|e| AppError::IdentityStoreError(format!("Failed to change username: {}", e)))?;

    info!("Username changed for identity: {:?}", updated_identity);
    Ok(updated_identity)
}
