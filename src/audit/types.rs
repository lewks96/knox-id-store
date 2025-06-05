use crate::store::types::Identity;
use serde::{Deserialize, Serialize};
use sqlx::Type;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, Type)]
#[sqlx(type_name = "identity_audit_event_type", rename_all = "PascalCase")]
pub enum IdentityAuditEventType {
    Created,
    Updated,
    Deleted,
    Authenticated,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IdentityAuditEventData {
    IdentityCreated(Identity),
    IdentityDeleted(Uuid),
    AttributeChanged(String, String),
    Authenticated(Uuid),
    PasswordChanged(Uuid, String),
    EmailChanged(Uuid, String),
    UsernameChanged(Uuid, String),
    EmailVerified(Uuid),
    IsActiveChanged(Uuid, bool),
    IsEnabledChanged(Uuid, bool),
}
