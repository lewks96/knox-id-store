use crate::audit::types::{IdentityAuditEventData, IdentityAuditEventType};
use crate::store::types::Identity;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::types::JsonValue;
use sqlx::{FromRow, Type};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct IdentityAuditEventModel {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub event_type: IdentityAuditEventType,
    pub event_data: IdentityAuditEventData,
    pub created_at: NaiveDateTime,
}
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct IdentityAuditEventModelSerde {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub event_type: IdentityAuditEventType,
    pub event_data: Value,
    pub created_at: NaiveDateTime,
}
