use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityModel {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub password_attempts: i32,
    pub last_authenticated_at: Option<DateTime<Utc>>,

    pub is_active: bool,
    pub is_verified: bool,
    pub is_enabled: bool,

    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

