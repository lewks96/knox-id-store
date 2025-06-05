use crate::store::models::IdentityModel; // Assuming this path is correct
use chrono::{DateTime, Utc};
use rsa::signature::digest::Update;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
// Ensure these paths to your generated gRPC types are correct
use crate::grpc::identity_service::CreateIdentityPayload as CreateIdentityPayloadProto;
use crate::grpc::identity_service::Identity as IdentityProto;
use crate::grpc::identity_service::IdentityUpdatePayload as UpdateIdentityPayloadProto;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Identity {
    pub id: Uuid,
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "emailAddress")]
    pub email: String, // Internal field name
    #[serde(rename = "passwordAttempts")]
    pub password_attempts: i32,
    #[serde(rename = "lastAuthenticatedAt")]
    pub last_authenticated_at: Option<DateTime<Utc>>,

    #[serde(rename = "isActive")]
    pub is_active: bool,
    #[serde(rename = "isVerified")]
    pub is_verified: bool,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,

    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl From<IdentityModel> for Identity {
    fn from(model: IdentityModel) -> Self {
        Self {
            id: model.id,
            first_name: model.first_name,
            last_name: model.last_name,
            username: model.username,
            email: model.email,
            password_attempts: model.password_attempts,
            last_authenticated_at: model.last_authenticated_at,
            is_active: model.is_active,
            is_verified: model.is_verified,
            is_enabled: model.is_enabled,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityUpdate {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(rename = "username")]
    pub username: Option<String>,
    #[serde(rename = "emailAddress")]
    pub email: Option<String>, // Internal field name
    #[serde(rename = "isActive")]
    pub is_active: Option<bool>,
    #[serde(rename = "isVerified")]
    pub is_verified: Option<bool>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateIdentityPayload {
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "emailAddress")]
    pub email: String, // Internal field name
    #[serde(rename = "passwordAttempts")]
    pub password_attempts: i32,
    pub password: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
    #[serde(rename = "isVerified")]
    pub is_verified: bool,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}

impl From<CreateIdentityPayload> for IdentityModel {
    fn from(payload: CreateIdentityPayload) -> Self {
        Self {
            id: Uuid::new_v4(),
            first_name: payload.first_name,
            last_name: payload.last_name,
            username: payload.username,
            email: payload.email,
            password_hash: payload.password.unwrap_or_default(), // Handle password hashing separately and more robustly
            password_attempts: payload.password_attempts,
            last_authenticated_at: None,
            is_active: payload.is_active,
            is_verified: payload.is_verified,
            is_enabled: payload.is_enabled,
            created_at: Some(Utc::now()),
            updated_at: None,
        }
    }
}

// --- Protobuf Conversions ---

// From Protobuf CreateIdentityPayload (CreateIdentityPayloadProto) to Internal CreateIdentityPayload
impl From<CreateIdentityPayloadProto> for CreateIdentityPayload {
    fn from(proto: CreateIdentityPayloadProto) -> Self {
        Self {
            first_name: proto.first_name,
            last_name: proto.last_name,
            username: proto.username,
            email: proto.email_address, // Proto: email_address -> Internal: email
            password_attempts: proto.password_attempts,
            password: proto.password,
            is_active: proto.is_active,
            is_verified: proto.is_verified,
            is_enabled: proto.is_enabled,
        }
    }
}

// From Internal CreateIdentityPayload to Protobuf CreateIdentityPayload (CreateIdentityPayloadProto)
impl From<CreateIdentityPayload> for CreateIdentityPayloadProto {
    fn from(internal: CreateIdentityPayload) -> Self {
        Self {
            first_name: internal.first_name,
            last_name: internal.last_name,
            username: internal.username,
            email_address: internal.email, // Internal: email -> Proto: email_address
            password_attempts: internal.password_attempts,
            password: internal.password,
            is_active: internal.is_active,
            is_verified: internal.is_verified,
            is_enabled: internal.is_enabled,
        }
    }
}

// From Protobuf Identity (IdentityProto) to Internal Identity
impl From<IdentityProto> for Identity {
    fn from(proto: IdentityProto) -> Self {
        Self {
            id: uuid::Uuid::try_parse(&proto.id)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to parse UUID from proto: {}, error: {}", proto.id, e);
                    uuid::Uuid::nil() // Fallback or handle error more robustly
                }),
            first_name: proto.first_name,
            last_name: proto.last_name,
            username: proto.username,
            email: proto.email_address, // Proto: email_address -> Internal: email
            password_attempts: proto.password_attempts,
            last_authenticated_at: option_timestamp_to_datetime(proto.last_authenticated_at),
            is_active: proto.is_active,
            is_verified: proto.is_verified,
            is_enabled: proto.is_enabled,
            created_at: option_timestamp_to_datetime(proto.created_at),
            updated_at: option_timestamp_to_datetime(proto.updated_at),
        }
    }
}

// From Internal Identity to Protobuf Identity (IdentityProto)
impl From<Identity> for IdentityProto {
    fn from(internal: Identity) -> Self {
        Self {
            id: internal.id.to_string(),
            first_name: internal.first_name,
            last_name: internal.last_name,
            username: internal.username,
            email_address: internal.email, // Internal: email -> Proto: email_address
            password_attempts: internal.password_attempts,
            last_authenticated_at: option_datetime_to_timestamp(internal.last_authenticated_at),
            is_active: internal.is_active,
            is_verified: internal.is_verified,
            is_enabled: internal.is_enabled,
            created_at: option_datetime_to_timestamp(internal.created_at),
            updated_at: option_datetime_to_timestamp(internal.updated_at),
        }
    }
}

impl From<UpdateIdentityPayloadProto> for IdentityUpdate {
    fn from(proto: UpdateIdentityPayloadProto) -> Self {
        Self {
            first_name: proto.first_name,
            last_name: proto.last_name,
            username: proto.username,
            email: proto.email_address, // Proto: email_address -> Internal: email
            is_active: proto.is_active,
            is_verified: proto.is_verified,
            is_enabled: proto.is_enabled,
        }
    }
}

// --- Helper functions for timestamp conversions ---

// Helper for Option<chrono::DateTime<chrono::Utc>> to Option<prost_types::Timestamp>
fn option_datetime_to_timestamp(dt: Option<chrono::DateTime<chrono::Utc>>) -> Option<prost_types::Timestamp> {
    dt.map(|val| {
        prost_types::Timestamp::from(std::time::SystemTime::from(val))
    })
}

// Helper for Option<prost_types::Timestamp> to Option<chrono::DateTime<chrono::Utc>>
fn option_timestamp_to_datetime(ts: Option<prost_types::Timestamp>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.and_then(|val| {
        match std::time::SystemTime::try_from(val) {
            Ok(system_time) => Some(chrono::DateTime::<chrono::Utc>::from(system_time)),
            Err(e) => {
                eprintln!("Failed to convert prost_types::Timestamp to SystemTime: {:?}", e);
                None // Fallback or handle error more robustly
            }
        }
    })
}
