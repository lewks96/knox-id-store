use crate::audit::models::{IdentityAuditEventModel, IdentityAuditEventModelSerde};
use crate::audit::types::{IdentityAuditEventData, IdentityAuditEventType};
use crate::errors::AppError;
use crate::errors::AppError::AuditSerializationError;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait AuditStore: Send + Sync + 'static {
    async fn record_identity_event(
        &self,
        identity_id: Uuid,
        event_type: IdentityAuditEventType,
        event_data: IdentityAuditEventData,
    ) -> Result<IdentityAuditEventModel, AppError>;

    async fn get_identity_events(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<IdentityAuditEventModel>, AppError>;

    async fn get_all_events(&self) -> Result<Vec<IdentityAuditEventModel>, AppError>;
}

#[derive(Clone)]
pub struct PgAuditStore {
    pool: sqlx::PgPool,
}

impl PgAuditStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        PgAuditStore { pool }
    }
}

#[async_trait]
impl AuditStore for PgAuditStore {
    async fn record_identity_event(
        &self,
        identity_id: Uuid,
        event_type: IdentityAuditEventType,
        event_data: IdentityAuditEventData,
    ) -> Result<IdentityAuditEventModel, AppError> {
        let event = IdentityAuditEventModel {
            id: Uuid::new_v4(),
            identity_id,
            event_type,
            event_data,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let cloned_event = event.clone();
        sqlx::query!(
            "INSERT INTO audit_events (id, identity_id, event_type, event_data, created_at) VALUES ($1, $2, $3, $4, $5)",
            event.id,
            event.identity_id,
            event.event_type as _,
            serde_json::to_value(event.event_data).map_err(AuditSerializationError)?,
            event.created_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::IdentityStoreError(e.to_string()))?;

        Ok(cloned_event)
    }

    async fn get_identity_events(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<IdentityAuditEventModel>, AppError> {
        let events = sqlx::query_as!(
            IdentityAuditEventModelSerde,
            r#"
        SELECT
            id,
            identity_id,
            event_type AS "event_type: _", -- This is the crucial hint for the enum
            event_data,
            created_at
            -- If identity_id is a column you want to select and map:
            -- , identity_id
        FROM audit_events -- Your table name
        WHERE identity_id = $1
        ORDER BY created_at DESC -- Optional: good practice for audit logs
        "#,
            identity_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::IdentityStoreError(e.to_string()))?;

        // Convert serde_json::Value to IdentityAuditEventData
        let events: Vec<IdentityAuditEventModel> = events
            .into_iter()
            .map(|event| IdentityAuditEventModel {
                id: event.id,
                identity_id,
                event_type: event.event_type,
                event_data: serde_json::from_value(event.event_data).unwrap(),
                created_at: event.created_at,
            })
            .collect();

        Ok(events)
    }

    async fn get_all_events(&self) -> Result<Vec<IdentityAuditEventModel>, AppError> {
        let events = sqlx::query_as!(
            IdentityAuditEventModelSerde,
            r#"
            SELECT
                id,
                identity_id, 
                event_type AS "event_type: _", -- Crucial hint for the enum
                event_data,
                created_at
            FROM
                audit_events -- Or 'identity_audit_events' if that's your table name
            ORDER BY
                created_at DESC -- Or ASC, depending on desired order
            "#
        )
        .fetch_all(&self.pool) // Use the pool from self
        .await
        .map_err(|e| AppError::IdentityStoreError(e.to_string()))?;

        let events: Vec<IdentityAuditEventModel> = events
            .into_iter()
            .map(|event| {
                IdentityAuditEventModel {
                    id: event.id,
                    identity_id: event.identity_id, // Assuming this is part of the model
                    event_type: event.event_type,
                    event_data: serde_json::from_value(event.event_data).unwrap(),
                    created_at: event.created_at,
                }
            })
            .collect();

        Ok(events)
    }
}
