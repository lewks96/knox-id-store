use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use uuid::Uuid;
use crate::audit::audit::PgAuditStore;
use crate::errors::AppError::ApiError;
use crate::identity::{create_identity_from_dto, get_identity_by_id};
use crate::state::AppState;
use crate::store::identity_store::PgIdentityStore;
use crate::store::types::CreateIdentityPayload;

pub async fn create_identity_route(
    State(mut state): State<AppState<PgIdentityStore, PgAuditStore>>,
    Json(identity): Json<CreateIdentityPayload>,
) -> impl IntoResponse {
    let res = create_identity_from_dto(identity, &mut state.id_store, &mut state.audit_store)
        .await
        .map_err(|e| ApiError(format!("Failed to create identity: {}", e)));

    match res {
        Ok(identity) => {
            tracing::info!("Identity created: {:?}", identity);
            (StatusCode::CREATED, Json(identity)).into_response()
        }
        Err(e) => {
            tracing::error!("Error creating identity: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

pub async fn get_identity_by_uuid_route(
    Path(user_id): Path<Uuid>,
    State(mut state): State<AppState<PgIdentityStore, PgAuditStore>>,
) -> impl IntoResponse {
    let res = get_identity_by_id(user_id, &mut state.id_store)
        .await
        .map_err(|e| ApiError(format!("Failed to get identity: {}", e)));
    match res {
        Ok(identity) => {
            tracing::info!("Identity retrieved: {:?}", identity);
            (StatusCode::OK, Json(identity)).into_response()
        }
        Err(e) => {
            tracing::error!("Error retrieving identity: {}", e);
            (StatusCode::NOT_FOUND, e.to_string()).into_response()
        }
    }
}
