use std::net::SocketAddr;
use crate::audit::audit::PgAuditStore;
use crate::errors::AppError::ApiError;
use crate::identity::create_identity_from_dto;
use crate::store::identity_store::{IdentityStore, PgIdentityStore};
use crate::store::types::{CreateIdentityPayload, Identity};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router, response::IntoResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::any::install_default_drivers;
use state::AppState;
use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic_reflection::server::Builder;
use uuid::Uuid;
use crate::grpc::identity_service::identity_service_server::IdentityServiceServer;
use crate::grpc::MyIdentityService;

mod audit;
mod config;
mod errors;
mod identity;
mod state;
mod store;
mod routes;
mod grpc;

async fn health_probe() -> impl IntoResponse {
    (StatusCode::OK, "OK").into_response()
}

#[tokio::main]
async fn main() {
    let config = config::Config::from_env().expect("Failed to load config");
    tracing_subscriber::fmt()
        .with_max_level(config.log_level.parse().unwrap_or(tracing::Level::INFO))
        .init();

    let pool = PgPool::connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    let pg_store = PgIdentityStore::new(pool.clone());
    let pg_audit_store = PgAuditStore::new(pool.clone());

    let state = AppState {
        config: config.clone(),
        id_store: pg_store.clone(),
        audit_store: pg_audit_store,
    };

    const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/identity_descriptor.bin"));

    let reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1alpha().unwrap();

    tracing::info!("Starting knox-id-store");

    let identity_service = MyIdentityService::new(state.clone());

    let addr = "[::1]:50051".parse().unwrap(); // Standard gRPC address

    let r = Server::builder()
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(reflection_service)
        .serve(addr)
        .await;

    match r {
        Ok(_) => tracing::info!("gRPC server started successfully"),
        Err(e) => tracing::error!("Failed to start gRPC server: {}", e),
    }
    //let app = Router::new()
    //    .route("/health", get(health_probe))
    //    .route("/identity", post(routes::create_identity_route))
    //    .route("/identity/{user_id}", get(routes::get_identity_by_uuid_route))

    //    .with_state(state);

    //let listener = TcpListener::bind(format!("{}:{}", config.http_host, config.http_port))
    //    .await
    //    .expect("Failed to bind TCP listener");

    //axum::serve(listener, app)
    //    .await
    //    .expect("Failed to start server")
}
