use tonic::{transport::Server, Request, Response, Status};
use crate::store::identity_store::{IdentityStore as StoreTrait, PgIdentityStore};

pub mod identity_service {
    tonic::include_proto!("identity");
}

use identity_service::identity_service_server::{IdentityService, IdentityServiceServer};
use crate::audit::audit::{AuditStore, PgAuditStore};
use crate::errors::AppError::ApiError;
use crate::grpc::identity_service::{AuthenticateRequest, ChangeEmailRequest, ChangeUsernameRequest, CreateIdentityRequest, DeleteIdentityRequest, GetIdentityByEmailRequest, GetIdentityByIdRequest, GetIdentityByUsernameRequest, GetIdentityResponse, Identity, IdentityResponse, ResetPasswordRequest, SetActiveRequest, SetEnabledRequest, SetVerifiedRequest, UpdateIdentityRequest};
use crate::state::AppState;
use crate::store::types::CreateIdentityPayload;

pub struct MyIdentityService  {
    state: AppState<PgIdentityStore, PgAuditStore>,
}

impl MyIdentityService {
    pub fn new(state: AppState<PgIdentityStore, PgAuditStore>) -> Self {
        MyIdentityService { state }
    }
}

#[tonic::async_trait]
impl IdentityService for MyIdentityService {
    async fn create_identity(&self, request: Request<CreateIdentityRequest>) -> Result<Response<IdentityResponse>, Status> {
        let payload = request.into_inner().payload.unwrap();
        let identity = crate::identity::create_identity_from_dto(payload.into(), &self.state.id_store, &self.state.audit_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to create identity: {}", e)));

        match identity {
            Ok(identity) => {
                Ok(Response::new(IdentityResponse{
                    identity: Some(identity.into()),
                }))
            }
            Err(e) => Err(e),
        }
    }

    async fn get_identity_by_id(&self, request: Request<GetIdentityByIdRequest>) -> Result<Response<GetIdentityResponse>, Status> {
        let id = request.into_inner().id;
        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        let identity = crate::identity::get_identity_by_id(id, &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to get identity: {}", e)))?;
        match identity {
            Some(identity) => {
                Ok(Response::new(GetIdentityResponse {
                    identity: Some(identity.into()),
                }))
            }
            None => {
                Err(Status::not_found(format!("Identity with ID {} not found", id)))
            }
        }
    }

    async fn get_identity_by_username(&self, request: Request<GetIdentityByUsernameRequest>) -> Result<Response<GetIdentityResponse>, Status> {
        let username = request.into_inner().username;
        let identity = crate::identity::get_identity_by_username(username.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to get identity: {}", e)))?;

        match identity {
            Some(identity) => {
                Ok(Response::new(GetIdentityResponse {
                    identity: Some(identity.into()),
                }))
            }
            None => {
                Err(Status::not_found(format!("Identity with username {} not found", username)))
            }
        }
    }

    async fn get_identity_by_email(&self, request: Request<GetIdentityByEmailRequest>) -> Result<Response<GetIdentityResponse>, Status> {
        let email = request.into_inner().email_address;
        let identity = crate::identity::get_identity_by_email(email.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to get identity: {}", e)))?;

        match identity {
            Some(identity) => {
                Ok(Response::new(GetIdentityResponse {
                    identity: Some(identity.into()),
                }))
            }
            None => {
                Err(Status::not_found(format!("Identity with email {} not found", email)))
            }
        }
    }

    async fn update_identity(&self, request: Request<UpdateIdentityRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, payload) = (inner.id, inner.updates);
        
        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;
        let payload = payload.ok_or_else(|| Status::invalid_argument("Update payload is required"))?;

        let identity_update = crate::identity::update_identity(id, payload.into(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to update identity: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity_update.into()),
        }))
    }

    async fn delete_identity(&self, request: Request<DeleteIdentityRequest>) -> Result<Response<()>, Status> {
        let id = request.into_inner().id;
        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        crate::identity::delete_identity(id, &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete identity: {}", e)))?;

        Ok(Response::new(()))
    }

    async fn authenticate(&self, request: Request<AuthenticateRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, password) = (inner.id, inner.password);

        if id.is_empty() || password.is_empty() {
            return Err(Status::invalid_argument("Username and password must be provided"));
        }
        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format for ID"))?;

        let identity = crate::identity::authenticate(id, password.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Authentication failed: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn set_active(&self, request: Request<SetActiveRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, is_active) = (inner.id, inner.is_active);

        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        let identity = crate::identity::set_active(id, is_active, &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to set active status: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn set_verified(&self, request: Request<SetVerifiedRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, is_verified) = (inner.id, inner.is_verified);

        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        let identity = crate::identity::set_verified(id, is_verified, &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to set verified status: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn set_enabled(&self, request: Request<SetEnabledRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, is_enabled) = (inner.id, inner.is_enabled);

        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        let identity = crate::identity::set_enabled(id, is_enabled, &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to set enabled status: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn reset_password(&self, request: Request<ResetPasswordRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, new_password) = (inner.id, inner.new_password);

        if id.is_empty() || new_password.is_empty() {
            return Err(Status::invalid_argument("ID and new password must be provided"));
        }
        
        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format for ID"))?;

        let identity = crate::identity::reset_password(id, new_password.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to reset password: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn change_email(&self, request: Request<ChangeEmailRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, email) = (inner.id, inner.new_email_address);

        if id.is_empty() || email.is_empty() {
            return Err(Status::invalid_argument("ID and email must be provided"));
        }

        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format for ID"))?;

        let identity = crate::identity::change_email(id, email.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to change email: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }

    async fn change_username(&self, request: Request<ChangeUsernameRequest>) -> Result<Response<IdentityResponse>, Status> {
        let inner = request.into_inner();
        let (id, username) = (inner.id, inner.new_username);

        if id.is_empty() || username.is_empty() {
            return Err(Status::invalid_argument("ID and username must be provided"));
        }

        let id = uuid::Uuid::parse_str(&id)
            .map_err(|_| Status::invalid_argument("Invalid UUID format for ID"))?;

        let identity = crate::identity::change_username(id, username.as_str(), &self.state.id_store)
            .await
            .map_err(|e| Status::internal(format!("Failed to change username: {}", e)))?;

        Ok(Response::new(IdentityResponse {
            identity: Some(identity.into()),
        }))
    }
}