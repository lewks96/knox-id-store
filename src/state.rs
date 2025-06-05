use crate::audit::audit::AuditStore;
use crate::config::Config;
use crate::store::identity_store::IdentityStore;

#[derive(Clone)]
pub struct AppState<Store, Audit>
where
    Store: IdentityStore,
    Audit: AuditStore,
{
    pub config: Config,
    pub id_store: Store,
    pub audit_store: Audit,
}
