-- Add down migration script here
DROP TABLE IF EXISTS audit_events;
DROP TYPE IF EXISTS identity_audit_event_type;