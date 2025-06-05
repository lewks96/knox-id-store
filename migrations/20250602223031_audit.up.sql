-- Add up migration script here
CREATE TYPE identity_audit_event_type AS ENUM (
    'Created',
    'Updated',
    'Deleted',
    'Authenticated'
);

CREATE TABLE audit_events (
                                       id UUID PRIMARY KEY,
                                       identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                                       event_type identity_audit_event_type NOT NULL,
                                       event_data JSONB NOT NULL,
                                       created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
);
