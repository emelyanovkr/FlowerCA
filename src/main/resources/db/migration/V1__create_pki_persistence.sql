CREATE TABLE ca_issuers (
    id BINARY(16) NOT NULL,
    name VARCHAR(100) NOT NULL,
    subject_dn VARCHAR(1024) NOT NULL,
    serial_number VARBINARY(20) NOT NULL,
    subject_key_identifier VARBINARY(64) NOT NULL,
    certificate_der MEDIUMBLOB NOT NULL,
    status VARCHAR(32) NOT NULL,
    not_before DATETIME(6) NOT NULL,
    not_after DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_ca_issuers PRIMARY KEY (id),
    CONSTRAINT uk_ca_issuers_name UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_profiles (
    id BINARY(16) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(320) NULL,
    role VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_user_profiles PRIMARY KEY (id),
    CONSTRAINT uk_user_profiles_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE certificates (
    id BINARY(16) NOT NULL,
    user_profile_id BINARY(16) NULL,
    issuer_id BINARY(16) NOT NULL,
    serial_number VARBINARY(20) NOT NULL,
    fingerprint_sha256 VARBINARY(32) NOT NULL,
    profile VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    subject_dn VARCHAR(1024) NOT NULL,
    certificate_der MEDIUMBLOB NOT NULL,
    not_before DATETIME(6) NOT NULL,
    not_after DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revocation_reason VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_certificates PRIMARY KEY (id),
    CONSTRAINT fk_certificates_user_profile
        FOREIGN KEY (user_profile_id) REFERENCES user_profiles (id),
    CONSTRAINT fk_certificates_issuer
        FOREIGN KEY (issuer_id) REFERENCES ca_issuers (id),
    CONSTRAINT uk_certificates_issuer_serial UNIQUE (issuer_id, serial_number),
    CONSTRAINT uk_certificates_fingerprint_sha256 UNIQUE (fingerprint_sha256),
    INDEX ix_certificates_user_status (user_profile_id, status),
    INDEX ix_certificates_status_not_after (status, not_after)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_events (
    id BINARY(16) NOT NULL,
    actor_profile_id BINARY(16) NULL,
    actor_certificate_id BINARY(16) NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id BINARY(16) NULL,
    result VARCHAR(32) NOT NULL,
    details JSON NULL,
    occurred_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_audit_events PRIMARY KEY (id),
    INDEX ix_audit_events_occurred_at (occurred_at),
    INDEX ix_audit_events_target (target_type, target_id),
    INDEX ix_audit_events_actor (actor_profile_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
