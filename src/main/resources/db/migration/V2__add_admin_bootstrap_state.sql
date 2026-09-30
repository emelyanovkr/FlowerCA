CREATE TABLE admin_bootstrap_state (
    name VARCHAR(64) NOT NULL,
    user_profile_id BINARY(16) NULL,
    certificate_id BINARY(16) NULL,
    completed_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_admin_bootstrap_state PRIMARY KEY (name),
    CONSTRAINT fk_admin_bootstrap_user_profile
        FOREIGN KEY (user_profile_id) REFERENCES user_profiles (id),
    CONSTRAINT fk_admin_bootstrap_certificate
        FOREIGN KEY (certificate_id) REFERENCES certificates (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
