-- JWT cache for all token types, specifically required for long-term refresh_token handling
CREATE TABLE oauth2_authorization
(
	id                            VARCHAR(100) PRIMARY KEY NOT NULL,
	registered_client_id          VARCHAR(100) NOT NULL,
	principal_name                VARCHAR(200) NOT NULL,
	authorization_grant_type      VARCHAR(100) NOT NULL,
	authorized_scopes             VARCHAR(1000) DEFAULT NULL,
	attributes                    TEXT          DEFAULT NULL,
	state                         VARCHAR(500)  DEFAULT NULL,
	authorization_code_value      TEXT          DEFAULT NULL,
	authorization_code_issued_at  TIMESTAMP,
	authorization_code_expires_at TIMESTAMP,
	authorization_code_metadata   TEXT          DEFAULT NULL,
	access_token_value            TEXT          DEFAULT NULL,
	access_token_issued_at        TIMESTAMP,
	access_token_expires_at       TIMESTAMP,
	access_token_metadata         TEXT          DEFAULT NULL,
	access_token_type             VARCHAR(100)  DEFAULT NULL,
	access_token_scopes           VARCHAR(1000) DEFAULT NULL,
	oidc_id_token_value           TEXT          DEFAULT NULL,
	oidc_id_token_issued_at       TIMESTAMP,
	oidc_id_token_expires_at      TIMESTAMP,
	oidc_id_token_metadata        TEXT          DEFAULT NULL,
	refresh_token_value           TEXT          DEFAULT NULL,
	refresh_token_issued_at       TIMESTAMP,
	refresh_token_expires_at      TIMESTAMP,
	refresh_token_metadata        TEXT          DEFAULT NULL,
	-- unused by XTB, no indexes
	user_code_value               TEXT          DEFAULT NULL,
	user_code_issued_at           TIMESTAMP,
	user_code_expires_at          TIMESTAMP,
	user_code_metadata            TEXT          DEFAULT NULL,
	device_code_value             TEXT          DEFAULT NULL,
	device_code_issued_at         TIMESTAMP,
	device_code_expires_at        TIMESTAMP,
	device_code_metadata          TEXT          DEFAULT NULL
);

-- 2nd key indexes on data we actually use
-- Key length is required: BLOB/TEXT column '...' used in key specification without a key length
-- 255 is a sufficient prefix for the tokens to get to a distinctive part after the header
CREATE INDEX idx_oauth2_authorization_authorization_code_value ON oauth2_authorization(authorization_code_value);
CREATE INDEX idx_oauth2_authorization_access_token_value ON oauth2_authorization(access_token_value);
CREATE INDEX idx_oauth2_authorization_oidc_id_token_value ON oauth2_authorization(oidc_id_token_value);
CREATE INDEX idx_oauth2_authorization_refresh_token_value ON oauth2_authorization(refresh_token_value);
-- session termination (logout, reap)
CREATE INDEX idx_oauth2_authorization_client_principal ON oauth2_authorization(principal_name, registered_client_id);
CREATE INDEX idx_oauth2_authorization_authorization_expires_at ON oauth2_authorization(access_token_expires_at);
