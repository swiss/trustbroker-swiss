-- Even though we do not use device and user tokens yet we need additional indexes
-- because the JdbcOAuth2AuthorizationService queries _all__ token value columns in
-- findByToken used in our /introspect and /revoke usecases.
-- Performance gain: 0.05s instead of 5s == factor 100 on /introspect and /revoke
CREATE INDEX idx_oauth2_authorization_state ON oauth2_authorization(state);
CREATE INDEX idx_oauth2_authorization_user_code_value ON oauth2_authorization(user_code_value);
CREATE INDEX idx_oauth2_authorization_device_code_value ON oauth2_authorization(device_code_value);
