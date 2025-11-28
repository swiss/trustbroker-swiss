-- Even though we do not use device and user tokens yet we need additional indexes
-- because the JdbcOAuth2AuthorizationService queries _all__ token value columns in
-- findByToken used in our /introspect and /revoke usecases.
-- mariadb selects an execution plan on the table instead of the indexes in this case.
-- Performance gain: 0.05s instead of 5s == factor 100 on /introspect and /revoke
CREATE INDEX idx_state ON oauth2_authorization(state(255));
CREATE INDEX idx_user_code_value ON oauth2_authorization(user_code_value(255));
CREATE INDEX idx_device_code_value ON oauth2_authorization(device_code_value(255));
