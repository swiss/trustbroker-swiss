-- Large tokens lead to problems with the btree index of postgressql, use a HASH index instead.
-- HASH indexes are valid for equal comparisons but range queries do not work that way.
-- Use HASH index only for tokens that can grow large e.g. by adding many claims. Performance usually better on btree index.

DROP INDEX IF EXISTS idx_oauth2_authorization_access_token_value;
CREATE INDEX idx_oauth2_authorization_access_token_value ON oauth2_authorization USING HASH(access_token_value);

DROP INDEX IF EXISTS idx_oauth2_authorization_oidc_id_token_value;
CREATE INDEX idx_oauth2_authorization_oidc_id_token_value ON oauth2_authorization USING HASH(oidc_id_token_value);
