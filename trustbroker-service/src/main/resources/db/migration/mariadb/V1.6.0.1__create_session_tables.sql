-- XTB has additional session keys as follows:
-- * Primary is the main XTB-x session we use to track CP-side state
-- * 2nd key SP side is for the request/response tracking (any SAML acceptable format)
-- * 2nd key SSO is the sso-X or tmp-X session 'index' we send as SAML attribute ssoSessionId
-- * 2nd key OIDC is the JSESSIONID used by the spring-authorization-server
-- select SESSION_ID,EXPIRATION_TIMESTAMP from TB_AUTH_SESSION_CACHE where DATA like '%testuser%';
CREATE TABLE TB_AUTH_SESSION_CACHE
(
	SESSION_ID           VARCHAR(255) PRIMARY KEY NOT NULL,
	SP_SESSION_ID        VARCHAR(255),
	SSO_SESSION_ID       VARCHAR(255),
	OIDC_SESSION_ID      VARCHAR(255),
	EXPIRATION_TIMESTAMP TIMESTAMP NOT NULL,
	DATA                 MEDIUMTEXT
) ENGINE = InnoDB;

-- 2nd key indexes
-- show indexes from TB_AUTH_SESSION_CACHE;
CREATE INDEX IDX_SP_SESSION_ID ON TB_AUTH_SESSION_CACHE(SP_SESSION_ID);
CREATE INDEX IDX_SSO_SESSION_ID ON TB_AUTH_SESSION_CACHE(SSO_SESSION_ID);
CREATE INDEX IDX_OIDC_SESSION_ID ON  TB_AUTH_SESSION_CACHE(OIDC_SESSION_ID);
-- session termination by reaper only
CREATE INDEX IDX_EXPIRATION_TIMESTAMP ON TB_AUTH_SESSION_CACHE(EXPIRATION_TIMESTAMP);
