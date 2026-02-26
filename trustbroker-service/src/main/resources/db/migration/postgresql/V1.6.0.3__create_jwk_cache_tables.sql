-- JWK set rotated by the JwkCacheService according based on keySchedule
CREATE TABLE TB_AUTH_JWK_CACHE
(
	KEY_ID               VARCHAR(255) PRIMARY KEY NOT NULL,
	EXPIRATION_TIMESTAMP TIMESTAMP                NOT NULL,
	DELETION_TIMESTAMP   TIMESTAMP                NOT NULL,
	DATA                 TEXT
);

-- 2nd key indexes
-- key rollover job
CREATE INDEX IDX_TB_AUTH_JWK_CACHE_EXPIRATION_TIMESTAMP ON TB_AUTH_JWK_CACHE(EXPIRATION_TIMESTAMP);
