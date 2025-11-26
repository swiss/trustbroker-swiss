/*
Application user 'trustbroker' expected to be setup by installing the mariadb DB server.
Using root always works otherwise but is not security best practice.
*/
DELIMITER $$
CREATE PROCEDURE ${databaseName}.autoConfigureTrustbrokerUser()
BEGIN
	SET @userCount := 0;
	SELECT COUNT(*) INTO @userCount FROM mysql.user WHERE user = 'trustbroker' AND host = '%';
	IF @userCount > 0 THEN
		GRANT SELECT, INSERT, UPDATE, DELETE ON ${databaseName}.TB_AUTH_SESSION_CACHE TO 'trustbroker'@'%';
		GRANT SELECT, INSERT, UPDATE, DELETE ON ${databaseName}.TB_SAML_ARTIFACT_CACHE TO 'trustbroker'@'%';
		GRANT SELECT, INSERT, UPDATE, DELETE ON ${databaseName}.TB_AUTH_JWK_CACHE TO 'trustbroker'@'%';
		GRANT SELECT, INSERT, UPDATE, DELETE ON ${databaseName}.oauth2_authorization TO 'trustbroker'@'%';
		FLUSH PRIVILEGES;
	END IF;
END $$
DELIMITER ;
CALL ${databaseName}.autoConfigureTrustbrokerUser();
