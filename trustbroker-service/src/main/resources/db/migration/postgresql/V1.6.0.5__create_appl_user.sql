/*
Application user 'trustbroker' expected to be setup by installing the postgresql DB server.
The postgresql docker image does not support this concept but expects users to be created via SQL either as below
or via /docker-entrypoint-initdb.d/init.sql using a generated configuration for the password.
If trustbroker STATECACHE_PASS=secret was changed, DB setup needs to be fixed as follows for now:
Option 1: Use root instead of trustbroker in application.yml spring.datasource.username
          or docker_compose.yml SPRING_DATASOURCE_USERNAME
Option 2: docker exec -it postgresql psql --host=postgresql --port=5432 --dbname=tbss16 --username=root --password
          ALTER ROLE trustbroker WITH LOGIN PASSWORD 'secret';
*/

DO $$
BEGIN
   IF NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname = '${databaseUser}'
   ) THEN
CREATE ROLE ${databaseUser} WITH LOGIN PASSWORD '${databasePassword}';
GRANT USAGE ON SCHEMA ${databaseName} TO ${databaseUser};
GRANT SELECT, INSERT, UPDATE, DELETE ON TB_AUTH_SESSION_CACHE TO ${databaseUser};
GRANT SELECT, INSERT, UPDATE, DELETE ON TB_SAML_ARTIFACT_CACHE TO ${databaseUser};
GRANT SELECT, INSERT, UPDATE, DELETE ON TB_AUTH_JWK_CACHE TO ${databaseUser};
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth2_authorization TO ${databaseUser};
END IF;
END
$$;
