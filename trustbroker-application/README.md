# Swiss Trustbroker Application (XTB)

Spring-boot microservice implementing SAML brokerage between relying parties (RP) and claim providers (CP).
In the Oasis SAML terminology we are an IdP from the RP side and an SP towards the IdPs we integrate.

The service provides these main services:

- / only maps the favicon.ico and index.html
- /app contains the angular frontend
- /api/v1 provides the REST API for the application and the SAML endpoints
- /oauth2, /login and /userinfo provide OIDC service endpoints

Configuration is done via spring-profiles and a bootstrap based on these ENV variables:

- GIT_URL to fecth the runtime configuration for dispatching and HRD
- TRUSTBROKER_HOME as a configuration cache and providing the SSH key to contact GIT (see ../config/env.proj for DEV details)


