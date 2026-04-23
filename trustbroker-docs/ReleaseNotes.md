# Unreleased Versions

# 1.15.0 (2026-08)

### Improvements
- SAML:
  - Validation improvements.
- Security:
  - Disable API controllers of unused features. SSO, profile selection, announcements, monitoring need to be enabled explicitly if used.
  - Server-side rendering of skinny HRD.
- Config:
  - Improved profile merging for attributes with defaults.

### Bugfixes
- Config:
  - Fix duplicated Gauge registration warning.

# 1.14.0 (2026-05)

### Dependency upgrades

- Backend:
  - JDK 21.0.10
  - Spring Boot 3.5.13
  - Spring Cloud 2025.0.1
  - nimbus-jose-jwt 9.48
  - JGit 7.5.0.202512021534-r
  - CXF 4.2.0
  - commons-text 1.15.0
  - commons-lang3 3.20.0
  - commons-io 2.21.0
  - mariadb-java-client 3.5.7
  - PostgreSQL 42.7.10
  - Groovy 4.0.30
  - Bouncy Castle 1.83
- Frontend:
  - Angular 20.3.17
  - Oblique 14.2.1
  - npm 11.8.0

### Features
- UI:
  - Removal of the old tile-based HRD.
    CSS files in config may need to be adapted due to this!
  - Removal of old skinny HRD templates including the one with image support.
  - New notice page for CPs on HRD.

### Improvements
- OIDC:
  - Improvements for grant type token exchange.
- LDAP:
  - Organizational profile selection.
  - Switch to osixia openldap image.
- Attributes:
  - Option to make individual attributes mandatory.
- Cookies:
  - Same site now also considers Sec-Fetch-Site.
- UI:
  - Remove unused fonts.scss.
- Config:
  - Support Spring property references in XML configuration files.
  - Support loading certificates from paths outside the Git configuration.
- Security:
  - Hardening of protocol endpoints: WS-Trust and WS-FED are now disabled by default and need to be enabled explicitly.

### Bugfixes
-OIDC:
 - Fix handling of missing userinfo endpoint in CP.
 - Fix warnings in logs on configuration reload.
 - Allow token introspection between clients in the same SetupRP.
- WSTrust:
  - Accept RST ISSUE envelope signed by assertion issuer.
- DB:
  - Fixed BLOB type for PostgreSQL.

## 1.13.0.20260317T170552Z

### Features
- Git:
  - Aligned source, doc, and GitOps repository names.

### Bugfixes
- SAML:
  - Fixed InResponseTo validation, can be disabled via configuration.

## 1.13.0.20260316T084959Z

### Improvements
- UI: 
  - Skinny HRD files are now blocked if not enabled. Dropped old variants. Skinny HRD is disabled by default now.

### Bugfixes
- UI:
  - Fixed injection issue.

# Released Versions

## 1.13.0.20260306T105516Z

### Dependency upgrades

- Backend:
  - JDK 21
  - Spring Boot 3.5.7
  - nimbus-jose-jwt 9.47
- Frontend:
  - Angular 19.2.17
  - npm 11.6.4

### Features
- OIDC:
  - Support for grant type token exchange (disabled by default). This feature is still in beta stage with 1.13.0, do not enable it in production.
- WS-Fed:
  - Basic support for SignIn / SignOut (disabled by default).
- Database:
  - Add PostgreSQL.
- Test:
  - Support manipulations on final messages via global script - can be used e.g. to simulate invalid respones towards counter parties for security testing.

### Improvements
- OIDC:
  - Restrict default OIDC metadata grant_types_supported, revocation_endpoint_auth_methods_supported, introspection_endpoint_auth_methods_supported to the ones officially supported in XTB.
  - Option to only accept signed JWT response from backchannel userinfo call.
- SAML:
  - SecutityPolicies.requireSignedLogoutRequest now defaults to requireSignedAuthnRequest.
- WSTrust:
  - The protocol is now disabled by default.
  - Additional config options to apply IP and network based restrictions.
- DB:
  - Improve transaction boundaries for DB state access.
- IDM:
  - LDAP improvements and documentation.
- SSO:
  - Allow picking another claim than the subject from CP response to allow SSO using SubjectName with scope=SSO.
- LDAP:
  - Improved profile selection support.
  - Switched to osixia/openldap:stable image.
- UI:
  - Support banners without entry in application.yml.
  - Support HTML tags in banner subtitle too.
  - Path of internal UI APIs cleaned up.
- Announcements:
  - CP based announcements are now filtered based on the RP's CP mappings.
  - Disable continue button for global announcements.

### Bugfixes
- SSO:
  - Fix SSO join issue with CP that responds with another ID than requested (e.g. SamlMock).
  - Fix too strict subject name check issue for CP with SubjectNameMapping.
  - Fix QoA check with OIDC using RP config QoA instead of QoA from state.
  - Fix join via OIDC of session established via SAML.
- WSTrust:
  - Recipient in Issue RSTR was set to issuer in 1.12.0, revert to 1.11.0 behavior.
  - Fixed signature validation of RST ISSUE.
- Scripting:
  - If scripts abort the flow in BeforeIdm hook, JIT provisioning and other processing is aborted.
- UI:
  - Fixed injection issue.

## 1.12.0.20260129T105917Z

### Bugfixes
- SAML:
  - Fixed SAML request validation issue for redirect binding
- OIDC:
  - Unsigned JWT tokens received through backchannel connection are no longer accepted
- WSTrust:
  - doSignResponse disabled by default - enabling requires a p12 certificate and password
- LDAP:
  - Fix encoding of CP response parameters
- SSO:
  - Fix logout redirect URL on SSO screen
- License:
  - Remove AGPL template part describing how to adapt the template

### Improvements
- OIDC:
  - Metadata defaults for grantTypes, introspectionEndpointAuthMethods, revocationEndpointAuthMethods matching supported values
- SAML:
  - SamlMock now supports samples structured in directories and configuration of the buttons to be shown
  - Optional trust anchor for SAML requests for test automation or monitoring

## 1.12.0.20251125T141545Z

### Bugfixes
- SAML:
  - The special origin value 'null' is accepted a valid origin with validateHttpHeaders=true

### Improvements
- SAML:
  - The new ClaimsParty.ResponseIssuer can be set to decouple the CP response issuer from the ID.
- WSTrust:
  - Option to sign WS-Trust RSTR responses
  - Option to validate WS-Trust RENEW request

## 1.12.0.20251003T122936Z

### Dependency upgrades

- Backend - minor version upgrades:
  - Spring Boot 3.5.6
  - owasp.dependencycheck 12.1.3
  - github.node-gradle.node 7.1.0
  - google.cloud.tools.jib 3.4.5
- Frontend - major version upgrades:
  - Angular 19.2.4 
  - Oblique 13.3.3
  - CSS files in config may need to be adapted due to this!

### Features
- SAML:
  - Support SOAP 1.1 binding for LogoutRequest

### Improvements
- OIDC:
  - Cache RP side OIDC configurations used for JWE (JSON Web Encryption) 
  - Add encryption algorithms and methods to metadata
- SAML:
  - Allow validation of origin/referer HTTP headers against ACWhitelist with validateHttpHeaders=true for AuthnRequests
  - Allow restricting bindings via SupportedBinding
  - Added forwardRpProtocolBinding to control forwarding the ProtocolBinding from RP to CP
- WSTrust:
  - Support ADFS compatibility URL /adfs/services/trust
  - Support configuration of wsBasePath without hardcoded postfix
  - Include SSO session ID in SessionIndex of RENEW response assertion
  SSO:
  - Use SessionIndex from LogoutRequest locate as fallback to find SSO session
- IDM:
  - LDAP filtering improvements supporting '*' as wildcard and 'IDM:query_name:definition_name'
- QoA:
  - Add specifig NoAuthnContext error screen for QoA issues    
- UI:
  - Render header buttons in the configured order to avoid use of tabIndex

### Bugfixes
- Config:
  - Fixes copying of some AccessRequest, ProfileSelection and Announcement properties from profile to RP
  - SetupRP can now reference keystores in SetupRP's sub-path of keystores directory without specifiying the path, as specified
  - Merge SAML Qoa with OIDC Qoa
- OIDC:
  - Fixed double quoted encrypted userinfo response
  - Fixed processing of multiple space-separated acr_values
  - Using correct private key for decryption of encrypted internal SAML messages
- WSTrust:
  - Fixed validation and response issues in WSTrust RENEW request
- SSO:
  - Fix NPE in SSO session checking when SAML SessionIndex is used
  - Joining was not possible if the initiating paricipant did not sign the AuthnRequest
  - Logout notifications are now enabled by default when the configuration contains SloResponse entries for notifications
- QoA:
  - Use correct QoA config for OIDC side CP check

## 1.11.0.20250911T090750Z

### Dependency upgrades

- Backend - minor version upgrades:
  - Spring Boot 3.5.3
  - Spring Cloud 2025.0.0
  - JGit 7.3.0.202506031305-r
  - commons-beanutils 1.11.0 

### Features
- OIDC:
  - Support for JWE (JSON Web Encryption) 
  - Fetching of OIDC client metadata for encryption key discovery
- WSTrust:
  - Support for RENEW request if enabled (not yet fully functional in this release)
- IDM:
  - Improvements for LDAP IDM interface

### Improvmements
- Config:
  - IDM implementations can now be selected per query, allowing multiple implementations per RP
- SAML:
  - Allow AuthnRequest without AssertionConsumerServiceURL if enabled via AcWhitelist useDefault=true
- SSO:
  - Allow jointing SSO sessions with unsigned AuthnRequest if either requireSignedAuthnRequest=false or the new flag requireSignedAuthnRequestForSsoJoin=false
- QoA:
  - QoA handling is stricted with global policy enforceQoaIfMissing=true
  - Support downgrade CP response QoA to highest QoA requested by RP via downgradeToMaximumRequested
- Scripting:
  - CPResponse Groovy hook API methods aligned between all claim sources
  - Allow scripts to add parameters to OIDC CP authorization requests via context RpRequest.CONTEXT_OIDC_AUTHORIZATION_QUERY_PARAMETER
  - AfterProvisioning script hook added

### Bugfixes
 - Config:
   - Fixed SubjectNameMappings for CP IDs that contain colons
 - OIDC:
   - The state parameter is now sends back to OIDC client on SAML responder errors
   - Multiple OIDC acr_values are now correctly handled as space separated, not comma separated
 - SAML:
   - AuthnStatement now contains the (optional but recommended) SessionNotOrAfter timestamp
   - Fixed serialization issue in SamlMock artifact cache
- SSO:
   - SessionNotOnOrAfter now considers refresh_token activity on the SSO session
   - No longer allow SSO if the AuthnRequest contains an invalid signature
 - QoA:
   - QoA enforcement now blocks properly in all cases also on RP side 

## 1.10.0.20250707T135922Z

### Dependency upgrades

- Spring Boot 3.4.5

### Features

- OIDC CP support finalized.
- HRD: Add support for multiple ClaimsProviderDefinition.xml
- HRD: Configurable HTTP query parameter to select a CP.
  - In addition to CP.id also matched against CP.name or new CP.hrdHintAlias from the ClaimsProviderDefinition.xml for decoupling.
- First shot at an LDAP implementation of the IDM interface.

### Improvements

- Check Javadoc entries "@since 1.10.0" for details on new configuration options.
- New flag SecurityPolicies.ForceAuthn (RP or CP side) to enforce re-authentication on CP for CPs that cache the login state in the browser (defaulting to true for CPs).
- XTB frontend resources can now be cached by the browser.
- Added resilience support on StateCacheService and OAuth2AuthorizationService  with configurable delay and retries (see StateCacheProperties).
- SAML:
    - Support SAML redirect binding for logout notifications and LogoutResponse: SloResponse binding=”REDIRECT”
    - New options to control signature and encryption of messages / assertions.
    - Support optional inline encryption key placement.
- New date and time mappers for attributes:
  - Definition.mappers TIME_ISO, DATE_ISO, DATE_LOCAL and support parsing of these date/time formats and parsing from ISO date without time zone and from format 01.01.2000 [00:00:00]
  - Definition.mappers STRING, IGNORE
- HRD: Provide more information for unavailable CPs in a popover.
- Block OIDC redirect URIs that contain a user info part (...@).
- Script API improvements:
  - CPResponse.setAttribute/setAttribute s improved to just update the values and keep other settings of Definition
- Merge QoA from ProfileRP when QoA list in SetupRP is empty to allow using the same default model.
- OIDC CP mock claims now configurable in application.yaml
- New FlowPolicies.link to show a button with a link to an application page.
- New options for Qoa configuration to control handling of inbound values.

### Bugfixes

- Fix application.yml reload after Git changes by replacing spring-cloud-starter-bootstrap with spring-cloud-starter.
- SAML metadata fixes:
  - ArtifactResolution service only shown if binding is enabled
  - Encryption metadata shows correct certificates
- Ignore special QoA values like StrongestPossible for minimum/maximum calculations.
- Ignore urltester on Internet access.
- Fixes and layout improvements for new HRD.
- Accept HTTP X-Request-Id being a UUID as some /robots.txt endpoints do not use hex32 but uuid32.
- Fix broken SAML mock artifact cache


## v1.9.0.20250515T072935Z

### Bugfixes

 - Fix oauth2_authorization table not reap of unfinished authorizations or ones missing a refresh token (i.e. rows with NULL values).
   Note: This was not changed in 1.9.0 compared to previous releases.
   So depending on the database setup this could lead to leaking rows in earlier releases as well.


## v1.9.0.20250415T132527Z

### Dependency upgrades

- Spring Boot 3.4.4
- Spring Security 6.4.4
- Apache CXF 4.0.6
- Angular 18.2
- Oblique 11.3.4

### Features:

- New HRD layout:
  - Configurable banners on top.
  - Tiles grouped by configured order.
  - Disabled per default (GUI feature HRD_BANNERS, ClaimsProvider.order).
  - The old layout will be removed earliest in 1.12.0.

- QoA mapping and optional enforcement from/to RP and CP:
  - QoA element for ClaimsParty/RelyingParty.
  - HRD disabling CPs with insufficient requested and enforced QoA

- HRD CP mappings can now be configured in ProfileRP and can be picked in SetupRP by using the new enabled=true flag on any of the configured ClaimsProviderMappings entries.
- First shot at OIDC protocol provider support towards CPs, not yet functional end-to-end.
- OIDC CP mock to generate OIDC tokens for automated testing.

### Improvements

- Browser support: Add polyfills for older browser versions – last 4 Chrome/FF/Edge and last 5 Safari versions.
- To prevent unnecessary pod restarts when the infrastructure has problems, configure and use /actuator/health/readiness and /actuator/health/liveness probes.
  - Added timing information for readiness/liveness probes.
- Error handling of ‘state not found’ exceptions was improved in the global exception handler allowing to configure a separated error message and user flow.
- Claims mapping: The new ClaimsSelection can be used to aggregate all claims sources using Definition source instead.
  - Supported sources are CP, IDM, IDM:queryname, SCRIPT (when groovy scripts manipulate IDM claims), PROPS, and CONFIG
  - The ConstAttributes section was deprecated and can be replaced by ClaimsSelection specifying the value in the configuration. The CONFIG source is used to identify these claims.
- SAML RP side dynamic SAML AuthnRequest.ProtocolBinding supported instead of assuming a fixed configuration in XTB.
- WS-Trust clock skew supported to handle clients using system clocks running in the future (the same skew configuration than for SAML protocol is used).
- OIDC QoA and state handling was improved by using the spring-security continue marker (identifying an ongoing login) and in addition supporting acr_values as a trigger to check for SSO and step-up in addition to the already implemented prompt=login support. Forcing a login can therefore also be done with the acr_values in the authorize request.
- HRD handles disabled CPs now in rendering (e.g. controlled via announcements).
- Script API: Scripts can skip/enforce features via CPResponse/RPRequest
- Reduce unnecessary warnings in logs.

### Bugfixes

- Invalidate XTB session in case of session compatibility issues between XTB releases.
- Script based CPResponse flow policy shows support info on error screens.
- Error screen with ‘Continue to application’ now also works without a state (before user was stuck on the screen).
- OIDC logout: Consider realm logout requests without a client_id parameter to address ambiguities between multiple SetupRP that contain the same redirect_uri
- Retry to handle 'SAML AuthnRequest state lost' problem when establishing OIDC session on redirect from SAML to OIDC sub-system
- Fix reset of selected profile when logging in with a new RP using SSO.

### Security

- Validate OIDC error redirect URIs against config for error redirects as well.


## v1.8.0.20250218T172031Z

### Improvements

- New parameters to control OIDC refresh token lifetime.
- _SubjecNameMappings_ now configurable on both RP and CP side.
- Flow policies support direct redirects.
- _OpsDebug_ feature improved allowing customization of log levels.
- Script compilation errors are now reflected on status API.
- Script hook _BeforeResponse_ added to allow scripts on the complete, yet unfiltered output data.
- new _OpsAudit_ logging allows controlling what data is audited.
- Dependencies updated.
    
### Fixes

- OIDC setup without client secret addressed with a private _authorization_code_ lead to HTTP 302 instead of 401.
- Fix selection of default language if there is no language cookie.


## v1.7.0.20241021T070518Z

### Improvements

- Error page is now sent as JSON if any of the HTTP headers configured in _trustbroker.config.oidc.jsonErrorPageHeaders_ matches.
- Error logging cleanup.
- _RPRequest_ (with _rpIssuer_, _applicationName_, _contextClasses_, _referer_) object is now available to script hooks in the response phase.
    
### Fixes

- Disable Spring in-memory session storage that led to a memory leak causing out of memory conditions under load.
- _refresh_token_ expiration was not considered during reaping of OIDC tokens.


## v1.7.0.20240926T102809Z

### Features

- XML configurations can now be structured into nested directories.
- Configurable support debug feature added to produce DEBUG logs if signaled via HTTP protocol.
- Micrometer for Prometheus monitoring.
- New APIs:
  - _/api/v1/config/status_ to report broken configurations (access restricted to internal network).
  - _/api/v1/config/schemas/{file}_ provides current configuration XSDs (access restricted to internal network).
  - _/api/v1/version_ showing the deployed version.

###  Improvements

- OIDC:
  - New attribute mapper for e-mail with lower case transformation and de-duplication.
  - Fragment _redirect_uri_ handling supports arbitrary non-RFC3986 compliant query and fragment parameters now (caused breaking applications using deep-links with parameters).
  - SSO cookie also set on OIDC domain for improved global logout handling.
- Tracing: 
  - OpenTelemetry-aligned conversation ID support added.
  - Additional HTTP protocol detail logging can be enabled if a conversation ID is defined.
- Markup/markdown support for translations improved to allow sanitized HTML and markdown links (except in top level titles, button names, labels). 
- Upgrade to latest JDK/17, Spring Boot, Oblique.

### Fixes

- OIDC:
  - Fixed issues in session probing with _prompt=none_.
  - Fixed device ID check breaking SSO with OIDC session joiners. This also fixes a potential performance issue.
  - Fixed performance issues on /introspect and /revoke (additional indexes on _oauth2_authorization_ table).
  - _redirect_uri_ containing non-existing DNS endpoints could result in 15 to 25 seconds timeouts on validation.
- Fixed issue on bootstrap for not yet existing keystore.
- Fixed _RequestDeniedException_ log message _cpIssuer=null_.

### Compatibility

- Check for _Potentially breaking changes_ Javadoc comments in _trustbroker/federation/xmlconfig_ and _trustbroker/config_:
  - Some additional XML values are now validated via XSD.
  - The new _trustbroker.config.globalScriptPath_ was formerly included in the default _trustbroker.config.scriptPath_.


## v1.6.0.20240819T100141Z

Initial open sourcing release of trustbroker.swiss.
