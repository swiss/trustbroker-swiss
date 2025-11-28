# Unreleased Versions


## 1.13.0

### Dependency upgrades

- Backend:
  - JDK 21
  - Spring Boot 3.5.7
  - nimbus-jose-jwt 9.47

### Features
- Test:
  - Support manipulations on final messages via global script - can be used e.g. to simulate invalid respones towards counter parties for security testing.

### Improvements
- OIDC:
  - Restrict default OIDC metadata grant_types_supported, revocation_endpoint_auth_methods_supported, introspection_endpoint_auth_methods_supported to the ones officially supported in XTB.
- SAML:
  - SecutityPolicies.requireSignedLogoutRequest now defaults to requireSignedAuthnRequest
- DB:
  - Improve transaction boundaries for DB state access.
- IDM:
  - LDAP improvements and documentation.
- SSO:
  - Allow picking another claim than the subject from CP response to allow SSO using SubjectName with scope=SSO.
- LDAP:
  - Improved profile selection support.

### Bugfixes
- SSO:
  - Fix SSO join issue with CP that responds with another ID than requested (e.g. SamlMock).
  - Fix too strict subject name check issue for CP with SubjectNameMapping.
  - Fix QoA check with OIDC using RP config QoA instead of QoA from state.
  - Fix join via OIDC of session established via SAML.
- WSTrust:
  - Recipient in Issue RSTR was set to issuer in 1.12.0, revert to 1.11.0 behavior.

# Released Versions

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
  -- The old layout will be removed earliest in 1.12.0.

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
