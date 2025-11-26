/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.oidc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@AllArgsConstructor
@Slf4j
class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final ScriptService scriptService;

	private final ClaimsMapperService claimsMapperService;

	private final AuditService auditService;

	private final QoaMappingService qoaService;

	private final JWKSource<SecurityContext> jwkSource;

	@Override
	public void customize(JwtEncodingContext context) {
		if (context == null) {
			return;
		}

		var authorization = context.getAuthorization();
		if (authorization == null) {
			throw new TechnicalException("Missing authorization, cannot set Token claims");
		}

		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(
				authorization.getRegisteredClientId(), null, properties, false);
		var cpResponse = setCpResponseAttributes(context, authorization, relyingParty);
		var clientId = authorization.getRegisteredClientId();
		var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		boolean accessTokenOpaque = isAccessTokenOpaque(client, context);

		if (accessTokenOpaque) {
			log.debug("OidcClient={} opaque AccessToken is {}", clientId, accessTokenOpaque);
			return;
		}

		addTokenClaims(cpResponse, context);

		String conversationId = null;
		if (context.getPrincipal() instanceof Saml2Authentication saml2Authentication) {
			var saml2Response = saml2Authentication.getSaml2Response();
			var response = getResponse(saml2Response);
			conversationId = response.getInResponseTo();
			var assertions = getResponseAssertion(response, relyingParty, conversationId);
			addAuthTimeClaim(cpResponse, assertions, response.getIssueInstant()); // from original SAML Response Assertion
			addAcrClaim(cpResponse, assertions, client, relyingParty); // from original SAML Response Assertion
			addSidClaim(context.getPrincipal(), cpResponse);
		}

		// Note: id_token.nonce is handled by spring, refresh_token.nonce is handled by CustomRefreshTokenGenerator
		if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
			addNonce(cpResponse, authorization);
		}

		// ID handling like in SAML possible
		context.getClaims().id(UUID.randomUUID().toString());

		// Set these claims for all tokens
		addTypClaim(context, cpResponse);
		addIssClaim(cpResponse, client.orElse(null));
		addAudienceClaim(cpResponse);
		addAuthorizedPartyClaim(cpResponse, authorization);
		addScopeClaim(cpResponse);

		// Set kid and get the maximum kid through
		String kid = null;
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) || OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			kid = addKeyIdFromJwkSource(jwkSource, context);
		}

		// last chance to manipulate the output
		scriptService.processRpOnToken(cpResponse, relyingParty.getId(), null);

		// computed expiration
		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			addExpiresClaim(cpResponse, client);
		}

		// filter the scopes if scope is defined along oidcName, otherwise apply them
		var attributes = cpResponse.getClaims();
		if (!attributes.isEmpty()) {
			context.getClaims()
				   .claims(attrMap -> attrMap.putAll(attributes));
		}

		// optional typ claim
		setTypeHeader(context);

		// audit
		auditTokenClaims(clientId, context, kid, cpResponse, conversationId);
	}

	private List<Assertion> getResponseAssertion(Response response, RelyingParty relyingParty, String conversationId) {
		var rpSigner = relyingParty.getRpSigner();
		boolean requireEncryptedAssertion =  properties.getOidc().isSamlEncrypt();
		var responseAssertions = SamlUtil.getResponseAssertions(response, List.of(rpSigner), requireEncryptedAssertion);
		if (responseAssertions.isEmpty()) {
			throw new TechnicalException(String.format("Missing assertion for response=%s", conversationId));
		}
		return responseAssertions;
	}

	private static boolean isAccessTokenOpaque(Optional<OidcClient> client, JwtEncodingContext context) {
		boolean isAccessToken = context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN);
		var opaqueAccessToken = false;
		if(client.isPresent()){
			var oidcClient = client.get();
			var oidcSecurityPolicies = oidcClient.getOidcSecurityPolicies();
			opaqueAccessToken = oidcSecurityPolicies != null
					&& Boolean.TRUE.equals(oidcSecurityPolicies.getRequireOpaqueAccessToken());
		}
		return isAccessToken && opaqueAccessToken;
	}

	private void addExpiresClaim(CpResponse cpResponse, Optional<OidcClient> client) {
		if (client.isPresent()) {
			var issuedAt = Instant.now();
			var expiresAt = issuedAt.plus(properties.getSecurity().getTokenLifetimeSec(), ChronoUnit.SECONDS);
			var oidcSecurityPolicies = client.get().getOidcSecurityPolicies();
			if (oidcSecurityPolicies != null && oidcSecurityPolicies.getIdTokenTimeToLiveMin() != null) {
				expiresAt = issuedAt.plus(oidcSecurityPolicies.getIdTokenTimeToLiveMin(), ChronoUnit.MINUTES);
			}
			cpResponse.setClaims(IdTokenClaimNames.EXP, expiresAt);
		}
	}

	private static void addScopeClaim(CpResponse cpResponse) {
		var scope = cpResponse.getClaims().get(OidcUtil.OIDC_SCOPE);
		if (scope instanceof Collection<?> scopes) {
			var scopeList = Arrays.stream(scopes.toArray()).toList();
			var scopeClaim = OidcConfigurationUtil.getStringValueOfOidcClaim(scopeList);
			if (scopeClaim != null) {
				cpResponse.setClaim(OidcUtil.OIDC_SCOPE, scopeClaim);
			}
		}
	}

	private static void addAudienceClaim(CpResponse cpResponse) {
		// audience comes from spring-sec
		var audienceClaim = cpResponse.getClaims().get(OidcUtil.OIDC_AUDIENCE);
		// transform audience into a single valued claim if we have a list with only one value (Keycloak behavior)
		if (audienceClaim instanceof Collection<?> audiences) {
			var audClaims = Arrays.stream(audiences.toArray())
					.toList();
			if (audClaims.size() == 1) {
				cpResponse.setClaim(OidcUtil.OIDC_AUDIENCE, audClaims.get(0));
			}
		}
	}

	private static void addTokenClaims(CpResponse cpResponse, JwtEncodingContext context) {
		context.getClaims()
			   .claims(attrMap -> {
				   for (var entry : attrMap.entrySet()) {
					   if (cpResponse.getClaim(entry.getKey()) == null) {
						   cpResponse.setClaim(entry.getKey(), entry.getValue());
					   }
				   }
			   });
	}

	private void auditTokenClaims(String clientId, JwtEncodingContext context, String kid,
			CpResponse cpResponse, String conversationId) {
		// OIDC claims in data section
		var auditDtoBuilder = new OutboundAuditMapper(properties);
		context.getClaims()
			   .claims(attrMap ->
					   auditDtoBuilder.mapFromClaims(attrMap, AuditDto.AttributeSource.OIDC_RESPONSE)
			   );

		// add referer and other helpful stuff
		auditDtoBuilder.mapFrom(HttpExchangeSupport.getRunningHttpRequest());

		// kid header so we can track key rotation
		var auditDto = auditDtoBuilder.build();
		if (kid != null) {
			auditDtoBuilder.mapFromClaims(Map.of(OidcUtil.OIDC_HEADER_KEYID, kid), AuditDto.AttributeSource.OIDC_RESPONSE);
		}

		// overwrite referer with the original caller, so we can better correlate the application
		auditDto.setReferrer(getCurrentReferrer());

		// correlation with SAML side sending ssoSessionId usually
		var ssoSessionId = cpResponse.getAttribute(CoreAttributeName.SSO_SESSION_ID.getNamespaceUri());
		auditDto.setSsoSessionId(ssoSessionId);

		// correlated with initial OIDC session
		auditDto.setConversationId(conversationId);

		// correlation by message marker
		auditDto.setMessageId(getCurrentMessageId());

		// token type influences log level as access_token and id_token are mostly the same
		var tokenType = context.getTokenType()
							   .equals(OAuth2TokenType.ACCESS_TOKEN) ?
				EventType.OIDC_TOKEN : EventType.OIDC_IDTOKEN;
		auditDto.setEventType(tokenType);
		auditDto.setSide(DestinationType.RP.getLabel());

		auditDto.setOidcClientId(clientId);

		auditService.logOutboundFlow(auditDto);
	}

	private boolean isEnabledTokenClaim(String claim) {
		return properties.getOidc()
						 .getAddTokenClaims()
						 .contains(claim);
	}


	private boolean isEnabledTokenHeader(String header) {
		return properties.getOidc().getAddTokenHeader().contains(header);
	}

	private static String getCurrentReferrer() {
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			return session.getStateData().getRpReferer();
		}
		return null;
	}

	private static String getCurrentMessageId() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request != null) {
			// at the moment we log this, the code is consumed and invalidated
			return StringUtil.clean(request.getParameter(OidcUtil.OIDC_CODE));
		}
		return null;
	}

	private void addSidClaim(Authentication principal, CpResponse cpResponse) {
		if (!isEnabledTokenClaim(OidcUtil.OIDC_SESSION_ID)) {
			return;
		}
		var oidcSessionId = getSidClaim(principal);
		if (oidcSessionId != null) {
			cpResponse.setClaim(OidcUtil.OIDC_SESSION_ID, oidcSessionId);
			if (isEnabledTokenClaim(OidcUtil.OIDC_SESSION_STATE)) {
				cpResponse.setClaim(OidcUtil.OIDC_SESSION_STATE, oidcSessionId);
			}
		}
		else {
			log.error("Adding 'sid' claim ignored as principal does not contain at least 2 session indexes");
		}
	}

	static String getSidClaim(Authentication principal) {
		// by attaching to the SAML side we also get data when e.g. /token endpoint is not under session management
		var sessionIds = OidcSessionSupport.getSessionIdsFromAuthentication(principal);
		if (sessionIds != null && sessionIds.size() > 1) {
			var ssoSessionId = sessionIds.get(0);
			var oidcSessionId = sessionIds.get(1);
			log.debug("Setting sid claim from ssoSessionId={} to sid={}", ssoSessionId, oidcSessionId);
			return oidcSessionId;
		}
		else {
			log.error("Adding 'sid' claim ignored as principal does not contain at least 2 session indexes");
		}
		return null;
	}

	private void addIssClaim(CpResponse cpResponse, OidcClient client) {
		if (client == null || !isEnabledTokenClaim(OidcUtil.OIDC_ISSUER)) {
			return;
		}
		if (client.getRealm() != null) {
			// with or without slash
			String oidcIssuer = properties.getOidc().getIssuer();
			var iss = oidcIssuer + ApiSupport.KEYCLOAK_REALMS + "/" + client.getRealm();
			cpResponse.setClaim(OidcUtil.OIDC_ISSUER, iss);
		}
	}

	private void setTypeHeader(JwtEncodingContext context) {
		if (!isEnabledTokenHeader(HeaderParameterNames.TYPE)) {
			return;
		}
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ||
				OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			context.getJwsHeader()
				   .headers(headers -> headers.put(HeaderParameterNames.TYPE, OidcUtil.OIDC_HEADER_TYPE_JWT));
		}
	}

	private void addTypClaim(JwtEncodingContext context, CpResponse cpResponse) {
		if (!isEnabledTokenClaim(OidcUtil.OIDC_TOKEN_TYPE)) {
			return;
		}
		// Keycloak always sets the 'typ' claim. We do it too to distinguish tokens in auditing.
		// Spec https://datatracker.ietf.org/doc/html/rfc7519#section-5.1 defines it only for the header.
		// We do not set typ=JWT in the header as it's the default anyway.
		var tokenType = context.getTokenType()
							   .getValue();
		if (OAuth2TokenType.ACCESS_TOKEN.getValue()
										.equals(tokenType)) {
			tokenType = "Bearer"; // according to Keycloak
		}
		else if (OAuth2TokenType.REFRESH_TOKEN.getValue()
											  .equals(tokenType)) {
			tokenType = "Refresh"; // according to Keycloak
		}
		else if (OidcParameterNames.ID_TOKEN.equals(tokenType)) {
			tokenType = "ID"; // according to Keycloak
		}
		else {
			tokenType = "JWT"; // according to spec
		}
		cpResponse.setClaim(OidcUtil.OIDC_TOKEN_TYPE, tokenType);
	}

	// Optional claim representing the targeted client_id, We always set it.
	// Keycloak always sets it because usually aud includes the account client as well.
	private void addAuthorizedPartyClaim(CpResponse cpResponse, OAuth2Authorization authorization) {
		if (!isEnabledTokenClaim(OidcUtil.OIDC_AUTHORIZED_PARTY)) {
			return;
		}
		var clientId = authorization.getRegisteredClientId();
		if (clientId != null) {
			cpResponse.setClaim(OidcUtil.OIDC_AUTHORIZED_PARTY, clientId);
		}
	}

	// cache parsed response in HttpServletRequest if available to avoid parsing for each token
	private static Response getResponse(String saml2Response) {
		var cacheKey = "XTB.parsed.response";
		Response response = null;
		Pair<String, Response> responseMap = WebSupport.getRequestAttribute(cacheKey, true);
		if (responseMap != null && responseMap.getKey()
											  .equals(saml2Response)) {
			response = responseMap.getValue();
			log.debug("Using cached parsed response from HttpServletRequest");
		}
		if (response == null) {
			response = SamlIoUtil.getXmlObjectFromString(Response.class, saml2Response, "XTB-OIDC");
			log.debug("Caching parsed response in HttpServletRequest");
			WebSupport.setRequestAttribute(cacheKey, Pair.of(saml2Response, response), true);
		}
		return response;
	}

	private void addAcrClaim(CpResponse cpResponse, List<Assertion> assertions, Optional<OidcClient> oidcClient, RelyingParty relyingParty) {
		if (!isEnabledTokenClaim(IdTokenClaimNames.ACR)) {
			return;
		}
		if (CollectionUtils.isEmpty(assertions)) {
			return;
		}

		var useLegacyQoa = getLegacyQoaFlag(oidcClient);
		var qoaConfig = getClientQoaConfig(oidcClient, relyingParty);

		var authnContextClassRefs = new HashSet<String>();
		for (var assertion : assertions) {
			for (var authnStatement : assertion.getAuthnStatements()) {
				addContextClassRef(useLegacyQoa, authnContextClassRefs, authnStatement, qoaConfig);
			}
		}
		if (authnContextClassRefs.size() == 1) {
			cpResponse.setClaim(IdTokenClaimNames.ACR, authnContextClassRefs.iterator().next()); // STRING
		}
		else if (authnContextClassRefs.size() > 1) {
			cpResponse.setClaim(IdTokenClaimNames.ACR, authnContextClassRefs); // LIST
		}
	}

	private static QoaConfig getClientQoaConfig(Optional<OidcClient> oidcClient, RelyingParty relyingParty) {
		if (oidcClient.isPresent() && oidcClient.get().getQoa() != null) {
			return oidcClient.get().getQoaConfig();
		}

		return relyingParty.getQoaConfig();
	}

	private String getLegacyQoaFlag(Optional<OidcClient> oidcClient) {
		String useLegacyQoa = null; // pass through
		if (oidcClient.isPresent()) {
			useLegacyQoa = oidcClient.get().getUsePepQoa();
			if (useLegacyQoa == null) {
				useLegacyQoa = properties.getOidc().getDefaultUsePepQoaPolicy();
			}
		}
		return useLegacyQoa;
	}

	private void addContextClassRef(String legacyQoaPolicy, Set<String> authnContextClassRefs,
			AuthnStatement authnStatement, QoaConfig qoaConfig) {
		var authContext = authnStatement.getAuthnContext();
		if (authContext == null || authContext.getAuthnContextClassRef() == null ||
				authContext.getAuthnContextClassRef().getURI() == null) {
			log.debug("Missing authentication context class");
			return;
		}

		String contextQoa = authContext.getAuthnContextClassRef().getURI();
		var contextQoas = List.of(contextQoa);

		if (legacyQoaPolicy != null) {
			contextQoas = qoaService.extractPepQoaFromAuthLevel(contextQoa, qoaConfig, legacyQoaPolicy);

		}

		authnContextClassRefs.addAll(contextQoas);
	}

	// Spring JwtGenerator sets it for ID_TOKEN only
	// Spec clarification:
	// https://bitbucket.org/openid/connect/pull-requests/341/errata-clarified-nonce-during-id-token
	// keycloak.js expects a nonce on other tokens though
	private static void addNonce(CpResponse cpResponse, OAuth2Authorization authorization) {
		var nonce = getNonce(authorization);
		if (StringUtils.hasText(nonce)) {
			cpResponse.setClaim(IdTokenClaimNames.NONCE, nonce);
		}
	}

	static String getNonce(OAuth2Authorization authorization) {
		if (authorization == null) {
			return null;
		}
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (authorizationRequest == null) {
			return null;
		}
		var nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
		if (StringUtils.hasText(nonce)) {
			return nonce;
		}
		return null;
	}

	private void addAuthTimeClaim(CpResponse cpResponse, List<Assertion> assertions, Instant issueInstant) {
		if (!isEnabledTokenClaim(IdTokenClaimNames.AUTH_TIME)) {
			return;
		}
		var authTime = getAuthTimeFromResponse(assertions, issueInstant);
		if (authTime != null) {
			long epochSecond = authTime.getEpochSecond();
			cpResponse.setClaim(IdTokenClaimNames.AUTH_TIME, epochSecond);
		}
	}

	private static Instant getAuthTimeFromResponse(List<Assertion> assertions, Instant issueInstant) {
		if (CollectionUtils.isEmpty(assertions)) {
			return null;
		}
		for (var assertion : assertions) {
			for (var authnStatement : assertion.getAuthnStatements()) {
				if (authnStatement.getAuthnInstant() != null) {
					return authnStatement.getAuthnInstant();
				}
			}
			if (assertion.getIssueInstant() != null) {
				return issueInstant;
			}
		}
		log.debug("No AuthnInstant found in response");
		return null;
	}

	private static String addKeyIdFromJwkSource(JWKSource<SecurityContext> jwkSource, JwtEncodingContext context) {
		var kid = JwkUtil.getKeyIdFromJwkSource(jwkSource);
		if (kid != null) {
			context.getJwsHeader().keyId(kid);
		}
		return kid;
	}

	private CpResponse setCpResponseAttributes(JwtEncodingContext context, OAuth2Authorization authorization,
			RelyingParty relyingParty) {
		var clientId = authorization.getRegisteredClientId();
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		var scopes = authorization.getAuthorizedScopes();

		// transfer SAML attributes received by XTB on OIDC side from spring-sec
		// Can contain duplicate values coming from IDP (OriginalIssuer) and XTB (without it)
		var samlAttributesFromSpring = OidcConfigurationUtil.extractSamlAttributesFromContext(context);
		var samlAttributesWithDefs = OidcConfigurationUtil.mapSamlNamesToDefs(samlAttributesFromSpring);

		// get all definitions with oidcNames from all sources (attributes, userdetails, properties, constants)
		var definitionsFromConfig = OidcConfigurationUtil.getAllOidcDefinitions(relyingParty, oidcClient.orElse(null), scopes);

		// transform SAML to OIDC based on required definition (includes oidcMapper execution)
		// Uses a Definition/Object map, so we can invoke script hooks to compute derived OIDC claims
		var preComputedClaims = OidcConfigurationUtil.computeOidcClaims(samlAttributesFromSpring, definitionsFromConfig,
				claimsMapperService, properties.getOidc().isAddEidStandardClaims(), oidcClient.orElse(null));

		// allow manipulations before this goes out to clients, scripts can:
		// - manipulate, add or remove claims
		// - aggregate structured claims from existing claims and SAML attributes
		// NOTE: token and id_token receive the same claims
		var nameID = authorization.getPrincipalName();

		return CpResponse.builder()
						 .nameId(nameID) // subject nameid from XTB SAML
						 .nameIdFormat(NameIDType.UNSPECIFIED) // lost in translation by spring-sec
						 .oidcClientId(clientId)
						 .oidcScopes(scopes)
						 .attributes(samlAttributesWithDefs) // input from XTB SAML side
						 // (no diff on userdetails, properties etc. anymore)
						 .claims(preComputedClaims) // output towards OIDC clients
						 .build();
	}

}
