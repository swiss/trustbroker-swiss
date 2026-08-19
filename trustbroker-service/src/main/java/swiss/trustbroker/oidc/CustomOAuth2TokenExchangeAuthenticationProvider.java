/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc;

import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST;

import java.security.Principal;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.oidc.pkce.PublicClientAuthenticationToken;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.util.AssertionValidator;

/**
 * Token exchange handler endpoint. Copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider.
 * That class is final, so we cannot subclass it.
 * authenticate is customized to work around external token handling
 * The copying means we are tied to an internal class from Spring Authentication Server.
 * <p>
 * Original Javadoc:
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Exchange.
 *
 * @author Steve Riesenberg
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8693#name-request">Section 2.1. Request</a>
 * @since 1.3
 */

@AllArgsConstructor
@Slf4j
public class CustomOAuth2TokenExchangeAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String SAML2_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:saml2";

	private static final String MAY_ACT = "may_act";

	private static final String REQUEST_SCOPE = "request_scope";

	private static final String REQUEST_AUDIENCE = "audience";

	private static final String REQUEST_RESOURCE = "resource";

	private static final String REQUEST_SUBJECT_TOKEN = "subject_token";

	private static final String REQUEST_SUBJECT_TOKEN_TYPE = "subject_token_type";

	private static final String REQUEST_REQUESTED_TOKEN_TYPE = "requested_token_type";

	private static final String REQUEST_ADDITIONAL_PARAMS = "requested_additional_params";

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final CustomOAuth2AuthorizationService authorizationService;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final QoaMappingService qoaMappingService;

	private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		var tokenExchangeAuthentication = (OAuth2TokenExchangeAuthenticationToken) authentication;

		var clientPrincipal = CustomOAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication);
		var registeredClientId = OidcAuthenticationUtil.getClientIdFromPrincipal(clientPrincipal);
		var registeredClient = this.registeredClientRepository.findByClientId(registeredClientId);

		validateRegisteredClient(registeredClient, registeredClientId);

		// RP configuration
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(registeredClientId, registeredClientId, trustBrokerProperties, false);
		var optionalRpOidcClient = relyingPartyDefinitions.getOidcClientConfigById(registeredClientId, trustBrokerProperties);
		var rpOidcClient = validateRpClient(optionalRpOidcClient.orElse(null), registeredClientId);

		validateRpForPKCEAuthentication(clientPrincipal, rpOidcClient);
		OidcValidator.validateInputParams(rpOidcClient, registeredClient, registeredClientId, tokenExchangeAuthentication, ERROR_URI);

		// CP configuration
		var subjectToken = tokenExchangeAuthentication.getSubjectToken();
		var iss = OidcUtil.getClaimFromJwtToken(subjectToken, OidcUtil.OIDC_ISSUER);
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(iss, iss, false);

		validateClaimsParty(claimsParty, iss);
		OidcValidator.validateClaimsProviderMapping(relyingParty, claimsParty, ERROR_URI);

		var subjectAuthorization = this.authorizationService.findByToken(subjectToken, OAuth2TokenType.ACCESS_TOKEN);
		var subjectTokenType = tokenExchangeAuthentication.getSubjectTokenType();

		Map<String, Object> subjectTokenClaims;
		List<String> subjectAcrs;
		JWTClaimsSet jwtClaimsSet = null;
		if (subjectAuthorization == null && trustBrokerProperties.getOidc().isExternalTokenExchangeEnabled()) {
			// Validate external token
			try {
				if (SAML2_TOKEN_TYPE_VALUE.equals(subjectTokenType) && trustBrokerProperties.getOidc().isSaml2TokenExchangeEnabled()) {
					Assertion assertion = SamlIoUtil.getAssertionFromSubjectToken(subjectToken);

					AssertionValidator.validateTokenAssertion(claimsParty, assertion, trustBrokerProperties);

					var subjectValue = validateAndGetSubject(assertion, registeredClientId);
					subjectTokenClaims = SamlUtil.extractAttributesFromAssertion(assertion);

					subjectAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
															  .principalName(subjectValue)
															  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
															  .attribute("subjectTokenClaims", subjectTokenClaims)
															  .attribute("java.security.Principal", clientPrincipal)
															  .build();
				}
				else {
					validateTokenType(subjectTokenType);

					// subject_token validating with CP config
					var key = oidcMetadataCacheService.jwtKeySupplier(claimsParty);
					jwtClaimsSet = OidcUtil.verifyJwtToken(subjectToken, key, claimsParty.getId());
					validateClaimSet(jwtClaimsSet, claimsParty);
					subjectTokenClaims = new HashMap<>(jwtClaimsSet.getClaims());

					subjectAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
															  .principalName(jwtClaimsSet.getSubject())
															  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
															  .attribute("subjectTokenClaims", subjectTokenClaims)
															  .attribute("java.security.Principal", clientPrincipal)
															  .build();
				}
			}
			catch (JwtException ex) {
				CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_GRANT, ex.getMessage(), ERROR_URI);
				return null;
			}
		}
		else if (subjectAuthorization != null) {
			OAuth2Authorization.Token<OAuth2Token> subjectAuthorizationToken = subjectAuthorization.getToken(subjectToken);
			validateTokenAuthorization(subjectAuthorizationToken, subjectTokenType);
			if (subjectAuthorizationToken == null || subjectAuthorizationToken.getClaims() == null) {
				var message = String.format("SubjectAuthorization token is null for client %s", claimsParty.getId());
				CustomOAuth2EndpointUtils.throwErrorWithMessage(INVALID_REQUEST, message, ERROR_URI);
				return null;
			}
			subjectTokenClaims = new HashMap<>(subjectAuthorizationToken.getClaims());
			jwtClaimsSet = OidcUtil.parseJwtClaims(subjectTokenClaims);
		}
		else {
			var message = String.format("Token exchange disabled with external tokens clientId=%s", registeredClientId);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, ERROR_URI);
			return null;
		}

		if (jwtClaimsSet == null) {
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, "Missing subject claim", ERROR_URI);
			return null;
		}

		OAuth2Authorization actorAuthorization = getActorTokenAuthorization(subjectTokenClaims, tokenExchangeAuthentication, subjectAuthorization);

		OidcValidator.validateSubjectTokenIatExpNbf(jwtClaimsSet, rpOidcClient, trustBrokerProperties, ERROR_URI);

		verifySubjectTokenUniqueOrSave(subjectToken, jwtClaimsSet, registeredClientId, clientPrincipal.getName(), rpOidcClient, trustBrokerProperties);

		validateClaimSet(jwtClaimsSet, claimsParty);

		OidcClaimValidatorService.validateSubAudAzp(jwtClaimsSet, relyingParty.getId(), rpOidcClient, OAuth2ParameterNames.SUBJECT_TOKEN, false);
		subjectAcrs = OidcClaimValidatorService.validateAcrs(jwtClaimsSet, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties);

		if (subjectAuthorization.getAttribute(Principal.class.getName()) == null) {
			// As per https://datatracker.ietf.org/doc/html/rfc8693#section-1.1,
			// we require a principal to be available via the subject_token for
			// impersonation or delegation use cases.
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_GRANT, "subjectAuthorization", ERROR_URI);
		}

		// Validate params
		var requestParams = validateRequestParamAndRetrieveScopes(tokenExchangeAuthentication, registeredClient, subjectAuthorization,
				rpOidcClient);
		var authorizedScopes = requestParams.get(REQUEST_SCOPE);

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = CustomDPoPProofVerifier.verifyIfAvailable(tokenExchangeAuthentication);

		if (log.isTraceEnabled()) {
			log.trace("Validated token request parameters");
		}

		Authentication principal = getPrincipal(subjectAuthorization, actorAuthorization);
		var cpOriginalAttributes = relyingPartyService.extractAndValidateCpAttrs(jwtClaimsSet, requestParams, claimsParty);
		var tokenData = relyingPartyService.getTokenExchangeUserData(subjectTokenClaims, cpOriginalAttributes, relyingParty, claimsParty, rpOidcClient, authorizedScopes, subjectAcrs);
		isValidTokenData(tokenData, relyingParty, claimsParty);
		JwtUtil.addAuthTimeToClaimMap(tokenData, subjectTokenClaims);
		JwtUtil.addSidToClaimMap(tokenData, HttpExchangeSupport.getOrCreateSessionId());
		addAcrToToken(tokenData, subjectAcrs, claimsParty, relyingParty, rpOidcClient);
		JwtUtil.addDPopClaimToClaimMap(tokenData, dPoPProof);
		addAudToToken(tokenData, requestParams, registeredClientId);
		addAzpToken(tokenData, rpOidcClient);

		//  Simple serializable technical principal required so SAS can process refresh tokens
		var clientPrincipalHolder = new UsernamePasswordAuthenticationToken(registeredClientId, null, List.of());

		var authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
													  .principalName(subjectAuthorization.getPrincipalName())
													  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
													  .authorizedScopes(authorizedScopes)
													  .attribute(Principal.class.getName(), clientPrincipalHolder)
													  .attributes(attrs -> attrs.putAll(tokenData));

		tokenExchangeAuthentication.setDetails(tokenData);

		var tokenContext = CustomOAuth2AuthenticationProviderUtils.generateTokenContextForTokenExchange(OAuth2TokenType.ACCESS_TOKEN,
				tokenExchangeAuthentication, registeredClient, principal, authorizedScopes, dPoPProof);

		var tokens = generateAndSaveTokens(authorizationBuilder, tokenExchangeAuthentication, tokenContext, relyingParty, rpOidcClient, registeredClient, principal, authorizedScopes);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, subjectTokenType);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal,
				(OAuth2AccessToken) tokens.get(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN), (OAuth2RefreshToken)
				tokens.get(OidcUtil.TOKEN_RESPONSE_REFRESH_TOKEN), additionalParameters);
	}

	@Nullable OAuth2Authorization getActorTokenAuthorization(Map<String, Object> subjectTokenClaims, OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, OAuth2Authorization subjectAuthorization) {
		// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.4,
		// the may_act claim states that one party is authorized to become the actor on behalf of another party.
		var authorizedActorClaims = getActorClaims(subjectTokenClaims);
		var authenticationActorToken = tokenExchangeAuthentication.getActorToken();
		if (!authorizedActorClaims.isEmpty()) {
			// Check and use internal actor token (provided earlier towards relying parties).
			// External actors are blocked before.
			if (subjectAuthorization == null && trustBrokerProperties.getOidc().isExternalTokenExchangeEnabled()) {
				CustomOAuth2EndpointUtils.throwErrorWithMessage(INVALID_REQUEST, "actor_token authorization not supported", ERROR_URI);
			}
			return getOAuth2AuthorizationWithActorToken(tokenExchangeAuthentication, authorizedActorClaims);
		}
		else if (authenticationActorToken != null) {
			CustomOAuth2EndpointUtils.throwErrorWithMessage(INVALID_REQUEST, "actor_token without may_act claim", ERROR_URI);
		}
		return null;
	}

	void addAzpToken(Map<String, Object> tokenData, OidcClient rpOidcClient) {
		// Public client UserinfoAuthentication reference
		tokenData.putIfAbsent(OidcUtil.OIDC_AUTHORIZED_PARTY, rpOidcClient.getId());
	}

	void addAudToToken(Map<String, Object> tokenData, Map<String, Set<String>> requestParams, String clientId) {
		Set<String> audiences = requestParams.get(REQUEST_AUDIENCE);
		Set<String> resources = requestParams.get(REQUEST_RESOURCE);
		Set<String> audClaims = new HashSet<>();

		if (audiences != null || resources != null) {
			audClaims.add(clientId);
		}

		if (audiences != null) {
			audClaims.addAll(audiences);
		}

		if (resources != null) {
			audClaims.addAll(resources);
		}

		if (!audClaims.isEmpty()) {
			tokenData.put(OidcUtil.OIDC_AUDIENCE, audClaims);
		}
	}

	void verifySubjectTokenUniqueOrSave(String subjectToken, JWTClaimsSet jwtClaimsSet, String clientId,
												String clientPrincipalName, OidcClient oidcClient, TrustBrokerProperties trustBrokerProperties) {
		var subjectTokenCount = this.authorizationService.getSubjectTokenCount(subjectToken);
		var oidcSecurityPolicies = oidcClient.getOidcSecurityPolicies();
		var expirationTime = jwtClaimsSet.getExpirationTime();
		Timestamp expirationTimeTimeStep = null;
		var subjectTokenNotOnOrAfterToleranceSec = oidcSecurityPolicies.getSubjectTokenNotOnOrAfterToleranceSec();
		var notOnOrAfterToleranceSec = subjectTokenNotOnOrAfterToleranceSec != null ? subjectTokenNotOnOrAfterToleranceSec : trustBrokerProperties.getSecurity().getNotOnOrAfterToleranceSec();
		var subjectTokenNotOnOrAfterToleranceMill = notOnOrAfterToleranceSec * 1000;
		if (expirationTime != null) {
			expirationTimeTimeStep = new Timestamp(expirationTime.getTime() + subjectTokenNotOnOrAfterToleranceMill);
		}

		var subjectTokenMaxUseCount = oidcSecurityPolicies.getSubjectTokenMaxUseCount();
		if (expirationTime == null) {
			subjectTokenMaxUseCount = 1;
		}

		if (subjectTokenCount != null && subjectTokenCount >= subjectTokenMaxUseCount) {
			var message = String.format("subject_token can not be reused for client=%s. Max allowed usage=%s", oidcClient.getId(), subjectTokenMaxUseCount);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, message, ERROR_URI);
		}

		var iat = jwtClaimsSet.getIssueTime();
		var iatTimestamp = expirationTimeTimeStep;
		if (iat != null) {
			iatTimestamp = new Timestamp(iat.getTime());
		}
		log.debug("Subject token unique for client={}, expirationTime={}", clientId, expirationTime);
		this.authorizationService.saveTokenExchangeSubjectToken(subjectToken, clientId, clientPrincipalName, iatTimestamp, expirationTimeTimeStep);
	}

	void validateRpForPKCEAuthentication(Authentication clientPrincipal, OidcClient rpOidcClient) {
		if (PublicClientAuthenticationToken.class.isAssignableFrom(clientPrincipal.getClass()) &&
				Boolean.FALSE.equals(rpOidcClient.getOidcSecurityPolicies().getAllowPublicClientTokenExchange())) {
			var message = String.format("Missing authentication params for client=%s. " +
					"Received PublicClientAuthenticationToken but ClientSecret is expected", rpOidcClient.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, ERROR_URI);
		}
	}

	static void validateClaimsParty(ClaimsParty claimsParty, String iss) {
		if (claimsParty == null) {
			log.error("Missing OIDC client pair for iss={}", iss);
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, iss, ERROR_URI);
		}
	}

	static OidcClient validateRpClient(OidcClient rpOidcClient, String registeredClientId) {
		if (rpOidcClient == null) {
			log.error("Could not find Rp OidcClient with id={}", registeredClientId);
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, registeredClientId, ERROR_URI);
		}
		return rpOidcClient;
	}

	static void validateRegisteredClient(RegisteredClient registeredClient, String registeredClientId) {
		if (registeredClient == null) {
			log.error("Could not find Client with id={}", registeredClientId);
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, registeredClientId, ERROR_URI);
		}
	}

	static void validateClaimSet(JWTClaimsSet jwtClaimsSet, ClaimsParty claimsParty) {
		if (jwtClaimsSet == null) {
			var message = String.format("Claims are null in token for client %s", claimsParty.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, ERROR_URI);
		}
	}

	void addAcrToToken(Map<String, Object> tokenData, List<String> subjectAcrs,
			ClaimsParty claimsParty, RelyingParty relyingParty, OidcClient rpOidcClient) {
		if (subjectAcrs != null && !subjectAcrs.isEmpty()) {
			var cpOidcClient = claimsParty.getSingleOidcClient();
			var cpQoa = cpOidcClient.getQoa() != null ? cpOidcClient.getQoa() : claimsParty.getQoa();
			var rpQoa = rpOidcClient.getQoa() != null ? rpOidcClient.getQoa() : relyingParty.getQoa();
			var comparison = cpQoa != null && cpQoa.getComparison() != null ? cpQoa.getComparison() : QoaComparison.EXACT;
			var qoaSpec = qoaMappingService.mapRequestQoasToOutbound(comparison, subjectAcrs, new QoaConfig(cpQoa, claimsParty.getId()),
					new QoaConfig(rpQoa, relyingParty.getId()));
			List<String> outboundQoas = qoaSpec.contextClasses();

			if (outboundQoas != null && !outboundQoas.isEmpty()) {
				tokenData.put(OidcUtil.OIDC_ACR, outboundQoas.size() > 1 ? outboundQoas : outboundQoas.getFirst());
			}
		}
	}

	@SuppressWarnings("unchecked")
	static Map<String, Object> getActorClaims(Map<String, Object> subjectTokenClaims) {
		if (subjectTokenClaims != null && subjectTokenClaims.containsKey(MAY_ACT) && subjectTokenClaims.get(MAY_ACT) instanceof Map<?, ?> mayAct) {
			return (Map<String, Object>) mayAct;
		}
		return Collections.emptyMap();
	}

	static void isValidTokenData(Map<String, Object> tokenData, RelyingParty relyingParty, ClaimsParty claimsParty) {
		if (tokenData.isEmpty()) {
			var message = String.format("No token data found for subject token. In relyingParty=%s claims=%s", relyingParty.getId(), claimsParty);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.ACCESS_DENIED, message, ERROR_URI);
		}
	}

	static String validateAndGetSubject(Assertion assertion, String registeredClientId) {
		var subject = assertion.getSubject();
		if (subject == null || subject.getNameID() == null) {
			var message = String.format("Missing SAML2 assertion subject for token exchange clientId=%s", registeredClientId);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, ERROR_URI);
			return null;
		}

		return subject.getNameID().getValue();
	}

	static void validateTokenAuthorization(OAuth2Authorization.Token<OAuth2Token> subjectAuthorizationToken, String subjectTokenType) {
		if (subjectAuthorizationToken != null && !subjectAuthorizationToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked
			// [...].
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_GRANT, "subjectAuthorization", ERROR_URI);
		}

		validateTokenType(subjectTokenType, subjectAuthorizationToken);
	}

	Map<String, Set<String>> validateRequestParamAndRetrieveScopes(OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication,
																		   RegisteredClient registeredClient, OAuth2Authorization subjectAuthorization,
																		   OidcClient oidcClient) {
		Map<String, Set<String>> requestParams = new HashMap<>();
		if (!CollectionUtils.isEmpty(tokenExchangeAuthentication.getScopes())) {
			requestParams.put(REQUEST_SCOPE, validateRequestedScopes(registeredClient, tokenExchangeAuthentication.getScopes()));
		}
		else if (!CollectionUtils.isEmpty(subjectAuthorization.getAuthorizedScopes())) {
			requestParams.put(REQUEST_SCOPE, validateRequestedScopes(registeredClient, subjectAuthorization.getAuthorizedScopes()));
		}
		else if (oidcClient.getScopes() == null) {
			var message = String.format("Scopes are missing in=%s, configured", oidcClient.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, ERROR_URI);
		}
		else {
			requestParams.put(REQUEST_SCOPE, new LinkedHashSet<>(Set.of(OidcScopes.OPENID)));
		}

		var audiences = tokenExchangeAuthentication.getAudiences();
		OidcValidator.validateRequestedAudiences(audiences, oidcClient, ERROR_URI);
		if (!CollectionUtils.isEmpty(audiences)) {
			requestParams.put(REQUEST_AUDIENCE, audiences);
		}

		var resources = tokenExchangeAuthentication.getResources();
		OidcValidator.validateRequestResources(resources, oidcClient, ERROR_URI);
		if (!CollectionUtils.isEmpty(resources)) {
			requestParams.put(REQUEST_RESOURCE, resources);
		}

		var subjectTokenValue = tokenExchangeAuthentication.getSubjectToken();
		addRequestParamIfNotNull(requestParams, REQUEST_SUBJECT_TOKEN, subjectTokenValue);

		var subjectTokenType = tokenExchangeAuthentication.getSubjectTokenType();
		addRequestParamIfNotNull(requestParams, REQUEST_SUBJECT_TOKEN_TYPE, subjectTokenType);

		var requestedTokenType = tokenExchangeAuthentication.getRequestedTokenType();
		addRequestParamIfNotNull(requestParams, REQUEST_REQUESTED_TOKEN_TYPE, requestedTokenType);

		var additionalParameters = tokenExchangeAuthentication.getAdditionalParameters();
		if (additionalParameters != null) {
			for (Map.Entry<String, Object> additionalParameter : additionalParameters.entrySet()) {
				if (additionalParameter.getValue() != null) {
					addRequestParamIfNotNull(requestParams, "request_" + additionalParameter.getKey(), additionalParameter.getValue().toString());
				}
			}
		}

		return requestParams;
	}

	void addRequestParamIfNotNull(Map<String, Set<String>> requestParams, String paramName, String value) {
		if (value != null) {
			Set<String> values = new HashSet<>();
			values.add(value);
			requestParams.put(paramName, values);
		}
	}

	OAuth2Authorization getOAuth2AuthorizationWithActorToken(OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, Map<String, Object> authorizedActorClaims) {
		OAuth2Authorization actorAuthorization = null;
		if (StringUtils.hasText(tokenExchangeAuthentication.getActorToken())) {
			actorAuthorization = this.authorizationService.findByToken(tokenExchangeAuthentication.getActorToken(), OAuth2TokenType.ACCESS_TOKEN);
			if (actorAuthorization == null) {
				CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_GRANT, "actor_token", ERROR_URI);
				return null;
			}

			if (log.isTraceEnabled()) {
				log.trace("Retrieved authorization with actor token");
			}

			OAuth2Authorization.Token<OAuth2Token> actorToken = actorAuthorization.getToken(tokenExchangeAuthentication.getActorToken());
			validateTokenAuthorization(actorToken, tokenExchangeAuthentication.getActorTokenType());

			if (actorToken == null) {
				log.error("No actor token found for actor token={}", tokenExchangeAuthentication.getActorToken());
				CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_GRANT, "actor_token", ERROR_URI);
				return null;
			}

			if (authorizedActorClaims != null) {
				validateClaims(authorizedActorClaims, actorToken.getClaims(), OAuth2TokenClaimNames.ISS, OAuth2TokenClaimNames.SUB);
			}
		}
		else if (authorizedActorClaims != null) {
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_GRANT, "authorized_actor_claim", ERROR_URI);
		}
		return actorAuthorization;
	}

	Map<String, OAuth2Token> generateAndSaveTokens(OAuth2Authorization.Builder subjectAuthorizationBuilder,
	                                                       OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication,
	                                                       OAuth2TokenContext tokenContext,
	                                                       RelyingParty relyingParty, OidcClient rpOidcClient, RegisteredClient registeredClient,
	                                                       Authentication principal, Set<String> authorizedScopes) {

		OAuth2Token token;
		if (SAML2_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType())) {
			var saml2TokenGenerator = new Saml2TokenGenerator(relyingParty, trustBrokerProperties);
			token = saml2TokenGenerator.generate(tokenContext);
		}
		else {
			token = tokenGenerator.generate(tokenContext);
			if (token == null) {
				var message = "The token generator failed to generate the access token.";
				CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.SERVER_ERROR, message, ERROR_URI);
			}
		}

		Map<String, OAuth2Token> tokens = new HashMap<>();

		var accessToken = CustomOAuth2AuthenticationProviderUtils.accessToken(subjectAuthorizationBuilder, token, tokenContext);
		tokens.put(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN, accessToken);
		if (rpOidcClient != null && OidcConfigurationUtil.canIssueIdToken(rpOidcClient, authorizedScopes)) {
			var idToken = CustomOAuth2AuthenticationProviderUtils.idToken(subjectAuthorizationBuilder, token);
			tokens.put(OidcUtil.TOKEN_RESPONSE_ID_TOKEN, idToken);
		}

		if (rpOidcClient != null && OidcConfigurationUtil.canIssueRefreshToken(rpOidcClient)) {
			var refreshToken = CustomOAuth2AuthenticationProviderUtils.refreshToken(subjectAuthorizationBuilder,
					 tokenExchangeAuthentication, registeredClient, principal, authorizedScopes, tokenGenerator);
			tokens.put(OidcUtil.TOKEN_RESPONSE_REFRESH_TOKEN, refreshToken);
		}

		if (log.isTraceEnabled()) {
			log.trace("Generated access token={}", accessToken);
		}

		OAuth2Authorization authorization = subjectAuthorizationBuilder.build();
		this.authorizationService.save(authorization);

		if (log.isTraceEnabled()) {
			log.trace("Saved authorization");
		}

		return tokens;
	}

	static void validateTokenType(String tokenType, OAuth2Authorization.Token<OAuth2Token> token) {
		if (token == null) {
			log.error("No token found for tokenType={}", tokenType);
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, REQUEST_SUBJECT_TOKEN_TYPE, ERROR_URI);
			return;
		}
		String tokenFormat = token.getMetadata(OAuth2TokenFormat.class.getName());
		boolean isValidTokenType = ACCESS_TOKEN_TYPE_VALUE.equals(tokenType) || JWT_TOKEN_TYPE_VALUE.equals(tokenType) && OAuth2TokenFormat.SELF_CONTAINED.getValue().equals(tokenFormat);
		if (!isValidTokenType) {
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, REQUEST_SUBJECT_TOKEN_TYPE, ERROR_URI);
		}
	}

	static void validateTokenType(String tokenType) {
		boolean isValidTokenType = ACCESS_TOKEN_TYPE_VALUE.equals(tokenType) || JWT_TOKEN_TYPE_VALUE.equals(tokenType);
		if (!isValidTokenType) {
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, tokenType, ERROR_URI);
		}
	}

	static Set<String> validateRequestedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
		for (String requestedScope : requestedScopes) {
			if (!registeredClient.getScopes().contains(requestedScope)) {
				CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_SCOPE, REQUEST_SCOPE, ERROR_URI);
			}
		}

		return new LinkedHashSet<>(requestedScopes);
	}

	static void validateClaims(Map<String, Object> expectedClaims, Map<String, Object> actualClaims, String... claimNames) {
		if (actualClaims == null) {
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_GRANT, "actor_claim", ERROR_URI);
			return;
		}

		for (String claimName : claimNames) {
			if (!Objects.equals(expectedClaims.get(claimName), actualClaims.get(claimName))) {
				CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_GRANT, claimName, ERROR_URI);
			}
		}
	}

	static Authentication getPrincipal(OAuth2Authorization subjectAuthorization, OAuth2Authorization actorAuthorization) {
		Authentication subjectPrincipal = subjectAuthorization.getAttribute(Principal.class.getName());
		if (actorAuthorization == null) {
			if (subjectPrincipal instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
				return compositeAuthenticationToken.getSubject();
			}
			return subjectPrincipal;
		}

		// Capture claims for current actor's access token
		OAuth2TokenExchangeActor currentActor = new OAuth2TokenExchangeActor(actorAuthorization.getAccessToken().getClaims());
		List<OAuth2TokenExchangeActor> actorPrincipals = new LinkedList<>();
		actorPrincipals.add(currentActor);

		// Add chain of delegation for previous actor(s) if any
		if (subjectPrincipal instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
			subjectPrincipal = compositeAuthenticationToken.getSubject();
			actorPrincipals.addAll(compositeAuthenticationToken.getActors());
		}

		return new OAuth2TokenExchangeCompositeAuthenticationToken(subjectPrincipal, actorPrincipals);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
