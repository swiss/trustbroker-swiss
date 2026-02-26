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
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.ERROR_URI;

import java.security.Principal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
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

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String SAML2_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:saml2";

	private static final String MAY_ACT = "may_act";

	private static final String REQUEST_SCOPES = "scopes";

	private static final String REQUEST_AUDIENCES = "audiences";

	private static final String REQUEST_RESOURCES = "resources";

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final JWKSource<SecurityContext> jwkSource;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final QoaMappingService qoaMappingService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		var tokenExchangeAuthentication = (OAuth2TokenExchangeAuthenticationToken) authentication;
		var clientPrincipal = CustomOAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication);
		var registeredClientId = OidcAuthenticationUtil.getClientIdFromPrincipal(clientPrincipal);
		var registeredClient = this.registeredClientRepository.findByClientId(registeredClientId);

		// RP configuration
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(registeredClientId, registeredClientId, trustBrokerProperties, false);
		var rpOidcClient = relyingPartyDefinitions.getOidcClientConfigById(registeredClientId, trustBrokerProperties);

		validateInputParams(rpOidcClient, registeredClient, registeredClientId, tokenExchangeAuthentication);

		var subjectToken = tokenExchangeAuthentication.getSubjectToken();
		var iss = OidcUtil.getClaimFromJwtToken(subjectToken, OidcUtil.OIDC_ISSUER);
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(iss, iss, false);

		if (claimsParty == null) {
			log.error("Missing OIDC client pair for iss={}", iss);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}
		var cpOidcConfig = claimsParty.getSingleOidcClient();

		validateClaimsProviderMapping(relyingParty, claimsParty);

		var subjectAuthorization = this.authorizationService.findByToken(tokenExchangeAuthentication.getSubjectToken(), OAuth2TokenType.ACCESS_TOKEN);
		Map<String, Object> subjectTokenClaims;
		var subjectTokenType = tokenExchangeAuthentication.getSubjectTokenType();
		List<String> subjectAcrs;
		JWTClaimsSet jwtClaimsSet = null;
		if (subjectAuthorization == null && trustBrokerProperties.getOidc().isExternalTokenExchangeEnabled()) {
			// Validate external token
			try {
				if (SAML2_TOKEN_TYPE_VALUE.equals(subjectTokenType)) {
					Assertion assertion = SamlIoUtil.getAssertionFromSubjectToken(subjectToken);

					AssertionValidator.validateTokenAssertion(claimsParty, assertion, trustBrokerProperties);

					var subjectValue = validateAndGetSubject(assertion, registeredClientId);
					subjectTokenClaims = extractSamlClaims(assertion);

					subjectAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
															  .principalName(subjectValue)
															  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
															  .attribute("subjectTokenClaims", subjectTokenClaims)
															  .attribute("java.security.Principal", clientPrincipal)
															  .build();
				}
				else {
					if (!isValidTokenType(subjectTokenType)) {
						throw new OAuth2AuthenticationException(INVALID_REQUEST);
					}
					// subject_token validating with CP config
					var key = getJWKForClaimParty(claimsParty);
					jwtClaimsSet = OidcUtil.verifyJwtToken(subjectToken, key, claimsParty.getId());
					if (jwtClaimsSet == null) {
						var error = new OAuth2Error(INVALID_REQUEST,
						String.format("Claims are null in token for client %s", claimsParty.getId()), OidcExceptionHelper.ERROR_URI);
						throw new OAuth2AuthenticationException(error);
					}
					subjectTokenClaims = jwtClaimsSet.getClaims();

					subjectAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
															  .principalName(jwtClaimsSet.getSubject())
															  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
															  .attribute("subjectTokenClaims", subjectTokenClaims)
															  .attribute("java.security.Principal", clientPrincipal)
															  .build();
				}
			}
			catch (JwtException ex) {
				log.error(ex.getMessage(), ex);
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}
		}
		else if (subjectAuthorization != null) {
			OAuth2Authorization.Token<OAuth2Token> subjectAuthorizationToken = subjectAuthorization.getToken(tokenExchangeAuthentication.getSubjectToken());
			validateTokenAuthorization(subjectAuthorizationToken, subjectTokenType);
			if (subjectAuthorizationToken == null) {
				log.error("SubjectAuthorization token is null for client {}", claimsParty.getId());
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
			}
			subjectTokenClaims = subjectAuthorizationToken.getClaims();
			jwtClaimsSet = OidcUtil.parseJwtClaims(subjectTokenClaims);
		} else {
			log.error("Token exchange disabled for external token exchange clientId={}", registeredClientId);
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}

		if (jwtClaimsSet == null) {
			var error = new OAuth2Error(INVALID_REQUEST,
					String.format("Claims are null in token for client %s", claimsParty.getId()), OidcExceptionHelper.ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		OidcClaimValidatorService.validateSubAudAzp(jwtClaimsSet, claimsParty.getId(), cpOidcConfig);
		subjectAcrs = OidcClaimValidatorService.validateAcrs(jwtClaimsSet, claimsParty, cpOidcConfig, trustBrokerProperties);

		if (subjectAuthorization.getAttribute(Principal.class.getName()) == null) {
			// As per https://datatracker.ietf.org/doc/html/rfc8693#section-1.1,
			// we require a principal to be available via the subject_token for
			// impersonation or delegation use cases.
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.4,
		// The may_act claim makes a statement that one party is authorized to
		// become the actor and act on behalf of another party.
		Map<String, Object> authorizedActorClaims = null;
		authorizedActorClaims = getActorClaims(subjectTokenClaims, authorizedActorClaims);

		// Check for Actor token
		OAuth2Authorization actorAuthorization = getOAuth2AuthorizationWithActorToken(tokenExchangeAuthentication, authorizedActorClaims);

		// Validate params
		var requestParams = validateRequestParamAndRetrieveScopes(tokenExchangeAuthentication, registeredClient, subjectAuthorization,
				cpOidcConfig, subjectTokenClaims);
		var authorizedScopes = requestParams.get(REQUEST_SCOPES);

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = CustomDPoPProofVerifier.verifyIfAvailable(tokenExchangeAuthentication);

		if (log.isTraceEnabled()) {
			log.trace("Validated token request parameters");
		}

		Authentication principal = getPrincipal(subjectAuthorization, actorAuthorization);
		Map<String, Object> tokenData = relyingPartyService.getTokenExchangeUserData(subjectTokenClaims, jwtClaimsSet, relyingParty, claimsParty, rpOidcClient.get(), authorizedScopes);
		addAuthTimeToToken(tokenData, subjectTokenClaims);
		isValidTokenData(tokenData, relyingParty, claimsParty);
		addSidToToken(tokenData);
		addAcrToToken(tokenData, subjectAcrs, claimsParty, relyingParty, cpOidcConfig, rpOidcClient.get());
		addDPopClaim(tokenData, dPoPProof);

		var authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
													  .principalName(subjectAuthorization.getPrincipalName())
													  .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
													  .authorizedScopes(authorizedScopes)
													  .attributes(attrs -> attrs.putAll(tokenData));

		var tokenContextBuilder = generateTokenContext(registeredClient, principal, authorizedScopes, tokenExchangeAuthentication, dPoPProof);

		var tokens = generateAndSaveTokens(authorizationBuilder, tokenExchangeAuthentication, tokenContextBuilder, relyingParty, tokenData, rpOidcClient.get());

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, tokenExchangeAuthentication.getRequestedTokenType());

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal,
				(OAuth2AccessToken) tokens.get(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN), (OAuth2RefreshToken) tokens.get(OidcUtil.TOKEN_RESPONSE_REFRESH_TOKEN), additionalParameters);
	}

	private void addDPopClaim( Map<String, Object> tokenData, Jwt dPoPProof) {
		if (dPoPProof == null) {
			return;
		}
		tokenData.put(OidcUtil.OIDC_TOKEN_CNF, JwtUtil.getCnfValueFromHeader(dPoPProof.getHeaders()));
	}

	private void validateClaimsProviderMapping(RelyingParty relyingParty, ClaimsParty claimsParty) {
		var claimsProviderMappings = relyingParty.getClaimsProviderMappings();
		if (claimsProviderMappings == null) {
			log.error("Missing ClaimsProviderMappings for RelyingParty={}", relyingParty.getId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}
		var claimsProviderList = claimsProviderMappings.getClaimsProviderList();
		var rpCp = claimsProviderList.stream()
									 .filter(claimsProvider -> claimsProvider.getId().equals(claimsParty.getId()))
									 .findAny();
		if (rpCp.isEmpty()) {
			log.error("Missing ClaimsProviderMapping for ClaimParty={} in RelyingParty={}", claimsParty.getId(), relyingParty.getId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}
	}

	private void addAcrToToken(Map<String, Object> tokenData, List<String> subjectAcrs, ClaimsParty claimsParty, RelyingParty relyingParty, OidcClient cpOidcConfig, OidcClient rpOidcClient) {
		if (subjectAcrs != null && !subjectAcrs.isEmpty()) {
			var cpQoa = cpOidcConfig.getQoa() != null ? cpOidcConfig.getQoa() : claimsParty.getQoa();
			var rpQoa = rpOidcClient.getQoa() != null ? rpOidcClient.getQoa() : relyingParty.getQoa();
			var comparison = cpQoa.getComparison() != null ? cpQoa.getComparison() : QoaComparison.EXACT;
			var qoaSpec = qoaMappingService.mapRequestQoasToOutbound(comparison, subjectAcrs, new QoaConfig(cpQoa, claimsParty.getId()),
					new QoaConfig(rpQoa, relyingParty.getId()));
			List<String> outboundQoas = qoaSpec.contextClasses();

			if (outboundQoas != null && !outboundQoas.isEmpty()) {
				tokenData.put(OidcUtil.OIDC_ACR, outboundQoas);
			}
		}
	}

	private void addSidToToken(Map<String, Object> tokenData) {
		var sessionId = HttpExchangeSupport.getOrCreateSessionId();
		if (sessionId != null) {
			tokenData.put(OidcUtil.OIDC_SID, sessionId);
		}
	}

	private void addAuthTimeToToken(Map<String, Object> tokenData, Map<String, Object> subjectTokenClaims) {
		if (subjectTokenClaims != null && subjectTokenClaims.get(IdTokenClaimNames.AUTH_TIME) != null) {
			tokenData.put(IdTokenClaimNames.AUTH_TIME, subjectTokenClaims.get(IdTokenClaimNames.AUTH_TIME));
		}
	}

	private static Map<String, Object> getActorClaims(Map<String, Object> subjectTokenClaims, Map<String, Object> authorizedActorClaims) {
		if (subjectTokenClaims != null && subjectTokenClaims.containsKey(MAY_ACT) && subjectTokenClaims.get(MAY_ACT) instanceof Map<?, ?> mayAct) {
			authorizedActorClaims = (Map<String, Object>) mayAct;
		}
		return authorizedActorClaims;
	}

	private static void isValidTokenData(Map<String, Object> tokenData, RelyingParty relyingParty, ClaimsParty claimsParty) {
		if (tokenData.isEmpty()) {
			log.error("No token data found for subject token. In relyingParty={} claims={}", relyingParty.getId(), claimsParty);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
		}
	}

	private static String validateAndGetSubject(Assertion assertion, String registeredClientId) {
		if (assertion.getSubject() == null) {
			log.error("Missing SAML2 assertion subject for token exchange clientId={}", registeredClientId);
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}

		return assertion.getSubject().getNameID().getValue();
	}

	private static void validateTokenAuthorization(OAuth2Authorization.Token<OAuth2Token> subjectAuthorizationToken, String subjectTokenType) {
		if (subjectAuthorizationToken != null && !subjectAuthorizationToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked
			// [...].
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!isValidTokenType(subjectTokenType, subjectAuthorizationToken)) {
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}
	}

	private static void validateInputParams(Optional<OidcClient> rpOidcClient, RegisteredClient registeredClient, String registeredClientId, OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication) {
		if (rpOidcClient.isEmpty() || registeredClient == null) {
			log.error("Missing OIDC client configuration for token exchange clientId={}", registeredClientId);
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}

		if (log.isTraceEnabled()) {
			log.trace("Retrieved authorization with token for client {}", registeredClientId);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.TOKEN_EXCHANGE)) {
			log.error("Missing authorization grant type for token exchange authentication clientId={}", registeredClientId);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType()) && !OAuth2TokenFormat.SELF_CONTAINED.equals(registeredClient.getTokenSettings().getAccessTokenFormat())) {
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}
	}

	private Map<String, Set<String>> validateRequestParamAndRetrieveScopes(OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, RegisteredClient registeredClient, OAuth2Authorization subjectAuthorization, OidcClient oidcClient, Map<String, Object> subjectTokenClaims) {
		Map<String, Set<String>> requestParams = new HashMap<>();
		if (!CollectionUtils.isEmpty(tokenExchangeAuthentication.getScopes())) {
			requestParams.put(REQUEST_SCOPES, validateRequestedScopes(registeredClient, tokenExchangeAuthentication.getScopes()));
		}
		else if (!CollectionUtils.isEmpty(subjectAuthorization.getAuthorizedScopes())) {
			requestParams.put(REQUEST_SCOPES, validateRequestedScopes(registeredClient, subjectAuthorization.getAuthorizedScopes()));
		}
		else if (oidcClient.getScopes() != null) {
			log.error("Scopes are missing in={}, configured scopes={}", oidcClient.getId(), oidcClient.getScopes());
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}
		else {
			requestParams.put(REQUEST_SCOPES, new LinkedHashSet<>(Set.of(OidcScopes.OPENID)));
		}

		var audiences = tokenExchangeAuthentication.getAudiences();
		validateRequestedAudiences(audiences, oidcClient);
		if (!CollectionUtils.isEmpty(audiences)) {
			subjectTokenClaims.put(REQUEST_AUDIENCES, audiences);
			requestParams.put(REQUEST_AUDIENCES, audiences);
		}

		var resources = tokenExchangeAuthentication.getResources();
		validateRequestResources(resources, oidcClient);
		if (!CollectionUtils.isEmpty(resources)) {
			subjectTokenClaims.put(REQUEST_RESOURCES, resources);
			requestParams.put(REQUEST_RESOURCES, resources);
		}
		return requestParams;
	}

	private OAuth2Authorization getOAuth2AuthorizationWithActorToken(OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, Map<String, Object> authorizedActorClaims) {
		OAuth2Authorization actorAuthorization = null;
		if (StringUtils.hasText(tokenExchangeAuthentication.getActorToken())) {
			actorAuthorization = this.authorizationService.findByToken(tokenExchangeAuthentication.getActorToken(), OAuth2TokenType.ACCESS_TOKEN);
			if (actorAuthorization == null) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}

			if (log.isTraceEnabled()) {
				log.trace("Retrieved authorization with actor token");
			}

			OAuth2Authorization.Token<OAuth2Token> actorToken = actorAuthorization.getToken(tokenExchangeAuthentication.getActorToken());
			validateTokenAuthorization(actorToken, tokenExchangeAuthentication.getActorTokenType());

			if (authorizedActorClaims != null) {
				validateClaims(authorizedActorClaims, actorToken.getClaims(), OAuth2TokenClaimNames.ISS, OAuth2TokenClaimNames.SUB);
			}
		}
		else if (authorizedActorClaims != null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
		return actorAuthorization;
	}

	private Function<String, Optional<JWK>> getJWKForClaimParty(ClaimsParty claimsParty) {
		return oidcMetadataCacheService.jwtKeySupplier(claimsParty);
	}

	private void validateRequestResources(Set<String> resources, OidcClient oidcClient) {
		Set<String> configResources = oidcClient.getResources();
		if (configResources != null && !configResources.containsAll(resources)) {
			log.error("Resources={} are not matching configured resources={}", resources, configResources);
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}
	}

	private void validateRequestedAudiences(Set<String> audiences, OidcClient oidcClient) {
		Set<String> configAudiences = oidcClient.getAudiences();
		if (configAudiences != null && !configAudiences.containsAll(audiences)) {
			log.error("Audiences={} are not matching configured audience={}", audiences, configAudiences);
			throw new OAuth2AuthenticationException(INVALID_REQUEST);
		}
	}

	private Map<String, OAuth2Token> generateAndSaveTokens(OAuth2Authorization.Builder subjectAuthorizationBuilder, OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication,
													DefaultOAuth2TokenContext.Builder tokenContextBuilder, RelyingParty relyingParty, Map<String, Object> tokenData, OidcClient rpOidcClient) {
		OAuth2TokenContext tokenContext = tokenContextBuilder.build();

		OAuth2Token token = null;
		if (SAML2_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType())) {
			var saml2TokenGenerator = new Saml2TokenGenerator(relyingParty, trustBrokerProperties);
			token = saml2TokenGenerator.generate(tokenContext);
		}
		else {
			var nimbusJwtEncoder = new NimbusJwtEncoder(new FirstJwkSource(jwkSource));
			var jwtGenerator = new JwtGenerator(nimbusJwtEncoder);
			jwtGenerator.setJwtCustomizer(new TokenExchangeResponseCustomizer(tokenData, rpOidcClient, trustBrokerProperties));
			token = jwtGenerator.generate(tokenContext);
			if (token == null) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}
		}

		Map<String, OAuth2Token> tokens = new HashMap<>();

		var accessToken = CustomOAuth2AuthenticationProviderUtils.accessToken(subjectAuthorizationBuilder, token, tokenContext);
		tokens.put(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN, accessToken);
		if (rpOidcClient != null && canIssueIdToken(rpOidcClient)) {
			var idToken = CustomOAuth2AuthenticationProviderUtils.idToken(subjectAuthorizationBuilder, token);
			tokens.put(OidcUtil.TOKEN_RESPONSE_ID_TOKEN, idToken);
		}

		if (rpOidcClient != null && canIssueRefreshToken(rpOidcClient)) {
			var refreshToken = CustomOAuth2AuthenticationProviderUtils.refreshToken(subjectAuthorizationBuilder, token);
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

	private boolean canIssueRefreshToken(OidcClient oidcClient) {
		var authorizationGrantTypes = oidcClient.getAuthorizationGrantTypes();
		if (authorizationGrantTypes == null) {
			return false;
		}
		var types = authorizationGrantTypes.getGrantTypes();
		for (var type : types) {
			if (AuthorizationGrantType.REFRESH_TOKEN.equals(type.getType())) {
				return true;
			}
		}
		return false;
	}

	private boolean canIssueIdToken(OidcClient oidcClient) {
		var authorizationGrantTypes = oidcClient.getAuthorizationGrantTypes();
		var scopes = oidcClient.getScopes();
		if (authorizationGrantTypes == null || scopes == null) {
			return false;
		}
		var types = authorizationGrantTypes.getGrantTypes();
		for (var type : types) {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(type.getType()) && scopes.getScopeList().contains(OidcScopes.OPENID)) {
				return true;
			}
		}
		return false;
	}

	private static DefaultOAuth2TokenContext.Builder generateTokenContext(RegisteredClient registeredClient, Authentication principal, Set<String> authorizedScopes, OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, Jwt dPoPProof) {
		var tokenContextBuilder = DefaultOAuth2TokenContext.builder()
														   .registeredClient(registeredClient)
														   .principal(principal)
														   .authorizationServerContext(AuthorizationServerContextHolder.getContext()).authorizedScopes(authorizedScopes)
														   .tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
														   .authorizationGrant(tokenExchangeAuthentication);

		if (dPoPProof != null) {
			tokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProof);
		}

		return tokenContextBuilder;
	}

	private static Map<String, Object> extractSamlClaims(Assertion assertion) {
		Map<String, Object> samlAttributes = new HashMap<>();
		if (!assertion.getAttributeStatements().isEmpty()) {
			var assertionAttributes = assertion.getAttributeStatements().get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				var values = SamlUtil.getValuesFromAttribute(attribute);
				if (namespaceUri != null && !values.isEmpty()) {
					samlAttributes.put(namespaceUri, values); // free to be processed afterward
				}
			}
		}
		return samlAttributes;
	}

	private static boolean isValidTokenType(String tokenType, OAuth2Authorization.Token<OAuth2Token> token) {
		if (token == null) {
			return false;
		}
		String tokenFormat = token.getMetadata(OAuth2TokenFormat.class.getName());
		return ACCESS_TOKEN_TYPE_VALUE.equals(tokenType) || JWT_TOKEN_TYPE_VALUE.equals(tokenType) && OAuth2TokenFormat.SELF_CONTAINED.getValue().equals(tokenFormat);
	}

	private static boolean isValidTokenType(String tokenType) {
		return ACCESS_TOKEN_TYPE_VALUE.equals(tokenType) || JWT_TOKEN_TYPE_VALUE.equals(tokenType);
	}

	private static Set<String> validateRequestedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
		for (String requestedScope : requestedScopes) {
			if (!registeredClient.getScopes().contains(requestedScope)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
			}
		}

		return new LinkedHashSet<>(requestedScopes);
	}

	private static void validateClaims(Map<String, Object> expectedClaims, Map<String, Object> actualClaims, String... claimNames) {
		if (actualClaims == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		for (String claimName : claimNames) {
			if (!Objects.equals(expectedClaims.get(claimName), actualClaims.get(claimName))) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}
		}
	}

	private static Authentication getPrincipal(OAuth2Authorization subjectAuthorization, OAuth2Authorization actorAuthorization) {
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
