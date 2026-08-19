/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantTypes;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Scope;
import swiss.trustbroker.federation.xmlconfig.Scopes;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.oidc.pkce.PublicClientAuthenticationToken;
import swiss.trustbroker.saml.service.RelyingPartyService;

class CustomOAuth2TokenExchangeAuthenticationProviderTest {

	private QoaMappingService qoaMappingService;

	@BeforeEach
	void setUp() {
		qoaMappingService = mock(QoaMappingService.class);
	}

	@Test
	void addRequestParamIfNotNullAddsEntry() {
		var provider = givenProvider();
		Map<String, Set<String>> requestParams = new HashMap<>();

		provider.addRequestParamIfNotNull(requestParams, "request_scope", "openid");

		assertEquals(Set.of("openid"), requestParams.get("request_scope"));
		assertEquals(1, requestParams.size());
	}

	@Test
	void addRequestParamIfNotNullIgnoresNullValue() {
		var provider = givenProvider();
		Map<String, Set<String>> requestParams = new HashMap<>();

		provider.addRequestParamIfNotNull(requestParams, "request_scope", null);

		assertTrue(requestParams.isEmpty());
	}

	@Test
	void supportsTokenExchangeAuthenticationToken() {
		var provider = givenProvider();

		assertTrue(provider.supports(OAuth2TokenExchangeAuthenticationToken.class));
	}

	@Test
	void supportsRejectsOtherAuthenticationType() {
		var provider = givenProvider();

		assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
	}

	@Test
	void addAudToTokenAddsClientIdAndRequestedAudiences() {
		var provider = givenProvider();
		Map<String, Object> tokenData = new HashMap<>();
		Map<String, Set<String>> requestParams = new HashMap<>();
		requestParams.put("audience", Set.of("api-1", "api-2"));

		provider.addAudToToken(tokenData, requestParams, "client-1");
		assertEquals(Set.of("client-1", "api-1", "api-2"), tokenData.get("aud"));

		requestParams.put("resource", Set.of("resource-1", "resource-2"));

		provider.addAudToToken(tokenData, requestParams, "client-1");
		assertEquals(Set.of("client-1", "api-1", "api-2","resource-1", "resource-2" ), tokenData.get("aud"));

		requestParams = new HashMap<>();
		requestParams.put("resource", Set.of("resource-1", "resource-2"));
		provider.addAudToToken(tokenData, requestParams, "client-1");
		assertEquals(Set.of("client-1", "resource-1", "resource-2" ), tokenData.get("aud"));
	}

	@Test
	void addAudToTokenIgnoresMissingAudience() {
		var provider = givenProvider();
		Map<String, Object> tokenData = new HashMap<>();

		provider.addAudToToken(tokenData, Map.of(), "client-1");

		assertFalse(tokenData.containsKey("aud"));
	}

	@Test
	void addAzpTokenAddsAuthorizedPartyWhenMissing() {
		var provider = givenProvider();
		Map<String, Object> tokenData = new HashMap<>();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		provider.addAzpToken(tokenData, rpOidcClient);

		assertEquals("rp-client", tokenData.get("azp"));
	}

	@Test
	void addAzpTokenKeepsExistingAuthorizedParty() {
		var provider = givenProvider();
		Map<String, Object> tokenData = new HashMap<>();
		tokenData.put("azp", "existing-client");
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		provider.addAzpToken(tokenData, rpOidcClient);

		assertEquals("existing-client", tokenData.get("azp"));
	}

	@Test
	void validateClaimsPartyThrowsOnNull() {
		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaimsParty(null, "issuer"));

		assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
	}

	@Test
	void validateClaimsPartyAcceptsConfiguredClaimsParty() {
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaimsParty(
				givenClaimsParty(), "issuer"));
	}

	@Test
	void validateRpClientThrowsOnNull() {
		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateRpClient(null, "client-1"));

		assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
	}

	@Test
	void validateRpClientReturnsClient() {
		var rpOidcClient = OidcClient.builder().id("client-1").build();

		assertSame(rpOidcClient, CustomOAuth2TokenExchangeAuthenticationProvider.validateRpClient(rpOidcClient, "client-1"));
	}

	@Test
	void validateRegisteredClientThrowsOnNull() {
		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateRegisteredClient(null, "client-1"));

		assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, ex.getError().getErrorCode());
	}

	@Test
	void validateRegisteredClientAcceptsConfiguredClient() {
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateRegisteredClient(givenRegisteredClient(), "client-1"));
	}

	@Test
	void validateClaimSetThrowsOnNull() {
		var claimsParty = givenClaimsParty();

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaimSet(null, claimsParty));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateClaimSetAcceptsClaims() {
		var claimsParty = givenClaimsParty();

		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaimSet(
				new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("user").build(), claimsParty));
	}

	@Test
	void addAcrToTokenAddsMappedOutboundAcrs() {
		when(qoaMappingService.mapRequestQoasToOutbound(eq(QoaComparison.EXACT), eq(List.of("acr-1")), any(), any()))
				.thenReturn(new QoaSpec(QoaComparison.EXACT, List.of("mapped-acr")));
		var provider = givenProvider(qoaMappingService);
		Map<String, Object> tokenData = new HashMap<>();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(OidcClient.builder().id("cp-client").build());
		var relyingParty = givenRelyingParty();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		provider.addAcrToToken(tokenData, List.of("acr-1"), claimsParty, relyingParty, rpOidcClient);

		assertEquals("mapped-acr", tokenData.get("acr"));
	}

	@Test
	void addAcrToTokenIgnoresEmptySubjectAcrs() {
		var provider = givenProvider();
		Map<String, Object> tokenData = new HashMap<>();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(OidcClient.builder().id("cp-client").build());
		var relyingParty = givenRelyingParty();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		provider.addAcrToToken(tokenData, List.of(), claimsParty, relyingParty, rpOidcClient);

		assertFalse(tokenData.containsKey("acr"));
	}

	@Test
	void getActorClaimsReturnsMayActClaims() {
		Map<String, Object> mayAct = Map.of("sub", "actor");
		Map<String, Object> subjectClaims = new HashMap<>();
		subjectClaims.put("may_act", mayAct);

		assertEquals(mayAct, CustomOAuth2TokenExchangeAuthenticationProvider.getActorClaims(subjectClaims));
	}

	@Test
	void getActorClaimsReturnsEmptyMapForMissingOrInvalidClaim() {
		assertTrue(CustomOAuth2TokenExchangeAuthenticationProvider.getActorClaims(null).isEmpty());
		assertTrue(CustomOAuth2TokenExchangeAuthenticationProvider.getActorClaims(Map.of("may_act", "wrong")).isEmpty());
	}

	@Test
	void isValidTokenDataThrowsOnEmptyTokenData() {
		var relyingParty = givenRelyingParty();
		var claimsParty = givenClaimsParty();
		Map<String, Object> tokenData = Map.of();

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.isValidTokenData(tokenData, relyingParty, claimsParty));

		assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, ex.getError().getErrorCode());
	}

	@Test
	void isValidTokenDataAcceptsNonEmptyTokenData() {
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.isValidTokenData(
				Map.of("sub", "user"), givenRelyingParty(), givenClaimsParty()));
	}

	@Test
	void validateAndGetSubjectReturnsSubjectNameId() {
		var assertion = mock(Assertion.class);
		var subject = mock(Subject.class);
		var nameId = mock(NameID.class);
		when(assertion.getSubject()).thenReturn(subject);
		when(subject.getNameID()).thenReturn(nameId);
		when(nameId.getValue()).thenReturn("user-1");

		assertEquals("user-1", CustomOAuth2TokenExchangeAuthenticationProvider.validateAndGetSubject(assertion, "client-1"));
	}

	@Test
	void validateAndGetSubjectThrowsWithoutSubject() {
		var assertion = mock(Assertion.class);
		when(assertion.getSubject()).thenReturn(null);

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateAndGetSubject(assertion, "client-1"));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateTokenAuthorizationThrowsForInactiveToken() {
		var token = mockAuthorizationToken();
		when(token.isActive()).thenReturn(false);

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenAuthorization(token, "urn:ietf:params:oauth:token-type:access_token"));

		assertEquals(OAuth2ErrorCodes.INVALID_GRANT, ex.getError().getErrorCode());
	}

	@Test
	void validateTokenAuthorizationAcceptsActiveAccessToken() {
		var token = mockAuthorizationToken();
		when(token.isActive()).thenReturn(true);
		when(token.getMetadata(OAuth2TokenFormat.class.getName())).thenReturn(OAuth2TokenFormat.REFERENCE.getValue());

		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenAuthorization(
				token, "urn:ietf:params:oauth:token-type:access_token"));
	}

	@Test
	void validateTokenTypeRejectsNullToken() {
		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType(
						"urn:ietf:params:oauth:token-type:access_token", null));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateTokenTypeAcceptsSelfContainedJwt() {
		var token = mockAuthorizationToken();
		when(token.getMetadata(OAuth2TokenFormat.class.getName())).thenReturn(OAuth2TokenFormat.SELF_CONTAINED.getValue());

		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType(
				"urn:ietf:params:oauth:token-type:jwt", token));
	}

	@Test
	void validateTokenTypeRejectsReferenceJwt() {
		var token = mockAuthorizationToken();
		when(token.getMetadata(OAuth2TokenFormat.class.getName())).thenReturn(OAuth2TokenFormat.REFERENCE.getValue());

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType(
						"urn:ietf:params:oauth:token-type:jwt", token));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateTokenTypeWithoutTokenAcceptsSupportedTypes() {
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType(
				"urn:ietf:params:oauth:token-type:access_token"));
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType(
				"urn:ietf:params:oauth:token-type:jwt"));
	}

	@Test
	void validateTokenTypeWithoutTokenRejectsUnsupportedType() {
		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateTokenType("unsupported"));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateRequestedScopesReturnsRequestedScopes() {
		var registeredClient = givenRegisteredClient();

		assertEquals(new LinkedHashSet<>(Set.of(Scope.OPENID.getName())),
				CustomOAuth2TokenExchangeAuthenticationProvider.validateRequestedScopes(registeredClient, Set.of(Scope.OPENID.getName())));
	}

	@Test
	void validateRequestedScopesRejectsUnknownScope() {
		var registeredClient = givenRegisteredClient();
		var requestedScopes = Set.of("unknown");

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateRequestedScopes(registeredClient, requestedScopes));

		assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, ex.getError().getErrorCode());
	}

	@Test
	void validateClaimsAcceptsMatchingClaims() {
		assertDoesNotThrow(() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaims(
				Map.of("iss", "issuer", "sub", "user"), Map.of("iss", "issuer", "sub", "user"), "iss", "sub"));
	}

	@Test
	void validateClaimsRejectsMissingActualClaims() {
		Map<String, Object> tokenData = Map.of("iss", "issuer");

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaims(tokenData, null, "iss"));

		assertEquals(OAuth2ErrorCodes.INVALID_GRANT, ex.getError().getErrorCode());
	}

	@Test
	void validateClaimsRejectsMismatch() {
		Map<String, Object> expectedClaims = Map.of("iss", "issuer");
		Map<String, Object> actualClaims = Map.of("iss", "other");

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomOAuth2TokenExchangeAuthenticationProvider.validateClaims(expectedClaims, actualClaims, "iss"));

		assertEquals(OAuth2ErrorCodes.INVALID_GRANT, ex.getError().getErrorCode());
	}

	@Test
	void getPrincipalReturnsSubjectWithoutActor() {
		var subjectAuthorization = mock(OAuth2Authorization.class);
		Authentication subject = new UsernamePasswordAuthenticationToken("user", null);
		when(subjectAuthorization.getAttribute(Principal.class.getName())).thenReturn(subject);

		assertSame(subject, CustomOAuth2TokenExchangeAuthenticationProvider.getPrincipal(subjectAuthorization, null));
	}

	@Test
	void getPrincipalUnwrapsCompositeSubjectWithoutActor() {
		var subjectAuthorization = mock(OAuth2Authorization.class);
		Authentication subject = new UsernamePasswordAuthenticationToken("user", null);
		var composite = new OAuth2TokenExchangeCompositeAuthenticationToken(subject, List.of(new OAuth2TokenExchangeActor(Map.of("sub", "actor"))));
		when(subjectAuthorization.getAttribute(Principal.class.getName())).thenReturn(composite);

		assertSame(subject, CustomOAuth2TokenExchangeAuthenticationProvider.getPrincipal(subjectAuthorization, null));
	}

	@Test
	void getPrincipalBuildsCompositeWhenActorAuthorizationExists() {
		var subjectAuthorization = mock(OAuth2Authorization.class);
		Authentication subject = new UsernamePasswordAuthenticationToken("user", null);
		when(subjectAuthorization.getAttribute(Principal.class.getName())).thenReturn(subject);
		var actorAuthorization = mock(OAuth2Authorization.class);
		var accessToken = mockAuthorizationAccessToken();
		when(accessToken.getClaims()).thenReturn(Map.of("sub", "actor-1"));
		when(actorAuthorization.getAccessToken()).thenReturn(accessToken);

		var result = CustomOAuth2TokenExchangeAuthenticationProvider.getPrincipal(subjectAuthorization, actorAuthorization);

		var composite = assertInstanceOf(OAuth2TokenExchangeCompositeAuthenticationToken.class, result);
		assertSame(subject, composite.getSubject());
		assertEquals(1, composite.getActors().size());
	}

	@Test
	void validateRpForPKCEAuthenticationRejectsPublicClientWhenDisabled() {
		var provider = givenProvider();
		var clientPrincipal = givenPublicClientAuthenticationToken();
		var rpOidcClient = OidcClient.builder()
				.id("rp-client")
				.oidcSecurityPolicies(OidcSecurityPolicies.builder().allowPublicClientTokenExchange(false).build())
				.build();

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> provider.validateRpForPKCEAuthentication(clientPrincipal, rpOidcClient));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void validateRpForPKCEAuthenticationAcceptsPublicClientWhenEnabled() {
		var provider = givenProvider();
		var clientPrincipal = givenPublicClientAuthenticationToken();
		var rpOidcClient = OidcClient.builder()
				.id("rp-client")
				.oidcSecurityPolicies(OidcSecurityPolicies.builder().allowPublicClientTokenExchange(true).build())
				.build();

		assertDoesNotThrow(() -> provider.validateRpForPKCEAuthentication(clientPrincipal, rpOidcClient));
	}

	@Test
	void validateRequestParamAndRetrieveScopesUsesSubjectAuthorizationScopesAndCopiesParams() {
		var provider = givenProvider();
		var authentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(authentication.getScopes()).thenReturn(Set.of());
		when(authentication.getAudiences()).thenReturn(Set.of());
		when(authentication.getResources()).thenReturn(Set.of());
		when(authentication.getSubjectToken()).thenReturn("subject-token");
		when(authentication.getSubjectTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
		when(authentication.getRequestedTokenType()).thenReturn("requested-token-type");
		when(authentication.getAdditionalParameters()).thenReturn(Map.of("foo", "bar"));
		var registeredClient = givenRegisteredClient();
		var subjectAuthorization = mock(OAuth2Authorization.class);
		when(subjectAuthorization.getAuthorizedScopes()).thenReturn(Set.of(Scope.OPENID.getName()));
		var oidcClient = OidcClient.builder().id("rp-client").scopes(Scopes.builder().scopeList(List.of(Scope.OPENID.getName())).build()).build();

		var result = provider.validateRequestParamAndRetrieveScopes(authentication, registeredClient, subjectAuthorization, oidcClient);

		assertEquals(Set.of(Scope.OPENID.getName()), result.get("request_scope"));
		assertEquals(Set.of("subject-token"), result.get("subject_token"));
		assertEquals(Set.of("urn:ietf:params:oauth:token-type:access_token"), result.get("subject_token_type"));
		assertEquals(Set.of("requested-token-type"), result.get("requested_token_type"));
		assertEquals(Set.of("bar"), result.get("request_foo"));
	}

	@Test
	void verifySubjectTokenUniqueOrSaveStoresToken() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), mockTokenGenerator());
		var jwtClaims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
				.issueTime(java.util.Date.from(Instant.parse("2026-06-18T10:15:30Z")))
				.expirationTime(java.util.Date.from(Instant.parse("2026-06-18T11:15:30Z")))
				.build();
		var oidcClient = OidcClient.builder()
				.id("rp-client")
				.oidcSecurityPolicies(OidcSecurityPolicies.builder().subjectTokenMaxUseCount(2).build())
				.build();

		assertDoesNotThrow(() -> provider.verifySubjectTokenUniqueOrSave(
				"subject-token", jwtClaims, "client-1", "user-1", oidcClient, new TrustBrokerProperties()));

		verify(authorizationService).saveTokenExchangeSubjectToken(eq("subject-token"), eq("client-1"), eq("user-1"), any(), any());
	}

	@Test
	void verifySubjectTokenUniqueOrSaveRejectsExceededUseCount() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		when(authorizationService.getSubjectTokenCount("subject-token")).thenReturn(1);
		var trustBrokerProperties = new TrustBrokerProperties();
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, trustBrokerProperties, mockTokenGenerator());
		var jwtClaims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
				.expirationTime(java.util.Date.from(Instant.parse("2026-06-18T11:15:30Z")))
				.build();
		var oidcClient = OidcClient.builder()
				.id("rp-client")
				.oidcSecurityPolicies(OidcSecurityPolicies.builder().subjectTokenMaxUseCount(1).build())
				.build();

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> provider.verifySubjectTokenUniqueOrSave(
				"subject-token", jwtClaims, "client-1", "user-1", oidcClient, trustBrokerProperties));

		assertEquals(OAuth2ErrorCodes.INVALID_TOKEN, ex.getError().getErrorCode());
	}

	@Test
	void getActorTokenAuthorizationReturnsNullWithoutMayActAndWithoutActorToken() {
		var provider = givenProvider();
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getActorToken()).thenReturn(null);

		assertNull(provider.getActorTokenAuthorization(Map.of("sub", "user"), tokenExchangeAuthentication, mock(OAuth2Authorization.class)));
	}

	@Test
	void getActorTokenAuthorizationRejectsActorTokenWithoutMayAct() {
		var provider = givenProvider();
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getActorToken()).thenReturn("actor-token");
		Map<String, Object> subjectTokenClaims = Map.of("sub", "user");

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> provider.getActorTokenAuthorization(subjectTokenClaims, tokenExchangeAuthentication, mock(OAuth2Authorization.class)));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void getActorTokenAuthorizationRejectsExternalActorAuthorization() {
		var properties = new TrustBrokerProperties();
		properties.getOidc().setExternalTokenExchangeEnabled(true);
		var provider = givenProvider(mock(QoaMappingService.class), mock(CustomOAuth2AuthorizationService.class), properties, mockTokenGenerator());
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getActorToken()).thenReturn("actor-token");
		Map<String, Object> subjectTokenClaims = Map.of("may_act", Map.of("iss", "iss-1", "sub", "sub-1"));

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> provider.getActorTokenAuthorization(subjectTokenClaims, tokenExchangeAuthentication, null));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void getActorTokenAuthorizationReturnsResolvedActorAuthorization() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), mockTokenGenerator());
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getActorToken()).thenReturn("actor-token");
		when(tokenExchangeAuthentication.getActorTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
		var actorAuthorization = mock(OAuth2Authorization.class);
		when(authorizationService.findByToken("actor-token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(actorAuthorization);
		var actorToken = mockAuthorizationToken();
		when(actorAuthorization.getToken("actor-token")).thenReturn(actorToken);
		when(actorToken.isActive()).thenReturn(true);
		when(actorToken.getMetadata(OAuth2TokenFormat.class.getName())).thenReturn(OAuth2TokenFormat.REFERENCE.getValue());
		when(actorToken.getClaims()).thenReturn(Map.of("iss", "iss-1", "sub", "sub-1"));
		var subjectAuthorization = mock(OAuth2Authorization.class);

		var result = provider.getActorTokenAuthorization(
				Map.of("may_act", Map.of("iss", "iss-1", "sub", "sub-1")), tokenExchangeAuthentication, subjectAuthorization);

		assertSame(actorAuthorization, result);
	}

	@Test
	void getOAuth2AuthorizationWithActorTokenRejectsUnknownActorToken() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), mockTokenGenerator());
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getActorToken()).thenReturn("actor-token");
		Map<String, Object> authorizedActorClaims = Map.of("iss", "iss-1", "sub", "sub-1");

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> provider.getOAuth2AuthorizationWithActorToken(tokenExchangeAuthentication, authorizedActorClaims));

		assertEquals(OAuth2ErrorCodes.INVALID_GRANT, ex.getError().getErrorCode());
	}

	@Test
	void generateAndSaveTokensThrowsWhenTokenGeneratorReturnsNull() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator = (OAuth2TokenGenerator<OAuth2Token>) mock(OAuth2TokenGenerator.class);
		when(tokenGenerator.generate(any())).thenReturn(null);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), tokenGenerator);
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getRequestedTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
		var registeredClient = givenRegisteredClient();
		var scopes = Set.of(Scope.OPENID.getName());
		var builder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("user")
				.authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.TOKEN_EXCHANGE)
				.authorizedScopes(scopes);
		var tokenContext = givenTokenContext(registeredClient);
		var relyingParty = givenRelyingParty();
		var authenticator = new UsernamePasswordAuthenticationToken("user", null);

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> provider.generateAndSaveTokens(builder, tokenExchangeAuthentication, tokenContext,
						relyingParty, null, registeredClient, authenticator, scopes));

		assertEquals(OAuth2ErrorCodes.SERVER_ERROR, ex.getError().getErrorCode());
	}

	@Test
	void generateAndSaveTokensReturnsAccessTokenAndSavesAuthorization() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator = (OAuth2TokenGenerator<OAuth2Token>) mock(OAuth2TokenGenerator.class);
		var generatedToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-123",
				Instant.parse("2026-06-18T10:15:30Z"), Instant.parse("2026-06-18T11:15:30Z"), Set.of(Scope.OPENID.getName()));
		when(tokenGenerator.generate(any())).thenReturn(generatedToken);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), tokenGenerator);
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getRequestedTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
		var registeredClient = givenRegisteredClient();
		var builder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("user")
				.authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.TOKEN_EXCHANGE)
				.authorizedScopes(Set.of(Scope.OPENID.getName()));
		var tokenContext = givenTokenContext(registeredClient);

		var tokens = provider.generateAndSaveTokens(builder, tokenExchangeAuthentication, tokenContext,
				givenRelyingParty(), null, registeredClient,
				new UsernamePasswordAuthenticationToken("user", null), Set.of(Scope.OPENID.getName()));

		assertNotNull(tokens.get(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN));
		assertEquals(1, tokens.size());
		verify(authorizationService).save(any(OAuth2Authorization.class));
	}

	@Test
	void generateAndSaveTokensAddsIdTokenWhenRpCanIssueIdToken() {
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator = (OAuth2TokenGenerator<OAuth2Token>) mock(OAuth2TokenGenerator.class);
		var generatedToken = new Jwt("jwt-123", Instant.parse("2026-06-18T10:15:30Z"), Instant.parse("2026-06-18T11:15:30Z"),
				Map.of("alg", "RS256"), Map.of("sub", "user-1", "aud", List.of("client-1")));
		when(tokenGenerator.generate(any())).thenReturn(generatedToken);
		var provider = givenProvider(mock(QoaMappingService.class), authorizationService, new TrustBrokerProperties(), tokenGenerator);
		var tokenExchangeAuthentication = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getRequestedTokenType()).thenReturn("urn:ietf:params:oauth:token-type:access_token");
		var registeredClient = givenRegisteredClient();
		var builder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("user")
				.authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.TOKEN_EXCHANGE)
				.authorizedScopes(Set.of(Scope.OPENID.getName()));
		var tokenContext = givenTokenContext(registeredClient);
		var rpOidcClient = OidcClient.builder()
				.id("rp-client")
				.authorizationGrantTypes(AuthorizationGrantTypes.builder()
						.grantTypes(List.of(swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType.AUTHORIZATION_CODE))
						.build())
				.scopes(Scopes.builder().scopeList(List.of(Scope.OPENID.getName())).build())
				.build();

		var tokens = provider.generateAndSaveTokens(builder, tokenExchangeAuthentication, tokenContext,
				givenRelyingParty(), rpOidcClient, registeredClient,
				new UsernamePasswordAuthenticationToken("user", null), Set.of(Scope.OPENID.getName()));

		assertNotNull(tokens.get(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN));
		assertInstanceOf(OidcIdToken.class, tokens.get(OidcUtil.TOKEN_RESPONSE_ID_TOKEN));
	}

	private static CustomOAuth2TokenExchangeAuthenticationProvider givenProvider() {
		return givenProvider(mock(QoaMappingService.class));
	}

	private static CustomOAuth2TokenExchangeAuthenticationProvider givenProvider(QoaMappingService qoaMappingService) {
		return givenProvider(qoaMappingService, mock(CustomOAuth2AuthorizationService.class), new TrustBrokerProperties(), mockTokenGenerator());
	}

	private static CustomOAuth2TokenExchangeAuthenticationProvider givenProvider(QoaMappingService qoaMappingService,
			CustomOAuth2AuthorizationService authorizationService, TrustBrokerProperties trustBrokerProperties,
			OAuth2TokenGenerator<OAuth2Token> tokenGenerator) {
		return new CustomOAuth2TokenExchangeAuthenticationProvider(
				mock(ClientConfigInMemoryRepository.class),
				authorizationService,
				mock(OidcMetadataCacheService.class),
				mock(RelyingPartyDefinitions.class),
				trustBrokerProperties,
				mock(RelyingPartyService.class),
				mock(RelyingPartySetupService.class),
				qoaMappingService,
				tokenGenerator
		);
	}

	private static RegisteredClient givenRegisteredClient() {
		return RegisteredClient.withId("reg-1")
				.clientId("client-1")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope(Scope.OPENID.getName())
				.scope("profile")
				.redirectUri("https://redirect.example.com")
				.build();
	}

	@SuppressWarnings("unchecked")
	private static OAuth2Authorization.Token<OAuth2Token> mockAuthorizationToken() {
		return mock(OAuth2Authorization.Token.class);
	}

	@SuppressWarnings("unchecked")
	private static OAuth2Authorization.Token<OAuth2AccessToken> mockAuthorizationAccessToken() {
		return mock(OAuth2Authorization.Token.class);
	}

	@SuppressWarnings("unchecked")
	private static OAuth2TokenGenerator<OAuth2Token> mockTokenGenerator() {
		return (OAuth2TokenGenerator<OAuth2Token>) mock(OAuth2TokenGenerator.class);
	}

	private static OAuth2TokenContext givenTokenContext(RegisteredClient registeredClient) {
		var tokenContext = mock(OAuth2TokenContext.class);
		when(tokenContext.getAuthorizedScopes()).thenReturn(Set.of(Scope.OPENID.getName()));
		when(tokenContext.getRegisteredClient()).thenReturn(registeredClient);
		return tokenContext;
	}

	private static Authentication givenPublicClientAuthenticationToken() {
		try {
			var constructor = PublicClientAuthenticationToken.class.getDeclaredConstructor(String.class);
			constructor.setAccessible(true);
			return constructor.newInstance("public-client");
		}
		catch (ReflectiveOperationException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static RelyingParty givenRelyingParty() {
		return RelyingParty.builder()
		                   .id("rp")
		                   .build();
	}

	private static ClaimsParty givenClaimsParty() {
		return ClaimsParty.builder()
		                  .id("cp")
		                  .build();
	}
}

