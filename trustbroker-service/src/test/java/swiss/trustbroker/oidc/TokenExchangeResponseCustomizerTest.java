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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

@ExtendWith(MockitoExtension.class)
class TokenExchangeResponseCustomizerTest {

	private static final String CLIENT_ID = "test-client-id";
	private static final String KEY_ID = "test-key-id";
	private static final Long TOKEN_LIFETIME_SEC = 3600L;

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private TrustBrokerProperties properties;

	@Mock
	private JWKSource<SecurityContext> jwkSource;

	@Mock
	private OidcAuditService auditService;

	private TokenExchangeResponseCustomizer customizer;

	private JwtEncodingContext context;

	@BeforeEach
	void setUp() {
		HttpExchangeSupport.end();
		customizer = new TokenExchangeResponseCustomizer(relyingPartyDefinitions, properties, jwkSource, auditService);
		context = mock(JwtEncodingContext.class);
	}

	private static void mockClaimBuilder(JwtEncodingContext context) {
		var claimsBuilder = mockClaims(context);
		when(claimsBuilder.build()).thenReturn(mock(JwtClaimsSet.class));
	}

	private static JwtClaimsSet.Builder mockClaims(JwtEncodingContext context) {
		var claimsBuilder = mock(JwtClaimsSet.Builder.class);
		when(context.getClaims()).thenReturn(claimsBuilder);
		when(claimsBuilder.claim(anyString(), any())).thenReturn(claimsBuilder);
		return claimsBuilder;
	}

	private void mockProperties() {
		var securityProperties = mock(SecurityChecks.class);
		when(properties.getSecurity()).thenReturn(securityProperties);
		when(securityProperties.getTokenLifetimeSec()).thenReturn(TOKEN_LIFETIME_SEC);
	}

	@Test
	void customizeWithValidClient() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_ISSUED_AT), any());
		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_NOT_BEFORE), any());
		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_EXPIRATION_TIME), any());
		verify(auditService).auditTokenClaims(eq(CLIENT_ID), eq(context), isNull(),
				isNull(), isNull(), eq(properties), any(), any());
	}

	@Test
	void customizeWithMissingClientConfiguration() {
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.empty());

		mockClaims(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);

		var exception = assertThrows(TechnicalException.class, () -> customizer.customize(context));
		assertThat(exception.getInternalMessage(), is("Missing OIDC client configuration for=" + CLIENT_ID));
	}

	@Test
	void customizeWithClientSpecificTokenTimeToLive() {
		int customTokenLifeMin = 30; // 30 minutes
		OidcClient oidcClient = givenOidcClient(customTokenLifeMin);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_EXPIRATION_TIME), any());
	}

	@Test
	void customizeWithDefaultTokenTimeToLive() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));
		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_EXPIRATION_TIME), any());
	}

	@Test
	void customizeNormalizeAudienceFromCollection() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(List.of("aud1", "aud2"));

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_AUDIENCE), any());
	}

	@Test
	void customizeNormalizeAudienceFromSingleValue() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn("single-audience");

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_AUDIENCE), any());
	}

	@Test
	void customizeNormalizeAudienceNull() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_ISSUED_AT), any());
	}

	@Test
	void customizeNormalizeIssuerFromUrl() throws Exception {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(new URI("https://issuer.example.com").toURL());

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_ISSUER), any());
	}

	@Test
	void customizeNormalizeIssuerFromString() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn("https://issuer.example.com");

		customizer.customize(context);

		verify(context.getClaims()).claim(eq(OidcUtil.OIDC_ISSUER), any());
	}

	@Test
	void customizeWithKeyIdFromJwkSource() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();
		mockJwsHeader();

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getJwsHeader()).keyId(anyString());
	}

	@Test
	void customizeAddAttributesFromTokenExchangeAuthenticationToken() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("custom_claim", "custom_value");
		attributes.put("another_claim", 12345);

		mockClaims(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("custom_claim", "custom_value");
		verify(context.getClaims()).claim("another_claim", 12345);
	}

	private void mockJwsHeader() {
		JwsHeader.Builder jwsHeader = mock(JwsHeader.Builder.class);
		when(context.getJwsHeader()).thenReturn(jwsHeader);
		when(jwsHeader.keyId(anyString())).thenReturn(jwsHeader);
		try {
			RSAKey rsaKey = new RSAKey.Builder(new Base64URL("modulus"), new Base64URL("exponent"))
					.keyID(KEY_ID)
					.build();
			List<JWK> jwks = List.of(rsaKey);
			when(jwkSource.get(any(), any())).thenReturn(jwks);
		}
		catch (KeySourceException e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	void customizeAddAttributesFromAuthorizationGrant() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("role", "admin");

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var authorization = mock(OAuth2Authorization.class);
		when(authorization.getAttributes()).thenReturn(attributes);
		when(context.getAuthorization()).thenReturn(authorization);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("role", "admin");
	}

	@Test
	void customizeHandleInstantAttribute() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Instant instantValue = Instant.now();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("instant_claim", instantValue);

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("instant_claim", instantValue.getEpochSecond());
	}

	@Test
	void customizeHandleDateAttribute() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Date dateValue = new Date();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("date_claim", dateValue);

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("date_claim", dateValue.toInstant().getEpochSecond());
	}

	@Test
	void customizeHandleCollectionWithSingleElement() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("single_collection", List.of("single_value"));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("single_collection",  List.of("single_value"));
	}

	@Test
	void customizeHandleCollectionWithMultipleElements() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("multi_collection", List.of("value1", "value2", "value3"));

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim(eq("multi_collection"), any());
	}

	@Test
	void customizeHandleMapAttribute() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> mapValue = new HashMap<>();
		mapValue.put("jkt", "test-jkt-value");

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("cnf", mapValue);

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("cnf", mapValue);
	}

	@Test
	void customizeIgnoreNullAttributeValues() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("null_claim", null);

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims(), org.mockito.Mockito.times(3)).claim(anyString(), any());
	}

	@Test
	void customizeIgnoreNonStringKeyInAttributes() {
		OidcClient oidcClient = givenOidcClient(null);
		when(relyingPartyDefinitions.getOidcClientConfigById(CLIENT_ID, properties))
				.thenReturn(Optional.of(oidcClient));

		Map<Object, Object> attributes = new HashMap<>();
		attributes.put(123, "numeric_key_value");
		attributes.put("string_key", "string_key_value");

		mockClaimBuilder(context);
		mockRegisteredClientWithGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
		mockProperties();

		var tokenExchangeToken = mock(OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeToken.getDetails()).thenReturn(attributes);
		when(context.getAuthorizationGrant()).thenReturn(tokenExchangeToken);

		var claimsSet = mock(JwtClaimsSet.class);
		when(context.getClaims().build()).thenReturn(claimsSet);
		when(claimsSet.getClaim(OidcUtil.OIDC_AUDIENCE)).thenReturn(null);
		when(claimsSet.getClaim(OidcUtil.OIDC_ISSUER)).thenReturn(null);

		customizer.customize(context);

		verify(context.getClaims()).claim("string_key", "string_key_value");
	}

	@ParameterizedTest
	@MethodSource("convertStringToMapCases")
	void convertStringToMapCases(List<String> input, Object expected) {
		Object result = assertDoesNotThrow(() -> customizer.convertStringToMap(input));
		assertEquals(expected, result);
	}

	private static Stream<Arguments> convertStringToMapCases() {
		return Stream.of(
				Arguments.of(null, null),
				Arguments.of(List.of(), List.of()),
				Arguments.of(List.of("a", "b"), List.of("a", "b")),
				Arguments.of(java.util.Collections.singletonList(null), java.util.Collections.singletonList(null)),
				Arguments.of(List.of("plain-value"), List.of("plain-value")),
				Arguments.of(List.of("{}"), Map.of()),
				Arguments.of(List.of("{k1=v1, k2=v2}"), Map.of("k1", "v1", "k2", "v2")),
				Arguments.of(List.of("{broken}"), "{broken}")
		);
	}

	private void mockRegisteredClientWithGrantType(AuthorizationGrantType grantType) {
		RegisteredClient registeredClient = RegisteredClient.withId(CLIENT_ID)
		                                                    .clientId(CLIENT_ID)
		                                                    .authorizationGrantType(grantType)
		                                                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
		                                                    .build();
		when(context.getRegisteredClient()).thenReturn(registeredClient);
	}

	private OidcClient givenOidcClient(Integer tokenTimeToLiveMin) {
		var securityPolicies = mock(OidcSecurityPolicies.class);
		when(securityPolicies.getTokenTimeToLiveMin()).thenReturn(tokenTimeToLiveMin);

		var oidcClient = mock(OidcClient.class);
		when(oidcClient.getOidcSecurityPolicies()).thenReturn(securityPolicies);

		return oidcClient;
	}
}

