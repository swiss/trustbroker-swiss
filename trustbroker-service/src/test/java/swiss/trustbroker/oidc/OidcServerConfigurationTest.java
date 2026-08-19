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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderMetadataClaimNames;
import swiss.trustbroker.config.dto.OidcProperties;

class OidcServerConfigurationTest {

	private static final String CHECK_SESSION_IFRAME = "check_session_iframe";

	private static final String ID_TOKEN_ENCRYPTION_ALG = "id_token_encryption_alg_values_supported";

	private static final String ID_TOKEN_ENCRYPTION_METHOD = "id_token_encryption_enc_values_supported";

	private static final String USERINFO_ENCRYPTION_ALG = "userinfo_encryption_alg_values_supported";

	private static final String USERINFO_ENCRYPTION_METHOD = "userinfo_encryption_enc_values_supported";

	@Test
	void customizeProviderConfigurationEndpointAddsConfiguredClaims() {
		var oidcProperties = baseOidcProperties();
		oidcProperties.setLogoutEnabled(true);
		oidcProperties.setSessionIFrameEndpoint("https://issuer.example/session/iframe");
		oidcProperties.setTlsClientCertificateBoundAccessTokens(false);
		oidcProperties.setGrantTypes(List.of("authorization_code"));
		oidcProperties.setResponseTypes(List.of("code"));
		oidcProperties.setScopes(List.of("openid"));
		oidcProperties.setTokenEndpointAuthMethods(List.of("private_key_jwt"));
		oidcProperties.setIntrospectionEnabled(true);
		oidcProperties.setIntrospectionEndpointAuthMethods(List.of("private_key_jwt"));
		oidcProperties.setRevocationEnabled(true);
		oidcProperties.setRevocationEndpointAuthMethods(List.of("private_key_jwt"));
		oidcProperties.setSubjectTypes(List.of("public"));
		oidcProperties.setCodeChallengeMethods(List.of("S256"));
		oidcProperties.setIdTokenSigningAlgorithms(List.of("RS256"));
		oidcProperties.setDPoPSigningAlgValuesSupported(List.of("ES256"));
		oidcProperties.setIdTokenEncryptionAlgorithms(List.of("RSA-OAEP-256"));
		oidcProperties.setIdTokenEncryptionMethods(List.of("A256GCM"));
		oidcProperties.setUserInfoEnabled(true);
		oidcProperties.setUserInfoEncryptionAlgorithms(List.of("RSA-OAEP-256"));
		oidcProperties.setUserInfoEncryptionMethods(List.of("A256GCM"));

		var consumer = serverConfiguration(oidcProperties).customizeProviderConfigurationEndpoint();
		var providerConfiguration = applyCustomizer(consumer, baseProviderClaims());

		assertTrue(providerConfiguration.hasClaim(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT));
		assertThat(providerConfiguration.getClaims().get(CHECK_SESSION_IFRAME), is("https://issuer.example/session/iframe"));
		assertThat(providerConfiguration.getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED),
				is(List.of("authorization_code")));
		assertThat(providerConfiguration.getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED),
				is(List.of("ES256")));
		assertThat(providerConfiguration.getClaims().get(ID_TOKEN_ENCRYPTION_ALG), is(List.of("RSA-OAEP-256")));
		assertThat(providerConfiguration.getClaims().get(USERINFO_ENCRYPTION_METHOD), is(List.of("A256GCM")));
	}

	@Test
	void customizeProviderConfigurationEndpointRemovesDisabledAndSkipsOptionalClaims() {
		var oidcProperties = baseOidcProperties();
		oidcProperties.setLogoutEnabled(false);
		oidcProperties.setSessionIFrameEndpoint(null);
		oidcProperties.setIntrospectionEnabled(false);
		oidcProperties.setRevocationEnabled(false);
		oidcProperties.setUserInfoEnabled(false);
		oidcProperties.setDeviceAuthorizationEnabled(false);
		oidcProperties.setPushedAuthorizationRequestsEndpointEnabled(false);
		oidcProperties.setDPoPSigningAlgValuesSupported(List.of());
		oidcProperties.setGrantTypes(List.of());
		oidcProperties.setResponseTypes(null);
		oidcProperties.setTokenEndpointAuthMethods(null);
		oidcProperties.setIdTokenEncryptionAlgorithms(null);
		oidcProperties.setIdTokenEncryptionMethods(List.of());

		var consumer = serverConfiguration(oidcProperties).customizeProviderConfigurationEndpoint();
		var providerConfiguration = applyCustomizer(consumer, baseProviderClaims());

		assertFalse(providerConfiguration.hasClaim(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED));
		assertFalse(providerConfiguration.hasClaim(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT));
		assertFalse(providerConfiguration.hasClaim(CHECK_SESSION_IFRAME));
		assertFalse(providerConfiguration.hasClaim(ID_TOKEN_ENCRYPTION_ALG));
		assertFalse(providerConfiguration.hasClaim(ID_TOKEN_ENCRYPTION_METHOD));
		assertFalse(providerConfiguration.hasClaim(USERINFO_ENCRYPTION_ALG));
		assertFalse(providerConfiguration.hasClaim(USERINFO_ENCRYPTION_METHOD));
	}

	@Test
	void customizeProviderConfigurationEndpointClearsMetadataWhenOidcDisabled() {
		var oidcProperties = baseOidcProperties();
		oidcProperties.setEnabled(false);

		// If any mandatory attribute is missing Spring throws an IllegalArgumentException when building the provider configuration, so we expect that here.
		var consumer = serverConfiguration(oidcProperties).customizeProviderConfigurationEndpoint();
		var claims = baseProviderClaims();
		assertThrows(IllegalArgumentException.class, () -> applyCustomizer(consumer, claims));
	}

	private static OidcServerConfiguration serverConfiguration(OidcProperties oidcProperties) {
		return new OidcServerConfiguration(
				oidcProperties,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null
		);
	}

	private static OidcProperties baseOidcProperties() {
		var properties = new OidcProperties();
		properties.setEnabled(true);
		properties.setIssuer("https://issuer.example");
		properties.setIntrospectionEnabled(true);
		properties.setRevocationEnabled(true);
		properties.setUserInfoEnabled(true);
		properties.setDeviceAuthorizationEnabled(true);
		properties.setPushedAuthorizationRequestsEndpointEnabled(true);
		properties.setTlsClientCertificateBoundAccessTokens(true);
		return properties;
	}

	private static OidcProviderConfiguration applyCustomizer(
			java.util.function.Consumer<OidcProviderConfiguration.Builder> consumer,
			Map<String, Object> claims) {
		var providerConfigurationBuilder = OidcProviderConfiguration.withClaims(claims);
		consumer.accept(providerConfigurationBuilder);
		return providerConfigurationBuilder.build();
	}

	private static Map<String, Object> baseProviderClaims() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "https://issuer.example");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, "https://issuer.example/oauth2/authorize");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "https://issuer.example/oauth2/token");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "https://issuer.example/oauth2/jwks");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT, "https://issuer.example/oauth2/introspect");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, "https://issuer.example/oauth2/revoke");
		claims.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, "https://issuer.example/userinfo");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT,
				"https://issuer.example/oauth2/device_authorization");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
				"https://issuer.example/oauth2/par");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED, List.of("ES256"));
		claims.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, List.of("public"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, List.of("code"));
		return claims;
	}

}

