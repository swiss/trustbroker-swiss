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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.HomeName;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSource;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSources;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;
import swiss.trustbroker.sessioncache.dto.StateData;

public class OidcMockTestData {

	public static final String CLIENT_ID = "client1";

	public static final String CLIENT_SECRET = "secret1";

	public static final String CP_ISSUER_ID = "http://localhost:5050";

	public static final String CP_HOME_NAME = "cpHome1";

	public static final String REALM = "realm1";

	public static final String CODE = "code123";

	public static final String REDIRECT_URI = "http://localhost:8080/response";

	public static final String REDIRECT_URI_ENCODED = "http%3A%2F%2Flocalhost%3A8080%2Fresponse";

	public static final String CUSTOM_PARAM_ENCODED = "%7B%22id_token%22%3A%7B%22acr%22%3A+%7B%22essential%22%3A+true%2C%22values%22%3A+%5B%22acrvalue%22%5D%7D%7D%7D";

	public static final String CLAIM_EMAIL = "email";

	public static final String EMAIL = "User1@trustbroker.swiss";

	public static final String CLAIM_GIVEN_NAME = "given_name";

	public static final String GIVEN_NAME = "User1GivenName";

	public static final String CLAIM_FAMILY_NAME = "family_name";

	public static final String FAMILY_NAME = "User1FamilyName";

	public static final String CLIENT_SECRET_PLAIN = "{noop}";

	public static final int USERINFO_ATTRIBUTES = 4;

	public static final int BUSINESS_ATTRIBUTES = 3;

	public static final int TECHNICAL_ATTRIBUTES = 10;

	public static final int TOKEN_ATTRIBUTES = BUSINESS_ATTRIBUTES + TECHNICAL_ATTRIBUTES;

	// trustbroker-oidcmock URL and content
	public static final String METADATA_URL = "http://localhost:5050/.well-known/openid-configuration";

	public static final String METADATA_JSON =
			"""
			{
				"issuer":"http://localhost:5050",
				"authorization_endpoint":"http://localhost:5050/oauth2/authorize",
				"device_authorization_endpoint":"http://localhost:5050/oauth2/device_authorization",
				"token_endpoint":"http://localhost:5050/oauth2/token",
				"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt",
					"private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],
				"jwks_uri":"http://localhost:5050/oauth2/jwks",
				"userinfo_endpoint":"http://localhost:5050/userinfo",
				"end_session_endpoint":"http://localhost:5050/connect/logout",
				"response_types_supported":["code"],
				"grant_types_supported":["authorization_code","client_credentials","refresh_token",
					"urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:token-exchange"],
				"revocation_endpoint":"http://localhost:5050/oauth2/revoke",
				"revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt",
					"private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],
				"introspection_endpoint":"http://localhost:5050/oauth2/introspect",
				"introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt",
					"private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],
				"code_challenge_methods_supported":["S256"],
				"tls_client_certificate_bound_access_tokens":true,
				"subject_types_supported":["public"],
				"id_token_signing_alg_values_supported":["RS256"],
				"scopes_supported":["openid"]
			}
			""";

	public static final String JWKS_ENDPOINT = "http://localhost:5050/oauth2/jwks";

	public static final String USERINFO_ENDPOINT = "http://localhost:5050/userinfo";

	public static final String AUTHORIZE_ENDPOINT = "http://localhost:5050/oauth2/authorize";

	public static final String TOKEN_ENDPOINT = "http://localhost:5050/oauth2/token";

	public static final String TOKEN_RESPONSE =
			"""
			{
			  "access_token" : "access12345",
			  "refresh_token" : "refresh12345",
			  "scope" : "openid profile email",
			  "id_token" : "id12345",
			  "token_type" : "Bearer",
			  "expires_in" : 299
			}
			""";

	public static final String USERINFO_RESPONSE =
			"""
			{
				"sub": "User1",
				"given_name": "User1GivenName",
				"family_name": "User1FamilyName",
				"email": "User1@trustbroker.swiss"
			}
			""";

	public static final String ID_TOKEN = "eyJraWQiOiIwYWZjY2U4ZC1mMGFlLTRlZjgtYmNiNS1mN2E3NDQ2OGYxMWYiLCJhbGciOiJSUzI1NiJ9"
			+ ".eyJzdWIiOiJVc2VyMSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTA1MCIsImdpdmVuX25hbWUiOiJVc2VyMUdpdmVuTmFtZSIsIm5vbmNlIjoiYTQ2MjM5YzkwYzg1NGI0MmFlODA0NjBkMWZhN2NkMTIiLCJzaWQiOiJjSFI5THpIQUE1UDdyenlBQjFzaWF2T1FfWFdfS1QtejJsMnZLQjV0Tzd3IiwiYXVkIjoiWFRCLWRldiIsImF6cCI6IlhUQi1kZXYiLCJhdXRoX3RpbWUiOjE3NDAwNDI2NTksImV4cCI6MTc0MDA0NDQ2MCwiaWF0IjoxNzQwMDQyNjYwLCJmYW1pbHlfbmFtZSI6IlVzZXIxRmFtaWx5TmFtZSIsImp0aSI6Ijc5N2ZjYTA4LTc4MTctNDc3ZS05YTk4LTU1ZjU5NWRlZjg0MyIsImVtYWlsIjoiVXNlcjFAdHJ1c3Ricm9rZXIuc3dpc3MifQ"
			+ ".gVsz1oPJsFcX_TkGKhePXHn3DjE9-OctLgrp2DvjVKv7n0iO6PvDM94aBi3oYFHsrFsHXwl9AkWZf6uRgH-acRFMZjc-gQnz-Na3YelR_pIUIP7JFztgqV9_9-U5m5KwE6IU2Yk6nLKMeJ3g_77HxsyN-HFqK2LOETtLTv332clqlOeKViEpd_V11TELX9cERFm9ansIVAWajIYK52JDT-um9qJ35BymUU3tqYv8T-5FW4g_kAneFZe-819cHgeZq4tPDSUScf1mlpZitr2QuMLAvSd0qS4Wd1OAnImeuqalL_WiGlgsSU0A6m-x4eksuygTgXwsQhrPMxNeD-PSJg";

	public static final String ACCESS_TOKEN = "eyJraWQiOiJiNjc0ZmQyNC1mYTkyLTRiOTUtYTg5Ni1kMWY4YWI1MGM3MDkiLCJhbGciOiJSUzI1NiJ9"
			+ ".eyJzdWIiOiJVc2VyMSIsImF1ZCI6IlhUQi1kZXYiLCJuYmYiOjE3NDIyODczMzgsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjUwNTAiLCJleHAiOjE3NDIyODc2MzgsImlhdCI6MTc0MjI4NzMzOCwianRpIjoiMjE1NzY5ZWYtMzM3OC00ZjA4LWE1NTItYzMzNmUwMDgyOTI2In0"
			+ ".J5b_Wgj_hO4unnMlnUc5tq7zBqRyYx29cJM_dlqYLdB31K9VAosCb2baTovFpqXPx80QYT0pBbTLXy0u4oQJ4FKXR9MeDa4ogW4zKREHOoxmDcDm_FH3p5kYGzVWymeZCC_HZ7pEHjoQc7AwrJAsIC8FprNar4_j1QxVdWYCJ1SKnO7EczZFeXr4H47eK-z-bVSsQ-mK22v5Qx2w6Yj-A-bnuJe8huRd2pXceD2UxKgIfT7uSZ8YrufvX3IoxSfnWoBp4dweeD86YWifWhcg4qOBcxj875UCQEzsCG68iUsshE7a7Lkn7iCC5R5VojV4-cdA-pgbQnzXRmeTfqK-rA";

	public static final String SUBJECT = "User1";

	public static final String JWT_ID = "797fca08-7817-477e-9a98-55f595def843";

	public static final String NONCE = "a46239c90c854b42ae80460d1fa7cd12";

	public static final String SP_SESSION_ID = "S2-575b96d5f8f646ccbc8bc8d4a0c69fb3-79a58a9fe5f94379-35e14842e4644a5c967712d8";

	public static final String SESSION_ID = "cHR9LzHAA5P7rzyAB1siavOQ_XW_KT-z2l2vKB5tO7w";

	public static final int ID_TOKEN_CLAIMS = 13;

	public static final ClientAuthenticationMethod[] CLIENT_AUTHENTICATION_METHODS = {
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST,
			ClientAuthenticationMethod.CLIENT_SECRET_JWT, ClientAuthenticationMethod.PRIVATE_KEY_JWT,
			ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
	};

	public static final String JWKS_JSON =
			"""
			{
				"keys":[
					{
						"kty":"RSA",
						"e":"AQAB",
						"kid":"0afcce8d-f0ae-4ef8-bcb5-f7a74468f11f",
						"n":"w-RIGNIEaex3NZ-usZ8q_lNQB5AfOZ3cdo-kMdkuKkdXST5XrAh45BMF9IA6nb0m4yYztTw1YP0ajh15bMfNmnpRrQ3dx1UCgrWdbdvGILW0R7m7aHxd9uTLzeLYqcMhLui2ETI_otteu7-JHEQE7b9LEeUI8WcVTzlZYwneb5S9R7DhVQ6oTaB4QdKy8NcmFKsOzRynPPZC2j9r-WwExq1MU3qe9U-SWlWy8a4TX5wVsBAXpbK-rF7eo20OEX6daeu4-nW1rAG90Cwb0HzUIYoMF2YDSexj50d_7kD45CTRiapd4Lg8U37LZw8I0xdhcEzJ4CqRw3IQme3iowls3w"
						}
					]
			}
			""";

	public static final String KEY_ID = "0afcce8d-f0ae-4ef8-bcb5-f7a74468f11f";

	public static OpenIdProviderConfiguration givenConfiguration() {
		var authenticationMethods = ClientAuthenticationMethods.builder()
															   .methods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
															   .build();
		return OpenIdProviderConfiguration.builder()
										  .issuerId(CP_ISSUER_ID)
										  .tokenEndpoint(URI.create(TOKEN_ENDPOINT))
										  .authorizationEndpoint(URI.create(AUTHORIZE_ENDPOINT))
										  .jwkEndpoint(URI.create(JWKS_ENDPOINT))
										  .userinfoEndpoint(URI.create(USERINFO_ENDPOINT))
										  .authenticationMethods(authenticationMethods)
										  .build();
	}

	public static OidcClient givenClient() {
		var protocolEndpoints = ProtocolEndpoints.builder().metadataUrl(METADATA_URL).build();
		return OidcClient.builder()
						 .id(CLIENT_ID)
						 .realm(REALM)
						 .protocolEndpoints(protocolEndpoints)
						 .clientSecret(CLIENT_SECRET_PLAIN + CLIENT_SECRET)
						 .claimsSources(OidcClaimsSources.builder()
														 .claimsSourceList(
																 List.of(OidcClaimsSource.ID_TOKEN, OidcClaimsSource.USERINFO))
														 .build())
						 .build();
	}

	public static OidcClient givenClientWithSecret(String secret) {
		return OidcClient.builder()
						 .id(CLIENT_ID)
						 .clientSecret(secret)
						 .build();
	}

	public static ClaimsParty givenCpWithOidcClient(OidcClient client) {
		var oidc = Oidc.builder().clients(List.of(client)).build();
		var email = Definition.builder()
							  .name(CLAIM_EMAIL)
							  .build();
		var givenName = Definition.builder()
							  .name(CLAIM_GIVEN_NAME)
							  .build();
		var familyName = Definition.builder()
								  .name(CLAIM_FAMILY_NAME)
								  .build();
		var attributeSelection = AttributesSelection.builder()
													.definitions(List.of(email, givenName, familyName))
													.build();
		return ClaimsParty.builder()
						  .id(CP_ISSUER_ID)
						  .oidc(oidc)
						  .homeName(HomeName.builder().value(CP_HOME_NAME).build())
						  .certificates(Certificates.builder().build())
						  .attributesSelection(attributeSelection)
						  .build();
	}

	public static StateData givenStateData() {
		var spStateData = StateData.builder()
								   .id(SP_SESSION_ID)
								   .oidcNonce(NONCE)
								   .build();
		return StateData.builder()
						.id(SESSION_ID)
						.spStateData(spStateData)
						.build();
	}

	static JWKSet givenJwkSet() {
		try {
			return JWKSet.load(new ByteArrayInputStream(JWKS_JSON.getBytes(StandardCharsets.UTF_8)));
		}
		catch (ParseException | IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	public static Optional<JWK> givenJwk(String kid) {
		var key = givenJwkSet().getKeyByKeyId(kid);
		return Optional.ofNullable(key);
	}

}
