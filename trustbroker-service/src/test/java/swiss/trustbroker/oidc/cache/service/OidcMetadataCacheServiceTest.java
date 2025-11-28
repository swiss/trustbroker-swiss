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

package swiss.trustbroker.oidc.cache.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSource;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSources;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.OidcMockTestData;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

@SpringBootTest(classes = { OidcMetadataCacheService.class })
class OidcMetadataCacheServiceTest {

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private GlobalExceptionHandler globalExceptionHandler;

	@MockitoBean
	private OidcHttpClientProvider httpClientProvider;

	@MockitoBean
	private OidcClientSecretResolver clientSecretProvider;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private HttpClient httpClient;

	@MockitoBean
	private HttpResponse httpResponseMetadata;

	@MockitoBean
	private HttpResponse httpResponseJwk;

	@MockitoBean
	private ExecutorService executor;

	@Autowired
	private OidcMetadataCacheService service;

	@BeforeEach
	void setUp() {
		service.flushCache();
	}

	@ParameterizedTest
	@MethodSource
	void refreshConfigurations(String metadataJson, boolean success) throws Exception {
		var oidcClient = OidcMockTestData.givenClient();
		var cp = OidcMockTestData.givenCpWithOidcClient(oidcClient);
		mockMetadata(cp, oidcClient, metadataJson);
		var cps = givenClaimsParties(cp);
		doReturn(cps).when(relyingPartyDefinitions).getClaimsProviderSetup();
		doReturn(new OidcProperties()).when(trustBrokerProperties).getOidc();

		var rps = givenRelyingParties();
		doReturn(rps).when(relyingPartyDefinitions).getRelyingPartySetup();

		service.refreshConfigurations();

		if (success) {
			verifyNoInteractions(globalExceptionHandler);
			assertFalse(cp.initializedValidationStatus().hasErrors());
			verify(httpClient, times(2)).send(any(), any());
			// verify access is done from cache
			var metadata = service.getOidcConfiguration(cp);
			assertThat(metadata.getClientSecret(), is(OidcMockTestData.CLIENT_SECRET));
			verify(httpClient, times(2)).send(any(), any());
		}
		else {
			verify(globalExceptionHandler).logException(any(TechnicalException.class));
			assertTrue(cp.initializedValidationStatus().hasErrors());
			verify(httpClient).send(any(), any());
		}
	}

	static Object[][] refreshConfigurations() {
		return new Object[][] {
				{ OidcMockTestData.METADATA_JSON, true },
				{ "{}", false }
		};
	}

	@Test
	void getOidcConfiguration() throws Exception {
		var oidcClient = OidcMockTestData.givenClient();
		var cp = OidcMockTestData.givenCpWithOidcClient(oidcClient);
		mockMetadata(cp, oidcClient, OidcMockTestData.METADATA_JSON);

		var metadata = service.getOidcConfiguration(cp);

		validateStaticMetadata(metadata);
		assertThat(metadata.getJwkSet().getKeyByKeyId(OidcMockTestData.KEY_ID), is(not(nullValue())));
		assertThat(metadata.getClientSecret(), is(OidcMockTestData.CLIENT_SECRET));
		verify(httpClient, times(2)).send(any(), any());
	}

	@Test
	void getKey() throws Exception {
		var oidcClient = OidcMockTestData.givenClient();
		var cp = OidcMockTestData.givenCpWithOidcClient(oidcClient);
		mockMetadata(cp, oidcClient, OidcMockTestData.METADATA_JSON);
		var oidcProperties = new OidcProperties();
		doReturn(oidcProperties).when(trustBrokerProperties).getOidc();

		var jwk = service.getKey(cp, OidcMockTestData.KEY_ID);

		assertTrue(jwk.isPresent());
		assertThat(jwk.get().getKeyID(), is(OidcMockTestData.KEY_ID));
		verify(httpClient, times(2)).send(any(), any());

		// verify access is done from cache - refresh not
		jwk = service.getKey(cp, "unknown");
		assertTrue(jwk.isEmpty());
		verify(httpClient, times(2)).send(any(), any());

		// simulate re-fetch after refresh period
		oidcProperties.setMinimumMetadataCacheTimeSecs(0);
		jwk = service.getKey(cp, "unknown");
		assertTrue(jwk.isEmpty());
		verify(httpClient, times(4)).send(any(), any());
	}

	@ParameterizedTest
	@MethodSource
	void validateInvalidMetadata(String clientIssuerId, List<OidcClaimsSource> claimsSources,
			OpenIdProviderConfiguration metadata, boolean exceptionExpected) {
		var client = OidcMockTestData.givenClient();
		client.setIssuerId(clientIssuerId);
		client.setClaimsSources(OidcClaimsSources.builder().claimsSourceList(claimsSources).build());
		if (exceptionExpected) {
			assertThrows(TechnicalException.class, () -> service.validateMetadata(client, metadata));
		}
		else {
			assertDoesNotThrow(() -> service.validateMetadata(client, metadata));
		}
	}

	static Object[][] validateInvalidMetadata() {
		var metadata = OidcMockTestData.givenConfiguration();
		return new Object[][] {
				{ null, List.of(OidcClaimsSource.USERINFO),
						metadata.toBuilder().issuerId(null).build(), true },
				{ OidcMockTestData.CP_ISSUER_ID, List.of(OidcClaimsSource.USERINFO),
						metadata.toBuilder().issuerId(null).build(), false },
				{ null, List.of(OidcClaimsSource.USERINFO, OidcClaimsSource.ID_TOKEN),
						metadata.toBuilder().authorizationEndpoint(null).build(), true },
				{ null, List.of(OidcClaimsSource.ID_TOKEN, OidcClaimsSource.USERINFO),
						metadata.toBuilder().tokenEndpoint(null).build(), true },
				{ null, List.of(OidcClaimsSource.USERINFO), metadata.toBuilder().jwkEndpoint(null).build(), true },
				{ null, List.of(OidcClaimsSource.USERINFO), metadata.toBuilder().userinfoEndpoint(null).build(), true },
				{ null, List.of(OidcClaimsSource.ID_TOKEN), metadata.toBuilder().userinfoEndpoint(null).build(), false },
				{ null, List.of(OidcClaimsSource.ID_TOKEN), metadata.toBuilder().authenticationMethods(null).build(), false },
				{ null, List.of(OidcClaimsSource.ID_TOKEN),
						metadata.toBuilder().authenticationMethods(ClientAuthenticationMethods.builder().build()).build(), false },
				{ null, List.of(OidcClaimsSource.ID_TOKEN),
						metadata.toBuilder()
								.authenticationMethods(
										ClientAuthenticationMethods
												.builder()
												.methods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_JWT))
												.build()
								).build(), false },
				{ null, List.of(OidcClaimsSource.ID_TOKEN),
						metadata.toBuilder()
								.authenticationMethods(
										ClientAuthenticationMethods
												.builder()
												.methods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_POST))
												.build()
								).build(), false },
		};
	}

	private void mockMetadata(ClaimsParty cp, OidcClient oidcClient, String metadataJson) throws Exception {
		doReturn(httpClient).when(httpClientProvider)
							.createHttpClient(oidcClient, cp.getCertificates(), URI.create(OidcMockTestData.METADATA_URL));
		// mock metadata
		doReturn(httpResponseMetadata).when(httpClient).send(argThat(
				request -> request != null && request.uri().equals(URI.create(OidcMockTestData.METADATA_URL))
		), any());
		doReturn(HttpStatus.OK.value()).when(httpResponseMetadata).statusCode();
		doReturn(metadataJson).when(httpResponseMetadata).body();
		// mock jwks
		doReturn(httpResponseJwk).when(httpClient).send(argThat(
				request -> request != null && request.uri().equals(URI.create(OidcMockTestData.JWKS_ENDPOINT))
		), any());
		doReturn(HttpStatus.OK.value()).when(httpResponseJwk).statusCode();
		// re-create stream for each invocation
		doAnswer(invocation -> new ByteArrayInputStream(OidcMockTestData.JWKS_JSON.getBytes(StandardCharsets.UTF_8))).when(httpResponseJwk).body();
		// mock client secret
		doReturn(OidcMockTestData.CLIENT_SECRET).when(clientSecretProvider).resolveClientSecret(oidcClient);
	}

	private static void validateStaticMetadata(OpenIdProviderConfiguration metadata) {
		assertThat(metadata.getAuthorizationEndpoint(), is(URI.create(OidcMockTestData.AUTHORIZE_ENDPOINT)));
		assertThat(metadata.getJwkEndpoint(), is(URI.create(OidcMockTestData.JWKS_ENDPOINT)));
		assertThat(metadata.getTokenEndpoint(), is(URI.create(OidcMockTestData.TOKEN_ENDPOINT)));
		assertThat(metadata.getAuthenticationMethods(), is(not(nullValue())));
		assertThat(metadata.getAuthenticationMethods().getMethods(), containsInAnyOrder(
				OidcMockTestData.CLIENT_AUTHENTICATION_METHODS));
	}

	private ClaimsProviderSetup givenClaimsParties(ClaimsParty oidcCp) {
		var cps = List.of(
				ClaimsParty.builder().id("ignored").build(),
				oidcCp
		);
		return ClaimsProviderSetup.builder().claimsParties(cps).build();
	}

	private RelyingPartySetup givenRelyingParties() {
		List<RelyingParty> rps = List.of(RelyingParty.builder().id("ignored").build());
		return RelyingPartySetup.builder().relyingParties(rps).build();
	}
}
