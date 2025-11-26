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

package swiss.trustbroker.oidc.client.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.OidcMockTestData;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

@SpringBootTest(classes = { OidcTokenService.class })
class OidcTokenServiceTest {

	@MockitoBean
	private OidcHttpClientProvider httpClientProvider;

	@MockitoBean
	private HttpClient httpClient;

	@MockitoBean
	private HttpResponse httpResponseToken;

	@Autowired
	private OidcTokenService oidcTokenService;

	@Test
	void fetchTokens() throws Exception {
		var client = OidcMockTestData.givenClient();
		var certificates = Certificates.builder().build();
		var configuration = OidcMockTestData.givenConfiguration();
		mockTokenResponse(client, certificates, configuration);

		var result = oidcTokenService
				.fetchTokens(client, certificates, configuration, OidcMockTestData.REDIRECT_URI, OidcMockTestData.CODE);

		assertThat(result.size(), is(6));
		assertThat(result.get(OidcUtil.TOKEN_RESPONSE_TOKEN_TYPE), is(OidcUtil.OIDC_BEARER));
	}

	private void mockTokenResponse(OidcClient oidcClient, Certificates certificates, OpenIdProviderConfiguration configuration)
			throws Exception {
		doReturn(httpClient).when(httpClientProvider)
							.createHttpClient(oidcClient, certificates, configuration.getTokenEndpoint());
		// mock metadata
		doReturn(httpResponseToken).when(httpClient).send(argThat(
				request -> request != null && request.uri().equals(configuration.getTokenEndpoint())
						&& request.headers().firstValue(org.springframework.http.HttpHeaders.AUTHORIZATION).isPresent()
		), any());
		doReturn(HttpStatus.OK.value()).when(httpResponseToken).statusCode();
		doReturn(OidcMockTestData.TOKEN_RESPONSE).when(httpResponseToken).body();
	}

}
