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
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.OidcMockTestData;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

@SpringBootTest(classes = OidcUserinfoService.class)
class OidcUserinfoServiceTest {

	@MockitoBean
	private HttpClient httpClient;

	@MockitoBean
	private HttpResponse httpResponseUserinfo;

	@MockitoBean
	private OidcHttpClientProvider httpClientProvider;

	@Autowired
	private OidcUserinfoService oidcUserinfoService;

	@ParameterizedTest
	@MethodSource
	void fetchUserInfo(String responseString, String contentType, int expectedAttributes) throws Exception {
		var client = OidcMockTestData.givenClient();
		var certificates = Certificates.builder().build();
		var configuration = OidcMockTestData.givenConfiguration();
		mockUserinfoResponse(client, certificates, configuration, responseString, contentType);

		var result = oidcUserinfoService
				.fetchUserInfo(client, certificates, configuration, OidcMockTestData.ACCESS_TOKEN,
						OidcMockTestData::givenJwk);

		assertThat(result.toJSONObject().size(), is(expectedAttributes));
		assertThat(result.getSubject(), is(OidcMockTestData.SUBJECT));
	}

	static Object[][] fetchUserInfo() {
		return new Object[][] {
				{ OidcMockTestData.USERINFO_RESPONSE, MediaType.APPLICATION_JSON_VALUE, OidcMockTestData.USERINFO_ATTRIBUTES },
				{ OidcMockTestData.ID_TOKEN, OidcUtil.CONTENT_TYPE_JWT, OidcMockTestData.TOKEN_ATTRIBUTES },
				{ OidcMockTestData.USERINFO_RESPONSE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8",
						OidcMockTestData.USERINFO_ATTRIBUTES },
				{ OidcMockTestData.USERINFO_RESPONSE, MediaType.APPLICATION_JSON_VALUE + "; charset=UTF-8",
						OidcMockTestData.USERINFO_ATTRIBUTES }
		};
	}

	private void mockUserinfoResponse(OidcClient oidcClient, Certificates certificates,
			OpenIdProviderConfiguration configuration, String responseString, String contentType)
			throws Exception {
		doReturn(httpClient).when(httpClientProvider)
							.createHttpClient(oidcClient, certificates, configuration.getUserinfoEndpoint());
		// mock metadata
		doReturn(httpResponseUserinfo).when(httpClient).send(argThat(
				request -> request != null && request.uri().equals(configuration.getUserinfoEndpoint())
				&& request.headers().firstValue(org.springframework.http.HttpHeaders.AUTHORIZATION).isPresent()
		), any());
		doReturn(HttpStatus.OK.value()).when(httpResponseUserinfo).statusCode();
		doReturn(HttpHeaders.of(
				Map.of(org.springframework.http.HttpHeaders.CONTENT_TYPE,
				List.of(contentType)),
				(key, value) -> true))
				.when(httpResponseUserinfo).headers();
		doReturn(responseString).when(httpResponseUserinfo).body();
	}
}
