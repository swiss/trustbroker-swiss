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

package swiss.trustbroker.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import net.shibboleth.shared.net.URLBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlProperties;

@SpringBootTest(classes = WebSupport.class)
class WebSupportTest {

	private static final String TEST_URL = "https://localhost";

	private static final String TEST_QUERY = "one=uno&two=due&three=tre&two=deux";

	private static final String TEST_URL_WITH_QUERY = TEST_URL + '?' + TEST_QUERY;

	private static final String SAML_HOST = "https://saml.localdomain";

	private static final String SAML_PATH = "/saml";

	private static final String SAML_URL = SAML_HOST + SAML_PATH;

	private static final String OIDC_HOST = "https://oidc.localdomain";

	private static final String OIDC_PATH = "/oidc";

	private static final String OIDC_URL = OIDC_HOST + OIDC_PATH;

	private static final String OIDC_LOGOUT_PATH = "/oidc/logout";

	private static final String OIDC_LOGOUT_URL = OIDC_HOST + OIDC_LOGOUT_PATH;

	private static final String OIDC_IFRAME_PATH = "/oidc/iframe";

	private static final String OIDC_IFRAME_URL = OIDC_HOST + OIDC_IFRAME_PATH;


	@Test
	void getUniqueQueryParameter() throws Exception {
		var urlBuilder = new URLBuilder(TEST_URL_WITH_QUERY);
		assertThat(WebSupport.getUniqueQueryParameter(urlBuilder, "one"), is("uno"));
		assertThrows(RequestDeniedException.class, () -> WebSupport.getUniqueQueryParameter(urlBuilder, "two"));
		assertThat(WebSupport.getUniqueQueryParameter(urlBuilder, "four"), is(nullValue()));
	}

	@ParameterizedTest
	@CsvSource(value = {
		"test," + UrlBasedViewResolver.REDIRECT_URL_PREFIX + "test",
		"null,null"
	}, nullValues = "null")
	void getViewRedirectResponse(String url, String expected) {
		var result = WebSupport.getViewRedirectResponse(url);
		assertThat(result, is(expected));
	}

	@Test
	void testGetHttpContext() {
		var request = new MockHttpServletRequest();
		var network = new NetworkConfig();

		assertEquals(0, WebSupport.getHttpContext(request, network).size());

		request.setParameter("username", "test");
		assertEquals(1, WebSupport.getHttpContext(request, network).size());

		request.addHeader(TraceSupport.XTB_CLIENTIP, "test");
		assertEquals(1, WebSupport.getHttpContext(request, network).size());

		request.addHeader(network.getNetworkHeader(), "test");
		assertEquals(2, WebSupport.getHttpContext(request, network).size());
	}

	@Test
	void testClientNetworkInjectionOnIntranet() {
		var network = new NetworkConfig();

		// no network injection
		var request = new MockHttpServletRequest();
		assertThat(WebSupport.getClientNetwork(request, network), is(nullValue()));

		// intranet access, no injection
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getIntranetNetworkName());
		assertThat(WebSupport.getClientNetwork(request, network), is(network.getIntranetNetworkName()));

		// internet access, injection ignored
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getInternetNetworkName());
		request.addHeader(network.getTestNetworkHeader(), network.getIntranetNetworkName());
		assertThat(WebSupport.getClientNetwork(request, network), is(network.getInternetNetworkName()));

		// intranet access, injection working
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getIntranetNetworkName());
		request.addHeader(network.getTestNetworkHeader(), network.getInternetNetworkName());
		assertThat(WebSupport.getClientNetwork(request, network), is(network.getInternetNetworkName()));
	}

	@Test
	void canaryModeEnabledTest() {
		var request = new MockHttpServletRequest();

		var noConfig = NetworkConfig.builder()
									.build();
		assertFalse(WebSupport.canaryModeEnabled(request, noConfig));

		var networkConfig = NetworkConfig.builder()
										 .canaryMarkerName("canary")
										 .canaryEnabledValue("always")
										 .build();
		request.addHeader(networkConfig.getCanaryMarkerName(), networkConfig.getCanaryEnabledValue());
		assertTrue(WebSupport.canaryModeEnabled(request, networkConfig));

		request.removeHeader(networkConfig.getCanaryMarkerName());
		request.setCookies(new Cookie(networkConfig.getCanaryMarkerName(), networkConfig.getCanaryEnabledValue()));
		assertTrue(WebSupport.canaryModeEnabled(request, networkConfig));
	}

	@ParameterizedTest
	@MethodSource
	void anyHeaderMatches(Map<String, String> headers, List<RegexNameValue> conditions, boolean expected) {
		var request = new MockHttpServletRequest();
		for (var header : headers.entrySet()) {
			request.addHeader(header.getKey(), header.getValue());
		}
		assertThat(WebSupport.anyHeaderMatches(request, conditions), is(expected));
	}

	static Object[][] anyHeaderMatches() {
		return new Object[][] {
				// header not set
				{ Collections.emptyMap(), null, false },
				{
						Map.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
										  .name(HttpHeaders.ACCEPT)
										  .value(MediaType.APPLICATION_JSON_VALUE)
										  .regex(".*/.*")
										  .build()),
						false
				},
				// match by value
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
										  .name(HttpHeaders.ACCEPT)
										  .value(MediaType.APPLICATION_JSON_VALUE)
										  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.APPLICATION_JSON_VALUE)
											  .regex("[*]/[*]")
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.ALL_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.ALL_VALUE)
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.APPLICATION_JSON_VALUE)
											  .build()),
						false
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.ALL_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.APPLICATION_JSON_VALUE)
											  .build()),
						false
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.ALL_VALUE,
								"sec-fetch-mode", "cors"),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.APPLICATION_JSON_VALUE)
											  .build(),
								RegexNameValue.builder()
											  .name("sec-fetch-mode")
											  .value("cors")
											  .build()),
						true
				},
				// match by regex
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .regex(MediaType.APPLICATION_JSON_VALUE)
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.IMAGE_JPEG_VALUE + ',' + MediaType.APPLICATION_JSON_VALUE + ','
								+ MediaType.TEXT_HTML_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .regex(MediaType.APPLICATION_JSON_VALUE)
											  .build()),
						true
				},

				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.APPLICATION_PDF_VALUE)
											  .regex("application/.*")
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .value(MediaType.TEXT_HTML_VALUE)
											  .regex("text/.*")
											  .build()),
						false
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.ALL_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .regex("^(application/json|[*]/[*])$")
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .regex("^(application/json|[*]/[*])$")
											  .build()),
						true
				},
				{
						Map.of(HttpHeaders.ACCEPT, MediaType.APPLICATION_PDF_VALUE + ',' + MediaType.APPLICATION_JSON_VALUE),
						List.of(RegexNameValue.builder()
											  .name(HttpHeaders.ACCEPT)
											  .regex("^(application/json|[*]/[*])$")
											  .build()),
						false
				}
		};
	}

	@Test
	void getOwnOrigins() {
		var properties = givenProperties();
		var result = WebSupport.getOwnOrigins(properties);
		assertThat(result, containsInAnyOrder(SAML_HOST, OIDC_HOST));
	}

	@Test
	void getOwnPerimeterPaths() {
		var properties = givenProperties();
		var result = WebSupport.getOwnPerimeterPaths(properties);
		assertThat(result, containsInAnyOrder(SAML_PATH, OIDC_PATH, OIDC_IFRAME_PATH));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			",false",
			OIDC_HOST + ",true",
			OIDC_HOST + "/,true",
			OIDC_URL + ",true",
			OIDC_HOST + ".attack,false",
			TEST_URL + ",false",
			TEST_URL_WITH_QUERY + ",false",
			SAML_HOST + ",false",
			SAML_URL + ",false"
	}, nullValues = "null")
	void isInternalOidcRequest(String referer, boolean expected) {
		var properties = givenProperties();
		assertThat(WebSupport.isInternalOidcRequest(properties, referer), is(expected));
	}

	private static TrustBrokerProperties givenProperties() {
		var properties = new TrustBrokerProperties();
		// ignored:OIDC_LOGOUT_PATH
		properties.setSloDefaultOidcDestinationPath(TEST_URL + "/slo/destination");
		var saml = new SamlProperties();
		saml.setConsumerUrl(SAML_URL);
		// ignored:
		saml.setArtifactResolution(ArtifactResolution.builder().serviceUrl(TEST_URL + "/arp").build());
		properties.setSaml(saml);
		var oidc = new OidcProperties();
		oidc.setPerimeterUrl(OIDC_URL);
		oidc.setEndSessionEndpoint(OIDC_LOGOUT_URL);
		oidc.setSessionIFrameEndpoint(OIDC_IFRAME_URL);
		properties.setOidc(oidc);
		return properties;
	}

}
