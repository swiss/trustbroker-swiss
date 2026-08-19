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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.AllowPrivateNetworkAccess;
import swiss.trustbroker.config.dto.ContentSecurityPolicies;
import swiss.trustbroker.config.dto.FrameOptionsPolicies;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HeaderBuilder;

class OidcTxFilterTest {

	private static final String XTB_ORIGIN = "https://trustbroker.swiss";

	private static final String XTB_REFERER = XTB_ORIGIN + "/";

	private static final String APP_ORIGIN = "https://localhost:8080";

	private static final String APP_REFERER = APP_ORIGIN + "/";

	private static final String XTB_CSP = "frame-ancestors 'self' " + XTB_ORIGIN;

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private OidcFrameAncestorHandler oidcFrameAncestorHandler;

	@Mock
	private ApiSupport apiSupport;

	@Mock
	private ScriptService scriptService;

	@Mock
	private SessionTxWrapper sessionTxWrapper;

	private TrustBrokerProperties properties;

	private OidcTxFilter filter;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		properties = new TrustBrokerProperties();
		properties.setOidc(new OidcProperties());
		filter = new OidcTxFilter(relyingPartyDefinitions, properties, new ApiSupport(properties),
				scriptService, sessionTxWrapper);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
	}

	@ParameterizedTest
	@MethodSource
	void validateAndSetSecurityHeaders(String path, String origin, String referer, String frameOptions, String csp,
			String acOrigin) {
		var request = new MockHttpServletRequest();
		request.setRequestURI(path);
		request.addHeader(HttpHeaders.ORIGIN, origin);
		request.addHeader(HttpHeaders.REFERER, referer);
		List<OidcClient> oidcClients =
				origin.equals(APP_ORIGIN) ? List.of(OidcClient.builder().realm("app1").build()) : Collections.emptyList();
		when(relyingPartyDefinitions.getOidcClientsByPredicate(any())).thenReturn(oidcClients);
		var response = new MockHttpServletResponse();
		properties.setPerimeterUrl(XTB_ORIGIN + "/saml");
		properties.getOidc().setPerimeterUrl(XTB_ORIGIN + "/oidc");

		filter.validateAndSetSecurityHeaders(
				request,
				new OidcTxResponseWrapper(request, response, relyingPartyDefinitions, properties, apiSupport, oidcFrameAncestorHandler),
				path);

		assertThat(response.getHeader(HeaderBuilder.STRICT_TRANSPORT_SECURITY), is(not(nullValue())));
		assertThat(response.getHeader(HeaderBuilder.CONTENT_TYPE_OPTIONS), is(not(nullValue())));
		assertThat(response.getHeader(HeaderBuilder.REFERRER_POLICY), is(not(nullValue())));
		assertThat(response.getHeader(HeaderBuilder.ROBOTS_TAG), is(not(nullValue())));
		assertThat(response.getHeader(HeaderBuilder.FRAME_OPTIONS), is(frameOptions));
		assertThat(response.getHeader(HeaderBuilder.CONTENT_SECURITY_POLICY), is(csp));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN), is(acOrigin));
	}

	static Object[][] validateAndSetSecurityHeaders() {
		var frameOptions = new FrameOptionsPolicies();
		var csp = new ContentSecurityPolicies();
		return new Object[][] {
				{ ApiSupport.OIDC_USERINFO, APP_ORIGIN, APP_REFERER, frameOptions.getOidc(), csp.getOidc(), APP_ORIGIN },
				{ ApiSupport.OIDC_USERINFO, XTB_ORIGIN, XTB_REFERER, null, XTB_CSP, null },
				{ ApiSupport.PUBLIC_OIDC_CONFIG_PATH, APP_ORIGIN, APP_REFERER, frameOptions.getOidc(), csp.getOidc(), APP_ORIGIN },
				{ ApiSupport.PUBLIC_OIDC_CONFIG_PATH, XTB_ORIGIN, XTB_REFERER, null, XTB_CSP, XTB_ORIGIN },
				{ ApiSupport.PUBLIC_OIDC_CONFIG_PATH, "https://localhost:4200", "https://localhost:4200/",
						frameOptions.getOidc(), csp.getOidc(), null },
				{ ApiSupport.KEYCLOAK_REALMS + "/app1" + ApiSupport.PUBLIC_OIDC_CONFIG_PATH,
						APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getSaml(), APP_ORIGIN },
				{ ApiSupport.FRONTEND_CONTEXT + "/any", APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getFrontend(), null },
				{ ApiSupport.ADFS_PATH + "/ls", APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getSaml(), null },
				{ ApiSupport.HRD_CP_URL, APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getSaml(), null },
				{ ApiSupport.WEB_RESOURCE_PATH, APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getFallback(), null },
				{ "index.html", APP_ORIGIN, APP_REFERER, frameOptions.getFallback(), csp.getFallback(), null }
		};
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false,true,true,ALWAYS,null", // no preflight
			"true,false,true,ALWAYS,null", // not requested
			"true,true,false,ALWAYS,true", // network does not matter
			"true,true,true,NEVER,null", // network does not matter
			"true,true,false,INTRANET,null", // not on Intranet
			"true,true,true,INTRANET,true", // not on Intranet
	}, nullValues = "null")
	void validateAndSetSecurityHeadersPrivateNetwork(boolean preflight, boolean requestPrivateNetwork, boolean clientOnIntranet,
			AllowPrivateNetworkAccess allowPrivateNetworkAccess, String expectedAllowPrivateNetwork) {
		properties.setNetwork(givenNetworkConfig());
		properties.getCors().setAllowPrivateNetworkAccess(allowPrivateNetworkAccess);
		var request = new MockHttpServletRequest();
		if (preflight) {
			request.setMethod(HttpMethod.OPTIONS.name());
			request.addHeader(HttpHeaders.ORIGIN, "https://localhost:4200");
			request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.GET.name());
		}
		if (requestPrivateNetwork) {
			request.addHeader(HeaderBuilder.ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK, HeaderBuilder.ACCESS_CONTROL_PRIVATE_NETWORK);
		}
		if (clientOnIntranet) {
			request.addHeader(properties.getNetwork().getNetworkHeader(), properties.getNetwork().getIntranetNetworkName());
		}
		else {
			request.addHeader(properties.getNetwork().getNetworkHeader(), properties.getNetwork().getInternetNetworkName());
		}
		var response = new MockHttpServletResponse();

		filter.validateAndSetSecurityHeaders(
				request,
				new OidcTxResponseWrapper(request, response, relyingPartyDefinitions, properties, apiSupport, oidcFrameAncestorHandler),
				"/");
		assertThat(response.getHeader(HeaderBuilder.ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK), is(expectedAllowPrivateNetwork));
	}

	private static NetworkConfig givenNetworkConfig() {
		return NetworkConfig.builder()
		                    .intranetNetworkName("INTRANET")
		                    .internetNetworkName("INTERNET")
		                    .build();
	}
}
