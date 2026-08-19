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

package swiss.trustbroker.waf;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.util.ApiSupport;

class AccessFilterTest {

	private static final String PERIMETER_URL = "https://localhost/custom/perimeter";

	private static final String OIDC_PERIMETER_URL = "https://localhost/custom/oidc";

	private TrustBrokerProperties trustBrokerProperties;

	private Filter accessFilter;

	@BeforeEach
	void setUp() {
		trustBrokerProperties = new TrustBrokerProperties();
		trustBrokerProperties.setNetwork(new NetworkConfig());
		trustBrokerProperties.setOidc(new OidcProperties());
		// see WebSupport.getOwnPerimeterUris for what can be customized:
		trustBrokerProperties.getOidc().setSessionIFrameEndpoint("https://localhost/session/i.frame");
		trustBrokerProperties.getOidc().setPerimeterUrl(OIDC_PERIMETER_URL);
		trustBrokerProperties.setSaml(new SamlProperties());
		trustBrokerProperties.getSaml().setConsumerUrl("https://localhost/custom/consumer");
		trustBrokerProperties.setPerimeterUrl(PERIMETER_URL);
		trustBrokerProperties.setBlockedHeaderNames(List.of("X-Injected-Script", "X-Custom-Exploit"));
		accessFilter = new AccessFilter(trustBrokerProperties);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// SPA
			"/app,200",
			"/app/failure,200",
			// API cleaned up so old app resources now gone
			"/failure,404",
			"/sso,404",
			"/sso/groupid,404",
			"/home/issuer/id,404",
			"/device/issuer/id,404",
			"/profile/id,404",
			// APIs (/adfs/ls included below)
			"/api/v1/hrd/translations/de,404", // internal API
			"/adfs/ls,200",
			"/adfs/services/trust,200",
			"/api/v1/metadata,200",
			"/api/v1/saml/metadata,200",
			"/api/v1/saml/metadata/idp,200",
			"/api/v1/saml/metadata/sp,200",
			"/federationmetadata/2007-06/federationmetadata.xml,200", // XTB /case-sensitive) and ADFS (case-insensitive)
			"/FederationMetadata/2007-06/FederationMetadata.xml,200", // ADFS docs
			"/Federationmetadata/2007-06/FederationMetadata.xml,404", // blocked case
			"/HRD/,404", // blocked since v1.10
			// Search engines
			"/robots.txt,200",
			// Spring actuators
			"/actuator/health,404",
			"/actuator/info,404",
			"/api/v1/config,404",
			// assets referenced by UI
			"/assets/images/logo.svg,200",
			"/assets/images/favicon.ico,200",
			"/index.html,200",
			"/other.html,404",
			"/favicon.ico,200",
			"/runtime.a26ed6ea895c0fcf5af2.js,200",
			"/styles.58751f05ac77ca4b10bf.css,200",
			"/Regular.793e11078fdc9cd76c85.woff2,200",
			"/fa-solid-900.eeccf4f66002c6f2ba24.woff,200",
			"/fa-solid-900.be9ee23c0c6390141475.ttf,200",
			"/fa-regular-400.4689f52cc96215721344.svg,200",
			"/fa-brands-400.23f19bb08961f37aaf69.eot,200",
			// OIDC (needs to be consistent with /.well-known/openid-configuration)
			"/.well-known/openid-configuration,200",
			"/api/v1/openid-configuration,200",
			"/login,200",
			"/login/,200",
			"/login-,404",
			"/userinfo,200",
			"/logout,200",
			"/logout/,200",
			"/logout-,404",
			"/oauth2,404",
			"/oauth2/authorize,200",
			"/oauth2/token,200",
			"/oauth2/jwks,200",
			"/oauth2/revoke,200",
			"/oauth2/introspect,200",
			// custom config endpoints:
			"/custom/oidc,200",
			"/session/i.frame,200",
			"/session/i_frame,404", // . escaped
			"/custom/consumer,200",
			"/custom/perimeter,200",
			// Inaccessible URLs
			"/api/v2/incubating,404",
			"/hidden/secret,404",
			"/php.ini,404",
			"/../../../../../windows/win.ini,404"
	})
	void testAccess(String path, int expectedStatus) throws Exception {
		var request = new MockHttpServletRequest();
		request.setRequestURI(path);
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();
		accessFilter.doFilter(request, response, chain);
		assertThat("Access on path " +path, response.getStatus(), is(expectedStatus));
		validateChainCall(path, expectedStatus, chain, request);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// test all cases with one URL
			ApiSupport.CONFIG_STATUS_API + ",INTERNET,true,404",
			ApiSupport.CONFIG_STATUS_API + ",null,true,404",
			ApiSupport.CONFIG_STATUS_API + ",INTRANET,true,200",
			ApiSupport.CONFIG_STATUS_API + ",INTRANET,false,404",
			ApiSupport.CONFIG_STATUS_API + ",INTERNET,false,404",
			// test just enabled network config for others
			ApiSupport.CONFIG_SCHEMAS_API + "/RelyingParty.xsd,INTERNET,true,404",
			ApiSupport.CONFIG_SCHEMAS_API + "/RelyingParty.xsd,null,true,404",
			ApiSupport.CONFIG_SCHEMAS_API + "/RelyingParty.xsd,INTRANET,true,200",
			ApiSupport.RECONFIG_URL + ",INTERNET,true,404",
			ApiSupport.RECONFIG_URL + ",null,true,404",
			ApiSupport.RECONFIG_URL + ",INTRANET,true,200",
			// spring actuators
			"/actuator/health,INTERNET,true,404",
			"/actuator/health/readiness,INTERNET,true,404",
			"/actuator/health/liveness,null,true,404",
			"/actuator/health,INTRANET,true,200",
			"/actuator/info,INTRANET,true,200",
			// security corner cases
			"/api/v1/config/%73tatus" + ",INTERNET,true,404" // prevent bypassing isIntranet decision via URL encoding
	}, nullValues = "null")
	void testInternalAccess(String path, String headerValue, boolean networkConfig, int expectedStatus) throws Exception {
		var headerName = "X-Network";
		if (networkConfig) {
			trustBrokerProperties.getNetwork().setNetworkHeader(headerName);
			trustBrokerProperties.getNetwork().setInternetNetworkName("INTERNET");
			trustBrokerProperties.getNetwork().setIntranetNetworkName("INTRANET");
		}
		var request = new MockHttpServletRequest();
		request.setRequestURI(path);
		if (headerValue != null) {
			request.addHeader(headerName, headerValue);
		}
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();
		accessFilter.doFilter(request, response, chain);
		assertThat("Access on path " +path, response.getStatus(), is(expectedStatus));
		validateChainCall(path, expectedStatus, chain, request);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// internal APIs blocked
			ApiSupport.CONFIG_FRONTEND_API + ",null,404",
			ApiSupport.SSO_PARTICIPANTS_URL + ",https://other.localdomain,404",
			ApiSupport.ACCESS_REQUEST_INITIATE_URL + ",http://localhost,404",
			ApiSupport.ANNOUNCEMENTS_URL + "/rp1,http://localhost,404",
			ApiSupport.ASSETS_URL + "/image.jpg,https://localhost:8443,404",
			// internal APIs allowed
			ApiSupport.CONFIG_FRONTEND_API + "," + PERIMETER_URL + ",200",
			ApiSupport.TRANSLATIONS_URL + "/de," + OIDC_PERIMETER_URL + ",200",
			ApiSupport.ANNOUNCEMENTS_URL + "/rp1," + OIDC_PERIMETER_URL + ",200",
			ApiSupport.SSO_PARTICIPANTS_URL + "," + PERIMETER_URL + ",200",
			ApiSupport.HRD_URL + "/profiles," + PERIMETER_URL + ",200",
			ApiSupport.ACCESS_REQUEST_INITIATE_URL + "," + PERIMETER_URL + ",200",
			ApiSupport.ACCESS_REQUEST_TRIGGER_URL + "," + PERIMETER_URL + ",200",
			// external APIs allowed
			ApiSupport.ACCESS_REQUEST_TRIGGER_URL + "," + PERIMETER_URL + ",200",
			ApiSupport.ACCESS_REQUEST_TRIGGER_URL + ",null,200",
			ApiSupport.ACCESS_REQUEST_TRIGGER_URL + ",https://other.localdomain,200",
			ApiSupport.ACCESS_REQUEST_COMPLETE_URL + "/session1," + PERIMETER_URL + ",200",
			ApiSupport.ACCESS_REQUEST_COMPLETE_URL + "/session1,null,200",
			ApiSupport.ACCESS_REQUEST_COMPLETE_URL + "/session1,http://localhost,200",
	}, nullValues = "null")
	void testApiAccess(String path, String referer, int expectedStatus) throws Exception {
		var request = new MockHttpServletRequest();
		request.setRequestURI(path);
		if (referer != null) {
			request.addHeader(HttpHeaders.REFERER, referer);
		}
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();
		accessFilter.doFilter(request, response, chain);
		assertThat("Access on path " +path, response.getStatus(), is(expectedStatus));
		validateChainCall(path, expectedStatus, chain, request);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// no parameter present -> allowed (empty paramName is sentinel: skip addParameter)
			"'','',200",
			// unrelated parameter present -> allowed
			"SAMLRequest,payload,200",
			// default blocked parameter @class with a value -> blocked
			"@class,java.lang.String,404",
			// @class present even with empty value -> blocked (non-null getParameter result)
			"@class,'',404"
	})
	void testBlockedRequestParameter(String paramName, String paramValue, int expectedStatus) throws Exception {
		var request = new MockHttpServletRequest();
		request.setRequestURI("/app");
		if (!paramName.isEmpty()) {
			request.addParameter(paramName, paramValue);
		}
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();
		accessFilter.doFilter(request, response, chain);
		assertThat("Request parameter check for paramName='" + paramName + "'",
				response.getStatus(), is(expectedStatus));
		validateChainCall("/app", expectedStatus, chain, request);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// no header present -> allowed (empty headerName is sentinel: skip addHeader)
			"'','',200",
			// unrelated header present -> allowed
			"Accept,application/json,200",
			// first blocked header with a value -> blocked
			"X-Injected-Script,malicious.js,404",
			// second blocked header with a value -> blocked
			"X-Custom-Exploit,payload,404",
			// first blocked header even with empty value -> blocked (non-null getHeader result)
			"X-Injected-Script,'',404"
	})
	void testBlockedRequestHeader(String headerName, String headerValue, int expectedStatus) throws Exception {
		var request = new MockHttpServletRequest();
		request.setRequestURI("/app");
		if (!headerName.isEmpty()) {
			request.addHeader(headerName, headerValue);
		}
		var response = new MockHttpServletResponse();
		var chain = new MockFilterChain();
		accessFilter.doFilter(request, response, chain);
		assertThat("Request header check for headerName='" + headerName + "'",
				response.getStatus(), is(expectedStatus));
		validateChainCall("/app", expectedStatus, chain, request);
	}

	private static void validateChainCall(String path, int status, MockFilterChain chain, MockHttpServletRequest request) {
		if (status == HttpServletResponse.SC_OK) {
			assertThat("Access on path " + path, chain.getRequest(), is(request));
		}
		else {
			assertThat("Access on path " + path, chain.getRequest(), is(nullValue()));
		}
	}
}
