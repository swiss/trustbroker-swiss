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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.test.saml.util.SamlHttpTestBase;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest(classes = { SamlServiceTestConfiguration.class, SamlOutputService.class })
class SamlOutputServiceTest extends ServiceSamlTestUtil {

	private static final String RELAY_STATE = "state123";

	private static final String ISSUER_ID = "selfId";

	private static final String ENDPOINT = "https://localhost/service";

	private static final String ENDPOINT_ENCODED = "https&#x3a;&#x2f;&#x2f;localhost&#x2f;service";

	private static final DestinationType DESTINATION_ALIAS = DestinationType.RP;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private ArtifactCacheService artifactCacheService;

	@Autowired
	private VelocityEngine velocityEngine;

	@Autowired
	private SamlOutputService samlOutputService;

	@MockitoBean
	private SAMLArtifactMap artifactMap;

	@BeforeAll
	static void init() {
		SamlTestBase.setup();
	}

	@BeforeEach
	void setUp() {
		var saml = new SamlProperties();
		var ar = new ArtifactResolution();
		saml.setArtifactResolution(ar);
		doReturn(saml).when(trustBrokerProperties).getSaml();
		doReturn(ISSUER_ID).when(trustBrokerProperties).getIssuer();
	}

	@Test
	void sendPostRequest() throws Exception {
		var request = loadAuthnRequest();
		var credential = SamlTestBase.dummyCredential();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().build();

		samlOutputService.sendRequest(request, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedRequest = extractSamlPostRequest(httpResponse.getContentAsString());
		assertThat(encodedRequest.getID(), is(request.getID()));
		validateResponse(httpResponse);
	}

	@Test
	void sendArtifactRequest() throws Exception {
		var request = loadAuthnRequest();
		var credential = SamlTestBase.dummyCredential();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useArtifactBinding(true).build();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();

		samlOutputService.sendRequest(request, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedArtifact = extractSamlArtifactValue(httpResponse.getContentAsString());
		var requestIssuer = request.getIssuer().getValue();
		verify(artifactMap).put(encodedArtifact, requestIssuer, requestIssuer, request);
		validateResponse(httpResponse);
	}

	@Test
	void sendRedirectRequest() {
		var request = loadAuthnRequest();
		var credential = SamlTestBase.dummyCredential();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useRedirectBinding(true).build();

		samlOutputService.sendRequest(request, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		validateRedirectMessage(httpResponse, SamlIoUtil.SAML_REQUEST_NAME);
	}

	@Test
	void sendPostResponse() throws Exception {
		var response = loadAuthnResponse();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().build();

		samlOutputService.sendResponse(response, null, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedResponse = extractSamlPostResponse(httpResponse.getContentAsString());
		assertThat(encodedResponse.getID(), is(response.getID()));
		validateResponse(httpResponse);
	}

	@Test
	void sendArtifactResponse() throws Exception {
		var response = loadAuthnResponse();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useArtifactBinding(true).build();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();

		samlOutputService.sendResponse(response, null, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedArtifact = extractSamlArtifactValue(httpResponse.getContentAsString());
		var requestIssuer = response.getIssuer().getValue();
		verify(artifactMap).put(encodedArtifact, requestIssuer, requestIssuer, response);
		validateResponse(httpResponse);
	}

	@Test
	void sendLogoutResponseAsRedirect() throws Exception {
		var response = loadLogoutResponse();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useRedirectBinding(true).build();

		samlOutputService.sendResponse(response, null, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		// rendered as template
		validateResponse(httpResponse);
	}

	@Test
	void sendAuthnResponseAsRedirect() {
		var response = loadAuthnResponse();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useRedirectBinding(true).build();
		var credential = SamlTestBase.dummyCredential();

		samlOutputService.sendResponse(response, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		// normal SAML redirect
		validateRedirectMessage(httpResponse, SamlIoUtil.SAML_RESPONSE_NAME);
	}

	private static void validateRedirectMessage(MockHttpServletResponse httpResponse, String messageType) {
		assertThat(httpResponse.getStatus(), is(HttpStatus.FOUND.value()));
		var location = httpResponse.getHeader(HttpHeaders.LOCATION);
		assertThat(location, startsWith(ENDPOINT + '?' + messageType + '='));
		assertThat(location, containsString('&' + SamlIoUtil.SAML_RELAY_STATE + '=' + RELAY_STATE));
		assertThat(location, containsString('&' + SamlIoUtil.SAML_REDIRECT_SIGNATURE + '='));
		assertThat(location, containsString('&' + SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM + '='));
	}


	private static void validateResponse(MockHttpServletResponse httpResponse) throws Exception {
		assertThat(httpResponse.getStatus(), is(HttpStatus.OK.value()));
		var content = httpResponse.getContentAsString();
		assertThat(content, containsString(" action=\"" + ENDPOINT_ENCODED + '"'));
		var encodedRelayState = SamlHttpTestBase.extractHtmlFormValue( content, SamlIoUtil.SAML_RELAY_STATE);
		assertThat(encodedRelayState, is(RELAY_STATE));
	}

}
