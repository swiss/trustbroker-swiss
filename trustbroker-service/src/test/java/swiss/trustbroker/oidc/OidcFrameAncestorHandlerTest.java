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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.doReturn;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

class OidcFrameAncestorHandlerTest {

	private static final String CLIENT_ID = "oidcClient1";

	private TrustBrokerProperties properties;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@Mock
	private RelyingPartyDefinitions definitions;

	private OidcFrameAncestorHandler oidcFrameAncestorHandler;

	@BeforeEach
	void setUp() {
		MockitoAnnotations.openMocks(this);
		properties = new TrustBrokerProperties();
		request = new MockHttpServletRequest();
		oidcFrameAncestorHandler = new OidcFrameAncestorHandler(request, definitions, properties);
	}


	@Test
	void supportedFrameAncestorsNoClient() {
		var result = oidcFrameAncestorHandler.supportedFrameAncestors();
		assertThat(result, is(Collections.emptyList()));
		mockClientIdInRequest();
		result = oidcFrameAncestorHandler.supportedFrameAncestors();
		assertThat(result, is(Collections.emptyList()));
		doReturn(Optional.empty()).when(definitions).getOidcClientConfigById(CLIENT_ID, properties);
		result = oidcFrameAncestorHandler.supportedFrameAncestors();
		assertThat(result, is(Collections.emptyList()));
	}

	@Test
	void supportedFrameAncestorsNoAcUrls() {
		var oidcClient = givenOidcClient(null);
		doReturn(Optional.of(oidcClient)).when(definitions).getOidcClientConfigById(CLIENT_ID, properties);
		var result = oidcFrameAncestorHandler.supportedFrameAncestors();
		assertThat(result, is(Collections.emptyList()));
		oidcClient.setRedirectUris(givenAcWhitelist(null, null));
		result = oidcFrameAncestorHandler.supportedFrameAncestors();
		assertThat(result, is(Collections.emptyList()));
	}

	@Test
	void supportedFrameAncestorsFromAcUrls() {
		mockClientIdInRequest();
		List<String> acUrls = List.of("https://domain1.net/authenticate", "https://domain2.net:8443/login");
		var redirectUris = givenAcWhitelist(acUrls, null);
		var oidcClient = givenOidcClient(redirectUris);
		doReturn(Optional.of(oidcClient)).when(definitions).getOidcClientConfigById(CLIENT_ID, properties);
		var result = oidcFrameAncestorHandler.supportedFrameAncestors();
		// origins derived from acUrls
		assertThat(result, is(List.of("https://domain1.net", "https://domain2.net:8443")));
	}

	@Test
	void resolveFrameAncestors() {
		mockClientIdInRequest();
		List<String> acUrls = List.of("https://domain1.net", "https://domain2.net");
		List<String> frameAncestors = List.of("https://ancestor1.net", "https://ancestor2.net/login");
		var redirectUris = givenAcWhitelist(acUrls, frameAncestors);
		var oidcClient = givenOidcClient(redirectUris);
		doReturn(Optional.of(oidcClient)).when(definitions).getOidcClientConfigById(CLIENT_ID, properties);
		var result = oidcFrameAncestorHandler.supportedFrameAncestors();
		// frame ancestors are used as provided, no derivation of origins
		assertThat(result, is(frameAncestors));
	}

	private void mockClientIdInRequest() {
		HttpExchangeSupport.begin(request, response);
		request.setParameter(OidcUtil.OIDC_CLIENT_ID, CLIENT_ID);
	}

	private OidcClient givenOidcClient(AcWhitelist redirectUris) {
		return OidcClient.builder()
						 .id(CLIENT_ID)
						 .redirectUris(redirectUris)
						 .build();
	}

	private static AcWhitelist givenAcWhitelist(List<String> acUrls, List<String> frameAncestors) {
		return AcWhitelist.builder()
						  .acUrls(acUrls)
						  .frameAncestors(frameAncestors)
						  .build();
	}


}
