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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ContentSecurityPolicies;
import swiss.trustbroker.config.dto.FrameOptionsPolicies;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.oidc.session.TomcatSessionManager;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HeaderBuilder;
class OidcTxFilterTest {

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private OidcFrameAncestorHandler oidcFrameAncestorHandler;

	@Mock
	private TomcatSessionManager tomcatSessionManager;

	@Mock
	private ApiSupport apiSupport;

	private TrustBrokerProperties properties;

	private OidcTxFilter filter;

	@BeforeEach
	void setUp() {
		MockitoAnnotations.openMocks(this);
		properties = new TrustBrokerProperties();
		properties.setOidc(new OidcProperties());
		filter = new OidcTxFilter(relyingPartyDefinitions, properties, tomcatSessionManager, new ApiSupport(properties));
	}

	@ParameterizedTest
	@MethodSource
	void validateAndSetSecurityHeaders(String path, String frameOptions, String csp) {
		var request = new MockHttpServletRequest();
		request.setRequestURI(path);
		var response = new MockHttpServletResponse();
		properties.setPerimeterUrl("https://localhost/saml");
		properties.getOidc().setPerimeterUrl("https://localhost/oidc");

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
	}

	static Object[][] validateAndSetSecurityHeaders() {
		var frameOptions = new FrameOptionsPolicies();
		var csp = new ContentSecurityPolicies();
		return new Object[][] {
				{ ApiSupport.OIDC_USERINFO, frameOptions.getOidc(), csp.getOidc() },
				{ ApiSupport.FRONTEND_CONTEXT + "/any", frameOptions.getFallback(), csp.getFrontend() },
				{ ApiSupport.ADFS_PATH + "/ls", frameOptions.getFallback(), csp.getSaml() },
				{ "index.html", frameOptions.getFallback(), csp.getFallback() }
		};
	}

}
