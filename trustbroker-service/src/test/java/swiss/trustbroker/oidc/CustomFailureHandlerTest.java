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
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

class CustomFailureHandlerTest {

	static class CustomAuthenticationException extends AuthenticationException {

		CustomAuthenticationException(String message) {
			super(message);
		}

	}

	private static final String ERROR_URL = "/app/failure";

	private static final String RETURN_URL = "https://localhost/return";

	private static final String ISSUER = "https://localhost:4200";

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private TrustBrokerProperties trustBrokerProperties;

	private CustomFailureHandler customFailureHandler;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		customFailureHandler = new CustomFailureHandler("test", relyingPartyDefinitions, trustBrokerProperties);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
		HttpExchangeSupport.end();
	}

	@ParameterizedTest
	@MethodSource
	void testOnAuthenticationFailure(AuthenticationException exception, String redirectUri, String expectedRedirect)
			throws IOException {
		var rp = RelyingParty.builder().id("rpId").build();
		var clientId = "client1";
		var acWhitelist = AcWhitelist.builder()
									   .acUrls(List.of(RETURN_URL))
									   .build();
		acWhitelist.calculateDerivedUrls();
		var client = OidcClient.builder()
							   .id(clientId)
							   .redirectUris(acWhitelist)
							   .build();
		var request = new MockHttpServletRequest();
		TraceSupport.setMdcTraceContext(request);
		request.setParameter(OidcUtil.OIDC_CLIENT_ID, clientId);
		request.addHeader(HttpHeaders.REFERER, "https://localhost");
		if (redirectUri != null) {
			var session = new MockHttpSession();
			request.setSession(session);
			OidcSessionSupport.setRedirectUri(session, redirectUri);
		}
		var response = new MockHttpServletResponse();
		var oidcProperties = new OidcProperties();
		oidcProperties.setIssuer(ISSUER);
		when(trustBrokerProperties.getOidc()).thenReturn(oidcProperties);
		when(trustBrokerProperties.getPerimeterUrl()).thenReturn(ISSUER);
		when(relyingPartyDefinitions.getRelyingPartyOidcClientByOidcClientId(clientId, null, trustBrokerProperties, true))
				.thenReturn(Pair.of(rp, client));
		HttpExchangeSupport.begin(request, response);

		customFailureHandler.onAuthenticationFailure(request, response, exception);

		assertThat(response.getRedirectedUrl(), startsWith(expectedRedirect));
		if (redirectUri == null) {
			assertThat(request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION), is(exception));
		}
	}

	static Object[][] testOnAuthenticationFailure() {
		var exception = new Saml2AuthenticationException(new Saml2Error(OAuth2ErrorCodes.INVALID_REQUEST,
				OidcExceptionHelper.CLIENT_AUTH_FAILED + "code"),
				"ignored");
		return new Object[][] {
				{
					new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "ignored",
						"http://ignored"), OidcExceptionHelper.OAUTH_2_0_PARAMETER + "code"),
						RETURN_URL,
						RETURN_URL + "?error=invalid_request&error_description=code&error_uri=" +
								WebUtil.urlEncodeValue(ISSUER + ERROR_URL)
				},
				{
						exception,
						RETURN_URL,
						RETURN_URL + "?error=invalid_request&error_description=code&error_uri=" +
								WebUtil.urlEncodeValue(ISSUER + ERROR_URL)
				},
				{
						exception,
						null,
						ERROR_URL
				},
				{
						exception,
						ISSUER + "/path",
						ISSUER + "/path?error=invalid_request&error_description=code&error_uri=" +
								WebUtil.urlEncodeValue(ISSUER + ERROR_URL)
				},
				{
						exception,
						"https://client.trustbroker.swiss/return",
						ERROR_URL
				},
				{
						new CustomAuthenticationException("ignored"),
						RETURN_URL,
						ERROR_URL // cannot extract error code from custom exception
				}
		};
	}

}
