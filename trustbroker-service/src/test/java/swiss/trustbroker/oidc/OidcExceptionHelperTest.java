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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlNamespace;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

@SpringBootTest(classes = OidcExceptionHelper.class)
class OidcExceptionHelperTest {

	private MockHttpSession session;

	private MockHttpServletRequest request;

	@BeforeEach
	void setUp() {
		SamlInitializer.initSamlSubSystem();
		request = new MockHttpServletRequest();
		session = new MockHttpSession();
	}

	@ParameterizedTest
	@MethodSource
	void adaptLocationForAuthenticationException(AuthenticationException authException, String redirectUri, String returnUrl,
			String issuer, String expectedResult) {
		mockSession(authException, redirectUri);
		var result = OidcExceptionHelper.buildLocationForAuthenticationException(request, returnUrl, issuer, "unit-test",
				uri -> redirectUri != null && redirectUri.equals(uri));
		assertThat(result, is(expectedResult));
	}

	static Object[][] adaptLocationForAuthenticationException() {
		return new Object[][] {
				{ // no session, no exception -> location not changed
						null,
						null,
						null,
						null,
						null
				},
				{ // session but no exception  -> location not changed
						null,
						"unused",
						null,
						null,
						null
				},
				{ // invalid redirect URI -> location not changed
						null,
						"https://:80/invalid",
						null,
						null,
						null
				},
				{ // OAuth exception
						new OAuth2AuthenticationException("test"),
						"http://localhost/client2",
						null,
						null,
						"http://localhost/client2?error=test",
				},
				{ // SAML exception but no saved request -> location not changed
						new Saml2AuthenticationException(new Saml2Error("any", "thing")),
						null,
						null,
						null,
						null
				},
				{ // exception code added
						new Saml2AuthenticationException(new Saml2Error("invalid_client", "bla bla")),
						"http://localhost/client1",
						null,
						null,
						"http://localhost/client1?error=invalid_client"
				},
				{ // exception code added
						new OAuth2AuthenticationException(new OAuth2Error("invalid_client", "bla bla", "ignored")),
						"http://localhost/client1",
						null,
						null,
						"http://localhost/client1?error=invalid_client"
				},
				{ // message mapped
						new OAuth2AuthorizationCodeRequestAuthenticationException(
								new OAuth2Error("invalid_client", OidcExceptionHelper.CLIENT_AUTH_FAILED + "code_challenge",
										"ignored"), null),
						"http://localhost/client1",
						null,
						null,
						"http://localhost/client1?error=invalid_client&error_description=code_challenge"
				},
				{ // description mapped
						new OAuth2AuthenticationException(new OAuth2Error("invalid_client", "bla bla", "ignored"),
								OidcExceptionHelper.OAUTH_2_0_PARAMETER + "code"),
						"http://localhost/client1",
						null,
						null,
						"http://localhost/client1?error=invalid_client&error_description=code"
				},
				{ // exception code added to existing query
						new Saml2AuthenticationException(new Saml2Error("invalid_request", "ignored")),
						"http://localhost/app2?foo=bar",
						null,
						null,
						"http://localhost/app2?foo=bar&error=invalid_request"
				},
				{ // with exception URI
						new Saml2AuthenticationException(new Saml2Error("invalid_request", "ignored")),
						"http://localhost/app2?foo=bar",
						"http://location/app/failure/12345",
						null,
						"http://localhost/app2?foo=bar&error=invalid_request&"
								+ "error_uri=http%3A%2F%2Flocation%2Fapp%2Ffailure%2F12345"
				},
				{ // with exception URI
						new OidcExceptionHelper.OidcAuthenticationException(
								new OAuth2Error("invalid_request", "wrong value","ignored"), "ignored too"),
						"http://localhost/app2?foo=bar",
						"http://location/app/failure/12345",
						null,
						"http://localhost/app2?foo=bar&error=invalid_request&error_description=wrong+value&"
								+ "error_uri=http%3A%2F%2Flocation%2Fapp%2Ffailure%2F12345"
				},
				{ // with relative exception URI
						new OidcExceptionHelper.OidcAuthenticationException(
								new OAuth2Error("invalid_request", "wrong value","ignored"), "ignored too"),
						"http://localhost/app2?foo=bar",
						"/app/failure/12345",
						"http://location",
						"http://localhost/app2?foo=bar&error=invalid_request&error_description=wrong+value&"
								+ "error_uri=http%3A%2F%2Flocation%2Fapp%2Ffailure%2F12345"
				},
				// String authorizationUri, String clientId, Authentication principal,
				//			@Nullable String redirectUri, @Nullable String state, @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters
				{
						givenAuthorizationCodeException(
								new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "wrong value","ignored"),
								OAuth2ParameterNames.REDIRECT_URI
						),
						"http://localhost/attacker",
						"http://location/app/failure/3333",
						null,
						null
				}
		};
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationException givenAuthorizationCodeException(OAuth2Error error,
			String parameterName) {
		var principal = new Principal() {
			@Override
			public String getName() {
				return "anonymous";
			}
		};
		var authority = new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return "anonymous";
			}
		};
		var principalToken = new AnonymousAuthenticationToken("auth1", principal, List.of(authority));
		var token =
				new OAuth2AuthorizationCodeRequestAuthenticationToken("https://localhost/auth", "client1",
						principalToken,
						"https://localhost/attacker", null, Set.of("openid"), Collections.emptyMap());
		return OidcExceptionHelper.createOidcException(error, parameterName, token, null);
	}

	@Test
	void saveAuthenticationException() {
		// no exception in session
		var redirectUri = "http://localhost/test";
		mockSession(null, redirectUri);
		var authException = new OAuth2AuthenticationException("test");
		assertThat(OidcExceptionHelper.hasAuthenticationException(request), is(false));
		OidcExceptionHelper.saveAuthenticationException(request, authException);
		assertThat(OidcExceptionHelper.hasAuthenticationException(request), is(true));
		var result = OidcExceptionHelper.buildLocationForAuthenticationException(
				request, "/return", "http://localhost", "unit-test", redirectUri::equals);
		assertThat(result, is("http://localhost/test?error=test&error_uri=http%3A%2F%2Flocalhost%2Freturn"));
	}

	private void mockSession(Exception authException, String redirectUri) {
		if (authException != null) {
			request.setSession(session);
			session.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, authException);
		}
		if (redirectUri != null) {
			request.setSession(session);
			OidcSessionSupport.setRedirectUri(session, redirectUri);
		}
	}

	@Test
	void enrichResponseError() {
		var response = SamlFactory.createResponse(Response.class, "issuer");
		response.setStatus(SamlFactory.createResponseStatus(StatusCode.RESPONDER, StatusCode.UNKNOWN_PRINCIPAL, null));
		Collection<Saml2Error> errors = new ArrayList<>();
		var error = new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "not supported");
		errors.add(error);
		var properties = givenOidcProperties();
		var resultErrors = OidcExceptionHelper.enrichResponseError(properties, response, errors);
		assertThat(resultErrors, hasSize(2));
		// first one is the mapped one
		assertThat(resultErrors.get(0).getErrorCode(), is("unknown_principal"));
		assertThat(resultErrors.get(0).getDescription(), containsString(StatusCode.UNKNOWN_PRINCIPAL));
		assertThat(resultErrors.get(1).getErrorCode(), is(error.getErrorCode()));
		assertThat(resultErrors.get(1).getDescription(), is(error.getDescription()));
	}

	@ParameterizedTest
	@MethodSource
	void mapErrorCode(String saml2ErrorCode, String saml2ErrorDescription, String statusCode, String nestedStatusCode,
			String statusMessage, String expectedCode) {
		Collection<Saml2Error> errors = new ArrayList<>();
		if (saml2ErrorCode != null) {
			var error = new Saml2Error(saml2ErrorCode, saml2ErrorDescription);
			errors.add(error);
		}
		OidcProperties properties = givenOidcProperties();
		var code = OidcExceptionHelper.mapErrorCode(properties, statusCode, nestedStatusCode, statusMessage, errors);
		assertThat(code, is(expectedCode));
	}

	static String[][] mapErrorCode() {
		return new String[][] {
				// default:
				{ null, null, null, null, null, OidcExceptionHelper.DEFAULT_ERROR_CODE },
				// code from error list:
				{ Saml2ErrorCodes.INVALID_DESTINATION, "anything", null, null, null, Saml2ErrorCodes.INVALID_DESTINATION },
				// code from error list, saml code ignored:
				{ Saml2ErrorCodes.INVALID_DESTINATION, "anything", StatusCode.RESPONDER, StatusCode.NO_AVAILABLE_IDP, "freetext",
						"no_available_idp" },
				// code from error list ignored, nested used:
				{ Saml2ErrorCodes.INVALID_DESTINATION, "Invalid status [InvalidNameIDPolicy]", StatusCode.INVALID_NAMEID_POLICY,
						null, "freetext", "invalid_name_id_policy" },
				// status message can be mapped:
				{ Saml2ErrorCodes.INVALID_ISSUER, "anything", null, null,
						"urn:example:names:tc:SAML:2.0:status:PwResetSuccessful",
						"example_pw_reset_successful" },
				// status code can be mapped:
				{ Saml2ErrorCodes.INVALID_ISSUER, "anything",
						"urn:example:names:tc:SAML:2.0:status:UserCancel", null, null,
						"example_user_cancel" },
				// nested status code can be mapped:
				{ Saml2ErrorCodes.INVALID_ISSUER, "anything", null, StatusCode.UNKNOWN_PRINCIPAL, null,
						"unknown_principal" },
				// responder -> nested used:
				{ null, null, StatusCode.RESPONDER, StatusCode.INVALID_NAMEID_POLICY, "freetext",
						"invalid_name_id_policy" },
				// responder w/o nested:
				{ null, null, StatusCode.RESPONDER, null, "freetext", OidcExceptionHelper.DEFAULT_ERROR_CODE },
				// status code used, nested ignored:
				{ null, null, StatusCode.INVALID_NAMEID_POLICY, StatusCode.PROXY_COUNT_EXCEEDED, "freetext",
						"invalid_name_id_policy" }
		};
	}

	private static OidcProperties givenOidcProperties() {
		var properties = new OidcProperties();
		var exampleNs = new SamlNamespace("urn:example:names:tc:SAML:2.0:status", "example");
		var oasisNs = new SamlNamespace("urn:oasis:names:tc:SAML:2.0:status", null);
		properties.setSamlNamespacesMappedToOidcFormat(List.of(exampleNs, oasisNs));
		return properties;
	}

}
