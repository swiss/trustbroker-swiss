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

package swiss.trustbroker.oidc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;

class CustomOAuth2TokenExchangeAuthenticationConverterTest {

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";
	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private final CustomOAuth2TokenExchangeAuthenticationConverter converter =
			new CustomOAuth2TokenExchangeAuthenticationConverter();

	@BeforeEach
	void setUp() {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("client", "secret"));
	}

	@AfterEach
	void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void convertReturnsNullWhenGrantTypeIsNotTokenExchange() {
		var request = baseRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

		assertNull(converter.convert(request));
	}

	@Test
	void convertReturnsAuthenticationTokenForValidRequest() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.removeParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.RESOURCE, "https://api-1.example.com");
		request.addParameter(OAuth2ParameterNames.RESOURCE, "https://api-2.example.com/resource");
		request.addParameter(OAuth2ParameterNames.AUDIENCE, "aud-1");
		request.addParameter(OAuth2ParameterNames.AUDIENCE, "aud-2");
		request.addParameter(OAuth2ParameterNames.SCOPE, "openid profile");
		request.addParameter("custom", "custom-value");
		request.addParameter("custom_multi", "a");
		request.addParameter("custom_multi", "b");
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "proof-value");

		var authentication = converter.convert(request);

		var token = assertInstanceOf(OAuth2TokenExchangeAuthenticationToken.class, authentication);
		assertEquals("subject-token", token.getSubjectToken());
		assertEquals(JWT_TOKEN_TYPE_VALUE, token.getSubjectTokenType());
		assertEquals(ACCESS_TOKEN_TYPE_VALUE, token.getRequestedTokenType());
		assertEquals(2, token.getResources().size());
		assertTrue(token.getResources().contains("https://api-1.example.com"));
		assertTrue(token.getResources().contains("https://api-2.example.com/resource"));
		assertEquals(2, token.getAudiences().size());
		assertTrue(token.getAudiences().contains("aud-1"));
		assertTrue(token.getAudiences().contains("aud-2"));
		assertNotNull(token.getScopes());
		assertTrue(token.getScopes().contains("openid"));
		assertTrue(token.getScopes().contains("profile"));
		assertEquals("custom-value", token.getAdditionalParameters().get("custom"));
		assertArrayEquals(new String[] { "a", "b" }, (String[]) token.getAdditionalParameters().get("custom_multi"));
		assertEquals("proof-value", token.getAdditionalParameters().get("dpop_proof"));
		assertEquals("POST", token.getAdditionalParameters().get("dpop_method"));
		assertEquals("https://server.example.com:8443/oauth2/token", token.getAdditionalParameters().get("dpop_target_uri"));
	}

	@Test
	void convertThrowsInvalidRequestForInvalidResourceUri() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addParameter(OAuth2ParameterNames.RESOURCE, "/relative");

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void convertThrowsUnsupportedTokenTypeForUnsupportedSubjectTokenType() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, "unsupported");

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void convertThrowsInvalidRequestWhenActorTokenProvidedWithoutType() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token");

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void convertThrowsInvalidRequestWhenActorTokenTypeProvidedWithoutToken() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void convertThrowsInvalidRequestWhenScopeProvidedMultipleTimes() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addParameter(OAuth2ParameterNames.SCOPE, "openid");
		request.addParameter(OAuth2ParameterNames.SCOPE, "profile");

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	@Test
	void convertThrowsInvalidRequestWhenDpopHeaderProvidedMultipleTimes() {
		var request = baseRequest();
		addRequiredTokenExchangeParams(request);
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "proof-1");
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "proof-2");

		var ex = assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
	}

	private static MockHttpServletRequest baseRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setScheme("https");
		request.setServerName("server.example.com");
		request.setServerPort(8443);
		request.setRequestURI("/oauth2/token");
		return request;
	}

	private static void addRequiredTokenExchangeParams(MockHttpServletRequest request) {
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, "subject-token");
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
	}

}

