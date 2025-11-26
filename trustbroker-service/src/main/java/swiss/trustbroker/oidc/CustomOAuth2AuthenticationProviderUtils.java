/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

/**
 * Copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils
 * That class is final and the method package private. It is also duplicated in
 * org.springframework.security.oauth2.server.oidc.authentication.OidcAuthenticationProviderUtils.
 * So we cannot re-use that code.
 * invalidate is unchanged.
 * getAuthenticatedClientElseThrowInvalidClient is adapted to Saml2Authentication.
 * The copying means we are tied to an internal class from Spring Authentication Server.
 * <p>
 * Original Javadoc:
 * Utility methods for the OpenID Connect 1.0 {@link AuthenticationProvider}'s.
 *
 * @author Joe Grandja
 * @since 0.1.1
 */
@Slf4j
public class CustomOAuth2AuthenticationProviderUtils {

	private CustomOAuth2AuthenticationProviderUtils() {
	}

	static Authentication getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		Authentication clientPrincipal = null;
		if (Saml2Authentication.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (Saml2Authentication) authentication.getPrincipal();
		}

		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}

		if (clientPrincipal == null) {
			log.error("Principal invalid: principalClass={}  authentication='{}'",
					authentication.getPrincipal().getClass(), authentication);
		}
		else if (clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		else {
			// OAuth2AuthenticationException status=200 => impossible to see if the principal is correct or not
			log.error("Principal not authenticated: userPrincipal='{}' authentication='{}'",
					clientPrincipal.getName(), authentication);
		}
		// OAuth2AuthenticationException status=200 => impossible to see if the principal is correct or not
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	static <T extends OAuth2Token> OAuth2Authorization invalidate(
			OAuth2Authorization authorization, T token) {
		// revoke any token
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(token,
						metadata ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

		// refresh_token invalidates dependant access_token and code
		if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
			authorizationBuilder.token(
					authorization.getAccessToken().getToken(),
					metadata ->
							metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

			// code
			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
					authorization.getToken(OAuth2AuthorizationCode.class);
			if (authorizationCode != null && !authorizationCode.isInvalidated()) {
				authorizationBuilder.token(
						authorizationCode.getToken(),
						metadata ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
			}
		}
		return authorizationBuilder.build();
	}

}
