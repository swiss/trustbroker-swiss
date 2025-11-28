/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator
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

import java.util.function.Consumer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.util.UrlAcceptor;

/**
 * Partially copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator
 * Javadoc of original class:
 *
 * A {@code Consumer} providing access to the {@link OAuth2AuthorizationCodeRequestAuthenticationContext}
 * containing an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
 * and is the default {@link OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthenticationValidator(Consumer) authentication validator}
 * used for validating specific OAuth 2.0 Authorization Request parameters used in the Authorization Code Grant.
 *
 * <p>
 * The default implementation first validates {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getRedirectUri()}
 * and then {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getScopes()}.
 * If validation fails, an {@link OAuth2AuthorizationCodeRequestAuthenticationException} is thrown.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2AuthorizationCodeRequestAuthenticationContext
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
@Slf4j
public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

	@Override
	public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authenticationContext.getAuthentication();
		String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();
		if (StringUtils.hasText(requestedRedirectUri)) {
			// ***** redirect_uri is available in authorization request
			validateRedirectUri(registeredClient, authorizationCodeRequestAuthentication, requestedRedirectUri);
		}
		else {
			// ***** redirect_uri is NOT available in authorization request
			if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID) ||
					registeredClient.getRedirectUris().size() != 1) {
				// redirect_uri is REQUIRED for OpenID Connect
				OidcExceptionHelper.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}
	}

	static void validateRedirectUri(RegisteredClient registeredClient,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			String requestedRedirectUri) {
		var clientRedirectUris = registeredClient.getRedirectUris();
		if (!UrlAcceptor.isRedirectUrlOkForAccess(requestedRedirectUri, clientRedirectUris)) {
			log.error("oidcClient={} - requested redirectUri={} does not match configured redirectUris={}",
					registeredClient.getClientId(), requestedRedirectUri, clientRedirectUris);
			OidcExceptionHelper.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
					authorizationCodeRequestAuthentication, registeredClient);
		}
	}

}
