/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

/**
 * Revocation handler endpoint. Copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider.
 * That class is final, so we cannot subclass it.
 * authenticate is customized to work around SAML2 kicking in when federating and provide some improved logging.
 * The copying means we are tied to an internal class from Spring Authentication Server.
 * <p>
 * Original Javadoc:
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Revocation.
 *
 * @author Vivek Babu
 * @author Joe Grandja
 * @see OAuth2TokenRevocationAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2.1">Section 2.1 Revocation Request</a>
 * @since 0.0.3
 */
@Slf4j
public class CustomTokenRevocationAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2AuthorizationService authorizationService;

	private final TrustBrokerProperties trustBrokerProperties;

	public CustomTokenRevocationAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			TrustBrokerProperties trustBrokerProperties) {
		this.authorizationService = authorizationService;
		this.trustBrokerProperties = trustBrokerProperties;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication =
				(OAuth2TokenRevocationAuthenticationToken) authentication;

		Authentication clientPrincipal =
				CustomOAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(authentication);
		String registeredClientId =
				OidcAuthenticationUtil.getClientIdFromPrincipal(clientPrincipal);

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				tokenRevocationAuthentication.getToken(), null);
		if (authorization == null) {
			log.info("No cached tokens for userPrincipal='{}' token='{}' (using input)", clientPrincipal.getName(),
					log.isDebugEnabled() ? OidcUtil.maskedToken(tokenRevocationAuthentication.getToken()) : "MASKED");
			// Return the authentication request when token not found
			return tokenRevocationAuthentication;
		}

		if (!(registeredClientId.equals(authorization.getRegisteredClientId()))) {
			log.error("Mismatch for userPrincipal='{}' having relyingPartyRegistrationId={} vs. registeredClientId={} error={}",
					clientPrincipal.getName(), registeredClientId, authorization.getRegisteredClientId(),
					OAuth2ErrorCodes.INVALID_CLIENT);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2Token> token = authorization.getToken(tokenRevocationAuthentication.getToken());
		if (token == null) {
			log.warn("No matching tokens for userPrincipal='{}' token='{}' error={}", clientPrincipal.getName(),
					log.isDebugEnabled() ? OidcUtil.maskedToken(tokenRevocationAuthentication.getToken()) : "HIDDEN",
					OAuth2ErrorCodes.INVALID_TOKEN);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		// persist revocation state
		authorization = CustomOAuth2AuthenticationProviderUtils.invalidate(authorization, token.getToken());
		this.authorizationService.save(authorization);

		// invalidate web session after revocation
		OidcSessionSupport.invalidateSession(trustBrokerProperties, "token invalidated");

		log.info("Token invalidated for userPrincipal='{}' tokenType={} token='{}'", clientPrincipal.getName(),
				tokenRevocationAuthentication.getTokenTypeHint(),
				log.isDebugEnabled() ? OidcUtil.maskedToken(tokenRevocationAuthentication.getToken()) : "MASKED");

		return new OAuth2TokenRevocationAuthenticationToken(token.getToken(), clientPrincipal);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		if (authentication == null) {
			throw new TechnicalException("Invalid Null Authentication");
		}
		log.debug("Received authenticationClass={}", authentication.getName());
		return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
