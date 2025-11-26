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

import java.util.Collection;
import java.util.Collections;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.oidc.JwtUtil;


// https://github.com/spring-projects/spring-security/issues/16406
@AllArgsConstructor
@Slf4j
public class CustomUserInfoAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2AuthorizationService authorizationService;

	private final JwtAuthenticationProvider jwtAuthenticationProvider;

	private final OidcUserInfoAuthenticationProvider userInfoAuthenticationProvider;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		var tokenValue = (String) authentication.getCredentials();
		if (tokenValue == null) {
			throw new RequestDeniedException("Missing UserInfo endpoint Authorization token");
		}

		if (JwtUtil.isJwt(tokenValue)) {
			if (authentication instanceof BearerTokenAuthenticationToken) {
				return jwtAuthenticationProvider.authenticate(authentication);
			}
			return userInfoAuthenticationProvider.authenticate(authentication);
		}

		JwtUtil.validateToken(tokenValue);

		// Opaque oidcIdToken
		var auth2Authorization = authorizationService.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);

		if (auth2Authorization == null) {
			throw new RequestDeniedException(String.format("No authorization found for token=%s", tokenValue));
		}

		OAuth2Authorization.Token<OAuth2Token> authorizedToken = auth2Authorization.getToken(tokenValue);

		if (authorizedToken == null) {
			log.error("No authorization found for token={}", tokenValue);
			throw new RequestDeniedException(String.format("No authorization found for token=%s", tokenValue));
		}

		if (!authorizedToken.isActive()) {
			log.error("Token={} expired or inactive", tokenValue);
			throw new RequestDeniedException(String.format("Token=%s expired or inactive", tokenValue));
		}

		Collection<GrantedAuthority> authorities = Collections.emptyList();

		var oidcIdToken = auth2Authorization.getToken(OidcIdToken.class);
		if (oidcIdToken == null) {
			// LATER OAuth2 idps are not using the IdToken
			throw new RequestDeniedException(String.format("No IdToken found for token=%s", tokenValue));
		}
		var idTokenClaims = oidcIdToken.getToken().getClaims();

		var principal = new DefaultOAuth2AuthenticatedPrincipal(auth2Authorization.getPrincipalName(), idTokenClaims, authorities);

		var accessToken = auth2Authorization.getToken(OAuth2AccessToken.class);
		if (accessToken == null) {
			throw new RequestDeniedException(String.format("No OAuth2AccessToken found for token=%s", tokenValue));
		}
		var token = accessToken.getToken();

		return new BearerTokenAuthentication(principal, token, authorities);

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcUserInfoAuthenticationProvider.class.isAssignableFrom(authentication) || BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}


}
