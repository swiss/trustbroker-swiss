/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.x
 * org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.
 * PublicClientRefreshTokenAuthenticationProvider
 *
 * Suggested here:
 * https://github.com/spring-projects/spring-authorization-server/commit/faad0be15367b9d138be6774356adb6e77c5d386
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

package swiss.trustbroker.oidc.pkce;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

public final class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

	private final RegisteredClientRepository registeredClientRepository;

	public PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		PublicClientRefreshTokenAuthenticationToken publicClientAuthentication =
				(PublicClientRefreshTokenAuthenticationToken) authentication;

		if (!ClientAuthenticationMethod.NONE.equals(publicClientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = publicClientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (!registeredClient.getClientAuthenticationMethods()
							 .contains(publicClientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient("authentication_method");
		}

		return new PublicClientRefreshTokenAuthenticationToken(registeredClient);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PublicClientRefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient(String parameterName) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_CLIENT,
				"Public client authentication failed: " + parameterName,
				null
		);
		throw new OAuth2AuthenticationException(error);
	}
}