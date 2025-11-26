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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import swiss.trustbroker.common.exception.TechnicalException;

public class OidcAuthenticationUtil {

	private OidcAuthenticationUtil() {}

	public static String getClientIdFromPrincipal(Authentication clientPrincipal) {

		if (Saml2Authentication.class.isAssignableFrom(clientPrincipal.getClass())) {
			DefaultSaml2AuthenticatedPrincipal registeredClient =
					(DefaultSaml2AuthenticatedPrincipal) clientPrincipal.getPrincipal();
			if (registeredClient != null) {
				return registeredClient.getRelyingPartyRegistrationId();
			}
		}

		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(clientPrincipal.getClass())) {
			RegisteredClient registeredClient = ((OAuth2ClientAuthenticationToken) clientPrincipal).getRegisteredClient();
			if (registeredClient != null) {
				return registeredClient.getId();
			}
		}
		throw new TechnicalException(String.format("Could not define clientPrincipal for= %s", clientPrincipal));
	}
}
