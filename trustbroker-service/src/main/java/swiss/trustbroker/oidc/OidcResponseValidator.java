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

import lombok.AllArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationProvider;

@AllArgsConstructor
class OidcResponseValidator
		implements Converter<OpenSaml5AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> {

	private final TrustBrokerProperties properties;

	private final Converter<OpenSaml5AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> delegate;

	@Override
	public Saml2ResponseValidatorResult convert(OpenSaml5AuthenticationProvider.ResponseToken responseToken) {
		var result = delegate.convert(responseToken);
		if (result != null && result.hasErrors()) {
			result = Saml2ResponseValidatorResult.failure(
					OidcExceptionHelper.enrichResponseError(properties.getOidc(), responseToken.getResponse(),
							result.getErrors()));
		}
		return result;
	}
}
