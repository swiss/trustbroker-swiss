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

package swiss.trustbroker.oidc.client.dto;

import java.net.URI;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;

/**
 * Configuration read from OIDC metadata.
 */
@ToString // required to ToString.Exclude
@Data
@Builder(toBuilder = true)
@AllArgsConstructor
@NoArgsConstructor
public class OpenIdProviderConfiguration {

	private String issuerId;

	private URI authorizationEndpoint;

	private URI tokenEndpoint;

	private URI userinfoEndpoint;

	private URI jwkEndpoint;

	private JWKSet jwkSet;

	private ClientAuthenticationMethods authenticationMethods;

	@ToString.Exclude
	private String clientSecret;

}
