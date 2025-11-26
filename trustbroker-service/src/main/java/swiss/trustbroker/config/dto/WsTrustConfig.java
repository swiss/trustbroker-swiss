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

package swiss.trustbroker.config.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.util.ApiSupport;

/**
 * WS-Trust protocol configuration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WsTrustConfig {

	public enum SoapVersionConfig {
		SOAP_1_1,
		SOAP_1_2,
		SOAP_1_X
	}

	/**
	 * Feature toggle allowing to disable the WSTrust endpoint
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean enabled = true;

	/**
	 * Keystore path.
	 */
	private String cert;

	/**
	 * Keystore type.
	 */
	private String type;

	/**
	 * Keystore alias.
	 *
	 * @since 1.12.0
	 */
	private String alias;

	/**
	 * Keystore password.
	 */
	private String password;

	/**
	 * Allow base path differing from SAML API.
	 */
	@Builder.Default
	private String wsBasePath = ApiSupport.WSTRUST_API;

	/**
	 * Enable ISSUE request.
	 * <br/>
	 * Default: true
	 * @since 1.12.0
	 */
	@Builder.Default
	private boolean issueEnabled = true;

	/**
	 * Enable RENEW request.
	 * <br/>
	 * Default: false
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean renewEnabled = false;

	/**
	 * RENEW request requires a valid SSO session.
	 * <br/>
	 * Default: true
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean renewRequiresSsoSession = true;

	/**
	 * RENEW request requires a valid security token.
	 * <br/>
	 * Default: true
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean renewRequiresSecurityToken = true;

	/**
	 * Require signed SOAP requests.
	 * <br/>
	 * Default: true
	 * @since 1.12.0
	 */
	@Builder.Default
	private boolean renewRequireSignedRequests = true;

	/**
	 * Sign SOAP responses.
	 * <br/>
	 * Default: true
	 * @since 1.12.0
	 */
	@Builder.Default
	private boolean doSignResponse = true;

	/**
	 * Lifetime expiration in minutes.
	 * <br/>
	 * Default: 480 (8 hours)
	 * @since 1.12.0
	 */
	@Builder.Default
	private long lifetimeMin = 480;

	/**
	 * SOAP version.
	 * <br/>
	 * Default: SOAP_1_X (alternatives SOAP_1_1, SOAP_1_2)
	 */
	@Builder.Default
	private SoapVersionConfig soapVersion = SoapVersionConfig.SOAP_1_X;

	private List<String> soapHeadersToConsider;

}
