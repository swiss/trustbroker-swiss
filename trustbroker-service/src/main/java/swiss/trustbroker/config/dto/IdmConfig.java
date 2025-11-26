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
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.config.RegexNameValue;

/**
 * Configuration for optional IDM integration.
 * <br>
 * Potentially breaking changes:
 * <ul>
 *     <li>With 1.10.0 value of attributes changed to Object to allow nested structures.</li>
 * </ul>
 *
 * @see IdmQueryService
 * @see swiss.trustbroker.federation.xmlconfig.IdmLookup
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdmConfig {

	/**
	 * IDM enabled.
	 * <br/>
	 * Default: true (but there is no default IDM service implementation)
	 */
	@Builder.Default
	private boolean enabled = true;

	/**
	 * Endpoint URL of the IDM
	 */
	private String endpointUrl;

	/**
	 * TLS protocol to use for the connection.
	 */
	private String tlsProtocol;

	/**
	 * Keystore for accessing the IDM.
	 */
	private KeystoreProperties keystore;

	/**
	 * Truststore for accessing the IDM.
	 */
	private KeystoreProperties truststore;

	/**
	 * Technical user for accessing the IDM.
	 */
	private TechUserProperties techuser;

	/**
	 * Security token signer.
	 */
	private KeystoreProperties signercert;

	/**
	 * Security token for accessing the IDM.
	 */
	private SecToken secToken;

	/**
	 * Mappings that might be needed by the implementation.
 	 */
	private List<RegexNameValue> mappings;

	/**
	 * Custom attributes that might be needed by the implementation.
 	 */
	private Map<String, Object> attributes;

	/**
	 * HTTP trace header supported by service to correlate calls from XTB.
	 */
	private String traceIdHeader;

}
