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
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;

/**
 * Support configuration.
 *
 * @see ClaimsProvider
 * @since 1.7.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Support {

	/**
	 * Feature flag
	 */
	@Builder.Default
	private boolean enabled = false;

	/**
	 * HTTP cookie or header name identifying the debug session.
	 */
	private String debugMarkerName;

	/**
	 * Value of the cookie or header signaling debug ON e.g. 'true'
	 */
	private String debugEnabledValue;

	/**
	 * Network header if present checked against the configured regexp e.g. 'INTRANET|INTERNET'
	 */
	private String allowedNetworks;

	/**
	 * List of IP regexp rules matched against the IP address received from perimeter or socket e.g. '192\.168\..*'
	 */
	private List<String> allowedClientIps;

	/**
	 * Logger names handle on a higher level than the default logging.logger level.
	 */
	private Map<String, String> level;

}
