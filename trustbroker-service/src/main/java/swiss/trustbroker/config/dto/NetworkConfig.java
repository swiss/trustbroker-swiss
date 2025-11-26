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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;

/**
 * Network configuration.
 *
 * @see ClaimsProvider
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkConfig {

	private String mobileGatewayIpRegex;

	/**
	 * Name for the Intranet network used in configurations.
	 * <br/>
	 * Default: INTRANET
	 */
	@Builder.Default
	private String intranetNetworkName = "INTRANET";

	/**
	 * Name for the Internet network used in configurations.
	 * <br/>
	 * Default: INTERNET
	 */
	@Builder.Default
	private String internetNetworkName = "INTERNET";

	/**
	 * HTTP header delivering the client network.
	 * Usually sent by load balancer
	 * <br/>
	 * Default: Client_Network (should be X-Client-Network)
	 */
	@Builder.Default
	private String networkHeader = "Client_Network";

	/**
	 * HTTP header for simulating the client network.
	 * Sent by test agents to test HRD rules.
	 * <br/>
	 * Default: "X-Simulated-Client-Network
	 */
	@Builder.Default
	private String testNetworkHeader = "X-Simulated-Client-Network";

	/**
	 * Running on K8S supporting canary routing using cookies, a test instance.
	 *
	 * @since 1.7.0
	 */
	@Builder.Default
	private String canaryMarkerName = "canary";

	/**
	 * Value for <code>canaryMarkerName</code>.
	 *
	 * @since 1.7.0
	 */
	@Builder.Default
	private String canaryEnabledValue = "always";

	/**
	 * Allow disabling OpenTelemetry traceparent propagation to backends that might block use otherwise.
	 *
	 * @since 1.7.0
	 */
	@Builder.Default
	private Boolean tracingEnabled = Boolean.TRUE;

	/**
	 * Default proxy URL.
	 *
	 * @since 1.9.0
	 */
	private String proxyUrl;

	/**
	 * Backend service connect timeout in seconds.
	 * <br/>
	 * Default: 30
	 *
	 * @since 1.10.0
	 */
	@Builder.Default
	private int backendConnectTimeoutSec = 30;

	public boolean isIntranet(String name) {
		return StringUtils.isNotEmpty(intranetNetworkName) && intranetNetworkName.equals(name);
	}

	public boolean isInternet(String name) {
		return StringUtils.isNotEmpty(internetNetworkName) && internetNetworkName.equals(name);
	}

}
