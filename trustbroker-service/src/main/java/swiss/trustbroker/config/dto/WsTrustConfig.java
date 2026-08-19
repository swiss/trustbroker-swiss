/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.federation.xmlconfig.WsTrustBinding;
import swiss.trustbroker.util.ApiSupport;

/**
 * WS-Trust protocol configuration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class WsTrustConfig {

	public enum SoapVersionConfig {
		SOAP_1_1,
		SOAP_1_2,
		SOAP_1_X
	}

	/**
	 * Feature toggle allowing to disable the WSTrust endpoint
	 * <br/>
	 * Default: false (since 1.13.0)
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean enabled = false;

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
	 * @since 1.13.0
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
	 * Default: false (since 1.13.0)
	 * @deprecated use bindings
	 * @since 1.12.0
	 */
	@Builder.Default
	@Deprecated(since = "1.14.0", forRemoval = true)
	private boolean issueEnabled = false;

	/**
	 * Enable RENEW request.
	 * <br/>
	 * Default: false
	 * @since 1.11.0
	 * @deprecated use bindings
	 */
	@Builder.Default
	@Deprecated(since = "1.14.0", forRemoval = true)
	private boolean renewEnabled = false;

	/**
	 * List of exposed WS-Trust bindings.
	 * <br/>
	 * Default: none
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.WsTrustBinding
	 * @since 1.14.0
	 */
	@Builder.Default
	private List<String> bindings = Collections.emptyList();

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
	 * Require signed SOAP requests for WS-Trust ISSUE.
	 * <br/>
	 * Default: true
	 * @since 1.13.0
	 */
	@Builder.Default
	private boolean issueRequireSignedRequests = true;

	/**
	 * WS-Trust ISSUE requires timestamp.
	 * <br/>
	 * Default: true
	 * @since 1.15.0
	 */
	@Builder.Default
	private boolean issueRequireTimestamp = true;

	/**
	 * Require signed SOAP requests for WS-Trust ISSUE.
	 * <br/>
	 * Default: true
	 * @since 1.13.0
	 * @deprecated
	 */
	@Builder.Default
	@Deprecated(since = "1.13.0", forRemoval = true)
	private boolean issueRequireSignedAssertions = true;

	/**
	 * Require signed SOAP requests for WS-Trust RENEW.
	 * <br/>
	 * Default: true
	 * @since 1.13.0
	 */
	@Builder.Default
	private boolean renewRequireSignedRequests = true;

	/**
	 * Sign SOAP responses.
	 * <br/>
	 * Default: true
	 * @since 1.13.0
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

	/**
	 * SOAP headers considered by the WS-Trust implementation.
	 * <br/>
	 * Default: not set
	 */
	private List<String> soapHeadersToConsider;

	/**
	 * List of client networks allowed (using <code>trustbroker.config.network.networkHeader</code> HTTP header).
	 *
	 * Default: not restricted
	 * @since 1.13.0
	 */
	private List<String> allowedNetworks;

	/**
	 * Client networks enforced if configured (<code>allowedNetworks</code>).
	 * <br/>
	 * Default: true - set to false in order to warn for violations only
	 * @since 1.13.0
	 */
	@Builder.Default
	private boolean enforceNetwork = true;

	/**
	 * Regex of client IPs allowed (using <code>X-Forwarded-For</code> HTTP header).
	 * <br/>
	 * @since 1.13.0
	 */
	private String allowedClientIpRegex;

	/**
	 * Client IPs enforced if configured (<code>allowedClientIpRegex</code>).
	 * <br/>
	 * Default: true - set to false in order to warn for violations only
	 * @since 1.13.0
	 */
	@Builder.Default
	private boolean enforceClientIp = true;

	public Set<WsTrustBinding> getWsTrustBindings() {
		Set<WsTrustBinding> result = new HashSet<>();
		if (issueEnabled) {
			log.warn("Deprecated trustbroker.config.wstrust.issue=true - configure  trustbroker.config.wstrust.bindings "
					+ "including ISSUE instead");
			result.add(WsTrustBinding.ISSUE);
		}
		if (renewEnabled) {
			log.warn("Deprecated trustbroker.config.wstrust.renew=true - configure  trustbroker.config.wstrust.bindings "
					+ "including RENEW instead");
			result.add(WsTrustBinding.RENEW);
		}
		if (bindings != null) {
			bindings.stream().map(WsTrustBinding::ofNameOrValue).collect(Collectors.toCollection(() -> result));
		}
		return Collections.unmodifiableSet(result);
	}
}
