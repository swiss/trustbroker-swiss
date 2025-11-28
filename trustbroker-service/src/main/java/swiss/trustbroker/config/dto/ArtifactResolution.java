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
import swiss.trustbroker.common.config.KeystoreProperties;

/**
 * SAML artifact resolution protocol configuration.
 *
 * @see swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints
 * @see swiss.trustbroker.federation.xmlconfig.Certificates
 * @see <a href="http://saml.xml.org/saml-specifications">SAML Specifications</a>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ArtifactResolution {

	/**
	 *  XTB Artifact Resolution service URL, included in the metadata.
	 *  <br/>
	 *  Note: Currently, the path that is requested on XTB needs to be <code>/api/v1/saml/arp</code>.
	 */
	private String serviceUrl;

	/**
	 *  XTB Artifact Resolution index.
	 * <br/>
	 * Default: 0
	 */
	@Builder.Default
	private int index = 0;

	/**
	 * Lifetime of artifacts in cache in seconds.
	 */
	private int artifactLifetimeSecs;

	/**
	 * Artifact cache reap interval in seconds.
	 */
	private int artifactReapIntervalSecs;

	/**
	 * Persist artifact cache. Required for multi-line setups.
	 */
	private Boolean persistentCache;

	/**
	 * Default proxy URL for artifact resolution.
	 *
	 * @deprecated Use NetworkConfig.proxyUrl
	 * @see NetworkConfig#getProxyUrl()
	 */
	@Deprecated(since = "1.9.0")
	private String proxyUrl;

	/**
	 * Default truststore for artifact resolution.
	 */
	private KeystoreProperties truststore;

	/**
	 * Default keystore for artifact resolution.
	 */
	private KeystoreProperties keystore;

}
