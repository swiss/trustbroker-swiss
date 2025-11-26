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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * SAML/OIDC protocol endpoints.
 *
 * @see <a href="http://saml.xml.org/saml-specifications">SAML Specifications</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery</a>
 */
@XmlRootElement(name = "ProtocolEndpoints")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class ProtocolEndpoints implements Serializable {

	/**
	 * SAML/OIDC metadata URL.
	 */
	@XmlElement(name = "MetadataUrl")
	private String metadataUrl;

	/**
	 * Proxy URL for these endpoints that overrides global default.
	 * <br/>
	 * Set to empty string to override global default to use no proxy.
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "ProxyUrl")
	private String proxyUrl;

	/**
	 * SAML Artifact Resolution Protocol URL.
	 */
	@XmlElement(name = "ArtifactResolutionUrl")
	private String artifactResolutionUrl;

	/**
	 * SAML Artifact Resolution Protocol index.
	 */
	@XmlElement(name = "ArtifactResolutionIndex")
	private Integer artifactResolutionIndex;

	/**
	 * @deprecated Use proxyUrl.
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@XmlElement(name = "ArtifactResolutionProxyUrl")
	private String artifactResolutionProxyUrl;

	/**
	 * @deprecated Use proxyUrl.
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@SuppressWarnings("java:S4275") // renaming getter for transition
	public String getArtifactResolutionProxyUrl() {
		return proxyUrl;
	}

	/**
	 * @deprecated Use proxyUrl
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	public void setArtifactResolutionProxyUrl(String proxyUrl) {
		log.warn("Use of deprecated ProtocolEndpoints.ArtifactResolutionProxyUrl={} - change to ProxyUrl", proxyUrl);
		this.proxyUrl = proxyUrl;
	}
}
