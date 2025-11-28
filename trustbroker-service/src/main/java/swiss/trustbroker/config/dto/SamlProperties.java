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
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameIDType;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * SAML protocol configuration.
 */
@Configuration
@ConfigurationProperties(prefix = "trustbroker.config.saml")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SamlProperties {

	/**
	 * XTB SAML consumer URL, included in the metadata.
	 * <br/>
	 * Note: Currently, the path that is requested on XTB needs to be one of the default paths:
	 * <ul>
	 *     <li><code>/api/v1/saml</code></li>
	 *     <li><code>/adfs/ls</code></li>
	 *     <li><code>/adfs/ls/</code></li>
	 *     <li><code>/trustbroker/adfs/ls/</code></li> (deprecated)
	 * </ul>
	 */
	private String consumerUrl;

	/**
	 * Flow control namespace mappings.
	 */
	private List<SamlNamespace> flowPolicyNamespaces;

	/**
	 * SAML Artifact Resolution configuration.
	 */
	private ArtifactResolution artifactResolution;

	/**
	 * List of exposed SAML protocols.
	 * <br/>
	 * Default:
	 * <ul>
	 *     <li>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST</li>
	 *     <li>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect</li>
	 *     <li>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact</li>
	 *     <li>urn:oasis:names:tc:SAML:2.0:bindings:SOAP (since 1.12.0 - only supported for LogoutRequest)</li>
	 * </ul>
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private List<String> bindings = List.of(
			SAMLConstants.SAML2_POST_BINDING_URI,
			SAMLConstants.SAML2_REDIRECT_BINDING_URI,
			SAMLConstants.SAML2_ARTIFACT_BINDING_URI,
			SAMLConstants.SAML2_SOAP11_BINDING_URI);

	/**
	 * SAML SP-side metadata can be hidden setting this feature flag to false.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean spMetadataEnabled = true;

	/**
	 * RP-side supported name formats
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private List<String> spNameFormats = List.of(NameIDType.UNSPECIFIED);

	/**
	 * SAML CP-side logout support could be enabled but CPs need to be added as RPs.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean spLogoutMetadataEnabled = false;

	/**
	 * SAML CP-side metadata can be hidden setting this feature flag to false.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean idpMetadataEnabled = true;

	/**
	 * CP-side supported name formats
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private List<String> idpNameFormats = List.of(NameIDType.UNSPECIFIED);

	/**
	 * SAML RP-side logout support can be hidden setting this feature flag to false.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private boolean idpLogoutMetadataEnabled = true;

	/**
	 * Drop all CP attributes if there is no AttributeSelection defined
	 *
	 * @since 1.10.0
	 */
	@Builder.Default
	private boolean dropAttrSelectionIfNoFilter = false;
}
