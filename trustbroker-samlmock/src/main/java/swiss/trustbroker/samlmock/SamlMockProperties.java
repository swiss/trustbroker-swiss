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

package swiss.trustbroker.samlmock;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;

@Configuration
@ConfigurationProperties(prefix = "trustbroker.samlmock")
@Data
public class SamlMockProperties {

	private String spSignerKeystore;

	private String spSignerPassword;

	private String spSignerAlias;

	private String idpSignerKeystore;

	private String idpSignerPassword;

	private String idpSignerAlias;

	private String mockDataDirectory;

	private String keystoreDirectory;

	private String issuer;

	private String assertionConsumerServiceUrl;

	private String idpServiceUrl;

	private String samlPostTargetUrl;

	private Map<String, String> samlPostTargetUrlMap;

	private boolean keepSampleUrlsforCpInitiated;

	private String audienceRestriction;

	private String consumerUrl;

	private String metadataUrl;

	private String arpUrl;

	private String tbApplicationUrl;

	private String testRpIssuer;

	private String testCpIssuer;

	private String skinnyAssertionNamespaces = OpenSamlUtil.SKINNY_ALL;

	private String dataEncryptionAlgorithm;

	private String keyEncryptionAlgorithm;

	private String keyPlacement;

	private boolean emitSki = false;

	private String encryptionKeystore;

	private String encryptionPassword;

	private String encryptionAlias;

	private String artifactResolutionServiceUrl;

	private String artifactResolutionIssuer;

	private boolean artifactResolutionIssuerIsRp;

	private boolean useOriginalAcr = false;

	private boolean signAuthnRequest = false;

	private List<String> validReturnUrls = new ArrayList<>();

	private boolean cacheMockFiles = false;

	public String getArtifactResolutionIssuer() {
		if (artifactResolutionIssuer != null) {
			return artifactResolutionIssuer;
		}
		return issuer;
	}
}
