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

package swiss.trustbroker.oidc;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;
import swiss.trustbroker.util.CertificateUtil;

/**
 * Provides HTTP clients configured for an OidcClient.
 */
@Service
@AllArgsConstructor
public class OidcHttpClientProvider {

	private final TrustBrokerProperties trustBrokerProperties;

	public HttpClient createHttpClient(OidcClient client, Certificates certificates, URI targetUri) {
		var proxyUri = getProxyUri(client.getProtocolEndpoints());
		var oidc = trustBrokerProperties.getOidc();
		var truststore = oidc != null ? oidc.getTruststore() : null;
		if (certificates.getBackendTruststore() != null) {
			truststore = CertificateUtil.toKeystoreProperties(certificates.getBackendTruststore());
		}
		var keystore = oidc != null ? oidc.getKeystore() : null;
		if (certificates.getBackendKeystore() != null) {
			keystore = CertificateUtil.toKeystoreProperties(certificates.getBackendKeystore());
		}
		var connectTimeout = trustBrokerProperties.getNetwork() != null ?
				Duration.ofSeconds(trustBrokerProperties.getNetwork().getBackendConnectTimeoutSec()) : null;
		return HttpUtil.createHttpClient(targetUri.getScheme(), truststore, keystore,
				trustBrokerProperties.getKeystoreBasePath(), proxyUri, null, connectTimeout);
	}

	URI getProxyUri(ProtocolEndpoints protocolEndpoints) {
		var proxyUrl = protocolEndpoints != null ? protocolEndpoints.getProxyUrl() : null;
		if (proxyUrl == null && trustBrokerProperties.getNetwork() != null) {
			proxyUrl = trustBrokerProperties.getNetwork().getProxyUrl();
		}
		if (StringUtils.isEmpty(proxyUrl)) {
			return null;
		}
		return WebUtil.getValidatedUri(proxyUrl);
	}
}
