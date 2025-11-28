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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.net.URI;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;

class OidcHttpClientProviderTest {

	private static final String PROXY_URL = "http://localhost:3128";

	private TrustBrokerProperties trustBrokerProperties;

	private OidcHttpClientProvider provider;

	@BeforeEach
	void setUp() {
		trustBrokerProperties = new TrustBrokerProperties();
		provider = new OidcHttpClientProvider(trustBrokerProperties);
	}

	@Test
	void createHttpClient() {
		var client = OidcClient.builder().build();
		var certificates = Certificates.builder().build();
		var targetUri = URI.create(PROXY_URL);
		var httpClient = provider.createHttpClient(client, certificates, targetUri);
		assertThat(httpClient, is(not(nullValue())));
	}

	@ParameterizedTest
	@MethodSource
	void getProxyUri(ProtocolEndpoints protocolEndpoints, NetworkConfig network, URI expected) {
		trustBrokerProperties.setNetwork(network);
		assertThat(provider.getProxyUri(protocolEndpoints), is(expected));
	}

	static Object[][] getProxyUri() {
		return new Object[][] {
				{ null, null, null },
				{
					new ProtocolEndpoints(),
					new NetworkConfig(),
					null
				},
				{
					null,
					NetworkConfig.builder().proxyUrl(PROXY_URL).build(),
					URI.create(PROXY_URL)
				},
				{
					new ProtocolEndpoints(),
					NetworkConfig.builder().proxyUrl(PROXY_URL).build(),
					URI.create(PROXY_URL)
				},
				// override default with blank:
				{
						ProtocolEndpoints.builder().proxyUrl("").build(),
						NetworkConfig.builder().proxyUrl(PROXY_URL).build(),
						null
				},
				// override default:
				{
					ProtocolEndpoints.builder().proxyUrl(PROXY_URL).build(),
					NetworkConfig.builder().proxyUrl("https://localhost").build(),
					URI.create(PROXY_URL)
				},
		};
	}
}
