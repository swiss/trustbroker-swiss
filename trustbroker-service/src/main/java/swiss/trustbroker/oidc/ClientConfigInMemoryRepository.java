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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

@Component
@RequiredArgsConstructor
@Slf4j
public class ClientConfigInMemoryRepository implements RegisteredClientRepository {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties properties;

	@Override
	public void save(RegisteredClient registeredClient) {
		// spring-sec registered clients are not persisted in DB so they do not need secret obfuscation
		log.debug("RegisteredClient not saved/updated");
	}

	@Override
	public RegisteredClient findById(String id) {
		return findByClientId(id);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		RegisteredClient registeredClient = null;
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		if (oidcClient.isPresent()) {
			registeredClient = oidcClient.get().getRegisteredClient();
			if (registeredClient == null) {
				log.debug("Found clientId={} in definitions, creating RegisteredClient", clientId);
				registeredClient = OidcConfigurationUtil.createRegisteredClient(oidcClient.get(),
						properties.getSecurity().getTokenLifetimeSec(), properties.getOidc().getCodeLifetimeSec());
			}
		}
		else {
			log.warn("Unknown clientId={} missing in SetupRP definitions (check config and miss-configured/buggy OIDC adapters)",
					clientId);
		}
		return registeredClient;
	}

}
