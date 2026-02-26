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

package swiss.trustbroker.oidc.tx;

import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.util.ApiSupport;

@Slf4j
public class OidcTxUtil {

	private static final Pattern CLIENT_ID_PATTERN = Pattern.compile(
			ApiSupport.SPRING_OAUTH2_AUTHORIZE_CTXPATH
					+ ".*[?&]" + OidcClientMetadataClaimNames.CLIENT_ID + "=(.*?)&");

	private OidcTxUtil() {
	}

	static String checkAndAddRealmContextPath(String location,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		var matcher = CLIENT_ID_PATTERN.matcher(location);
		if (matcher.find()) {
			var clientId = matcher.group(1);
			var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
			var realm = client.map(OidcClient::getRealm).orElse(null);
			if (realm != null) {
				var mappedLocation = location.replace(ApiSupport.SPRING_OAUTH2_AUTHORIZE_CTXPATH,
						ApiSupport.KEYCLOAK_REALMS + "/" + realm +
								ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.KEYCLOAK_AUTH);
				log.debug("Redirect URL location={} mapped to mappedLocation={}", location, mappedLocation);
				location = mappedLocation;
			}
		}
		return location;
	}

	static String getKeycloakRealm(String path) {
		if (path != null && path.startsWith(ApiSupport.KEYCLOAK_REALMS)) {
			var pathElements = path.split("/");
			return pathElements.length >= 3 ? pathElements[2] : null;
		}
		return null;
	}

	static boolean validateKeycloakRealm(String path, OidcClient oidcClient, String origin) {
		var realmName = getKeycloakRealm(path);
		if (realmName != null && !realmName.equals(oidcClient.getRealm())) {
			log.warn("oidcClientId={} with realm={} origin=\"{}\" called unexpected path=\"{}\"",
					oidcClient.getId(), oidcClient.getRealm(), StringUtil.clean(origin), StringUtil.clean(path));
			return false;
		}
		return true;
	}
}
