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

package swiss.trustbroker.oidc.tx;

import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
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

}
