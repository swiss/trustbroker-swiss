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

import java.util.HashMap;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.script.service.ScriptService;

@Slf4j
public class OidcUserInfoUtil {

	OidcUserInfoUtil() {}

	static Map<String, Object> filterUnwantedClaims(final Map<String, Object> claims,
			RelyingPartyDefinitions relyingPartyDefinitions,
			ScriptService scriptService, TrustBrokerProperties trustBrokerProperties) {
		var ret = new HashMap<>(claims);
		var clientId = OidcUtil.getClientIdFromTokenClaims(claims);
		if (clientId != null) {
			try {
				// drop configured claims
				var removeClaims = trustBrokerProperties.getOidc().getRemoveUserInfoClaims();
				if (removeClaims != null) {
					removeClaims.forEach(ret::remove);
				}
				// drop claims per RP via script support
				var config = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, trustBrokerProperties, true);
				if (config != null) {
					var ctx = CpResponse.builder()
										.oidcClientId(clientId)
										.rpIssuer(config.getId())
										.claims(ret) // copy-on-write
										.build();
					scriptService.processRpOnUserInfo(ctx, config.getId(), null);
				}
			}
			catch (TechnicalException ex) {
				log.error("Skip filtering /userinfo claims due to exception={}", ex.getInternalMessage(), ex);
			}
		}
		return ret;
	}

}
