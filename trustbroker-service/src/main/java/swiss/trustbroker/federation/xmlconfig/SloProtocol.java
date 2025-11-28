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

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Single logout (SLO) protocol.
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum SloProtocol {
	/**
	 * SAML2 LogoutResponse to an incoming LogoutRequest or notification via SAML2 LogoutRequest.
	 */
	SAML2(false),

	/**
	 * OIDC logout response to an incoming logout request or notification via OIDC logout.
	 *
	 * @see <a href="https://openid.net/specs/openid-connect-frontchannel-1_0.html">OpenID Connect Front-Channel Logout</a>
	 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect Back-Channel Logout</a>
	 */
	OIDC(false),

	/**
	 * Notification via HTTP GET request to the URL, which is used as-is regardless of the incoming protocol.
	 */
	HTTP(true);

	private boolean crossProtocol;

}
