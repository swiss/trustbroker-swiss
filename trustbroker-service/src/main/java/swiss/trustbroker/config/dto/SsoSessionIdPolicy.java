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

import java.util.UUID;

/**
 * SSO session ID generation policy.
 *
 */
public enum SsoSessionIdPolicy {
	/**
	 * Generate SSO session ID for SSO and temporary session ID otherwise.
	 */
	ALWAYS,

	/**
	 * Generate SSO session ID in SSO case only.
	 */
	SSOONLY,

	/**
	 * Generate no SSO session ID.
	 */
	NONE;

	public static final String SSO_PREFIX = "sso-";

	public static final String TMP_PREFIX = "tmp-";

	public static String generateSsoId(boolean isSso, String ssoSessionIdPolicy) {
		if (ssoSessionIdPolicy == null) {
			return null;
		}
		return switch (SsoSessionIdPolicy.valueOf(ssoSessionIdPolicy.toUpperCase())) {
			case ALWAYS -> (isSso ? SSO_PREFIX : TMP_PREFIX) + UUID.randomUUID().toString();
			case SSOONLY -> (isSso ? SSO_PREFIX + UUID.randomUUID().toString() : null);
			default -> null;
		};
	}

	public static String generateTempSsoId() {
		return TMP_PREFIX + UUID.randomUUID().toString();
	}

	public static boolean isSsoSession(String ssoSessionId) {
		return ssoSessionId != null && ssoSessionId.startsWith(SSO_PREFIX);
	}

}
