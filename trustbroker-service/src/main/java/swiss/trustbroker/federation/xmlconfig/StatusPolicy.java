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

import org.apache.commons.lang3.EnumUtils;

/**
 * Policy for handling if the user returned by the CP is not found or not active in the IDM.
 *
 * @since 1.7.0
 */
public enum StatusPolicy {
	/**
	 * Only fetch active users from the IDM.
	 * This is the default.
	 */
	FETCH_ACTIVE_ONLY,
	/**
	 * Throw an exception, leading to the standard error page.
	 */
	BLOCK,
	/**
	 * Send a SAML responder state UnknownPrincipal.
	 *
	 * @see org.opensaml.saml.saml2.core.StatusCode#UNKNOWN_PRINCIPAL
	 */
	BLOCK_RESPONDER,
	/**
	 * Display 'unknownuser' error page with text and instructions and a button continue to application.
	 */
	BLOCK_EXCEPTION,
	/**
	 * Display 'unknownuser' error page with text and instructions.
	 */
	BLOCK_UNKNOWN_USER,
	/**
	 * Proceed anyway.
	 */
	ALLOW_UNKNOWN_USER;

	public static StatusPolicy of(String name) {
		return EnumUtils.getEnum(StatusPolicy.class, name);
	}
}
