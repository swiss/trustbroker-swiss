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
 * Operation mode for single (global) logout.
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum SloMode {

	/**
	 * Configuration for response to the RP initiating the logout.
	 */
	RESPONSE(true, false, true),

	/**
	 * Configuration for notification to an RP participating in the SSO session that is being logged out.
	 * Fire and forget mode: do not wait for response of notification.
	 */
	NOTIFY_TRY(false, true, false),

	/**
	 * Configuration for notification to an RP participating in the SSO session that is being logged out.
	 * Wait for response of notification, fail if it times out.
	 */
	NOTIFY_FAIL(false, true, true),

	/**
	 * Configuration for both RESPONSE and NOTIFY_TRY
	 */
	RESPONSE_NOTIFY_TRY(true, true, false),

	/**
	 * Configuration for both RESPONSE and NOTIFY_FAIL
	 */
	RESPONSE_NOTIFY_FAIL(true, true, true);

	private boolean response;

	private boolean notification;

	private boolean waitForResponse;

	public boolean isNotifyTry() {
		return notification && !waitForResponse;
	}

	public boolean isNotifyFail() {
		return notification && waitForResponse;
	}
}
