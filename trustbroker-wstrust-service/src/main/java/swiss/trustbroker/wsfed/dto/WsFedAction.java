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

package swiss.trustbroker.wsfed.dto;

import java.util.Optional;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * WS-Fed actions.
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum WsFedAction {

	ACTION_SIGN_IN("wsignin1.0", true),

	ACTION_SIGN_OUT("wsignout1.0", false),

	ACTION_SIGN_OUT_LEGACY("wsignoutcleanup1.0", false);

	private final String action;

	private final boolean signIn;

	public boolean isSignOut() {
		return !signIn;
	}

	public static Optional<WsFedAction> of(String action) {
		for (var value : values()) {
			if (value.action.equals(action)) {
				return Optional.of(value);
			}
		}
		return Optional.empty();
	}
}
