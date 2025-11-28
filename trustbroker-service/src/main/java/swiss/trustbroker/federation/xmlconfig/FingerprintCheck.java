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

import java.util.function.BiPredicate;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

/**
 * SSO device fingerprint check.
 */
@Getter
public enum FingerprintCheck {

	/**
	 * Fingerprint must match completely.
	 */
	STRICT(false, FingerprintCheck::fullMatch),

	/**
	 * A partial match is OK. Ignore browser features that may vary if used within an iframe.
	 */

	LAX(false, FingerprintCheck::partialMatch),
	/**
	 * Mismatching fingerprint is accepted.
	 */

	OPTIONAL(true, FingerprintCheck::partialMatch);

	private static final String SEPARATOR = "\\.";

	private boolean allowMismatch;

	private BiPredicate<String, String> matchFunction;

	FingerprintCheck(boolean allowMismatch, BiPredicate<String, String> matchFunction) {
		this.allowMismatch = allowMismatch;
		this.matchFunction = matchFunction;
	}

	public boolean match(String incoming, String stored) {
		return matchFunction.test(incoming, stored);
	}

	private static boolean fullMatch(String incoming, String stored) {
		return StringUtils.isNotEmpty(incoming) && incoming.equals(stored);
	}

	private static boolean partialMatch(String incoming, String stored) {
		if (StringUtils.isEmpty(incoming) || StringUtils.isEmpty(stored)) {
			return false;
		}
		var incomingParts = incoming.split(SEPARATOR);
		var storedParts = stored.split(SEPARATOR);
		// structure must be the same
		if (incomingParts.length != storedParts.length) {
			return false;
		}
		int matchingParts = 0;
		for (int ii = 0; ii < incomingParts.length; ++ii) {
			if (incomingParts[ii].equals(storedParts[ii])) {
				++matchingParts;
			}
		}
		return matchingParts > 0;
	}
}
