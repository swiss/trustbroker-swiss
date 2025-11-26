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

package swiss.trustbroker.saml.util;

import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.saml.dto.ResponseData;

public class SamlValidationUtil {

	private SamlValidationUtil() {
	}

	public static void validateRelayState(ResponseData<?> responseData) {
		var relayState = responseData.getRelayState();
		if (StringUtils.isEmpty(relayState)) {
			var response = responseData.getResponse();
			throw new RequestDeniedException(String.format("Relay state '%s' of response id='%s' is null/empty",
					relayState, response != null ? response.getID() : null));
		}
	}

	public static void validateResponse(ResponseData<?> responseData) {
		if (responseData.getResponse() == null) {
			throw new RequestDeniedException(String.format("Missing response for relayState='%s'", responseData.getRelayState()));
		}
	}

	public static void validateProfileRequestId(String profileRequestId) {
		if (StringUtils.isEmpty(profileRequestId)) {
			throw new RequestDeniedException(String.format("ID of profile request is null/empty: '%s", profileRequestId));
		}
	}
}
