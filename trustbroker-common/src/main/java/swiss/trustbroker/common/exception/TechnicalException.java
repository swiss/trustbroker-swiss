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

package swiss.trustbroker.common.exception;

/**
 * Use this exception when we have failures because of configuration, infrastructure or internal code problems.
 * Client will see: Service rejected with HTTP/503 (DB, IDM problem or misconfiguration)
 */
public class TechnicalException extends TrustBrokerException {

	public TechnicalException(String internalMessage) {
		this(null, null, internalMessage, null);
	}

	public TechnicalException(String internalMessage, Throwable exception) {
		this(null, null, internalMessage, exception);
	}

	public TechnicalException(ErrorMarker errorMarker, String internalMessage, Throwable exception) {
		this(null, errorMarker, internalMessage, exception);
	}

	public TechnicalException(ErrorCode errorCode, ErrorMarker errorMarker, String internalMessage, Throwable exception) {
		super("Service rejected", defaultErrorCode(errorCode), errorMarker, internalMessage, exception);
	}

	private static ErrorCode defaultErrorCode(ErrorCode errorCode) {
		return errorCode != null ? errorCode : StandardErrorCode.REQUEST_REJECTED;
	}
}
