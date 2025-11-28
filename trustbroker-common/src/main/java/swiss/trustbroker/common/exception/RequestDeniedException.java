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
 * Use this exception when we have failures because of input data from network, and we blame the client.
 * Client will see: Access denied  with HTTP/403
 */
public class RequestDeniedException extends TrustBrokerException {

	public RequestDeniedException(String internalMessage) {
		this(null, null, internalMessage, null);
	}

	public RequestDeniedException(ErrorCode errorCode, String internalMessage) {
		this(errorCode, null, internalMessage, null);
	}

	public RequestDeniedException(String internalMessage, Throwable exception) {
		this(null, null, internalMessage, exception);
	}

	public RequestDeniedException(ErrorCode errorCode, ErrorMarker errorMarker, String internalMessage, Throwable exception) {
		super("Access denied", defaultErrorCode(errorCode), errorMarker, internalMessage, exception);
	}

	private static ErrorCode defaultErrorCode(ErrorCode errorCode) {
		return errorCode != null ? errorCode : StandardErrorCode.REQUEST_DENIED;
	}

}
