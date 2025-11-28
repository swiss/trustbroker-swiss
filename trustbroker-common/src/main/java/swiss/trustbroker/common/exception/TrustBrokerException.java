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

import lombok.Getter;

@Getter
public abstract class TrustBrokerException extends RuntimeException {

	// improve debuggability by exposing internal message when enabled via logging facility
	@SuppressWarnings("java:S1165")
	private static boolean debug = false;

	private final ErrorCode errorCode;

	private final ErrorMarker errorMarker;

	private final String internalMessage;

	protected TrustBrokerException(String message, ErrorCode errorCode, ErrorMarker errorMarker,
			String internalMessage, Throwable exception) {
		super(debug ? message + ": " + internalMessage : message, exception);
		this.errorCode = errorCode;
		this.errorMarker = defaultErrorMarker(errorMarker);
		this.internalMessage = getMarkerMessage(this.errorMarker, internalMessage);
	}

	public static String getMarkerMessage(ErrorMarker errorMarker, String message) {
		return errorMarker == ErrorMarker.DEFAULT ? message : "xtbCode=" + errorMarker + " " + message;
	}

	private static ErrorMarker defaultErrorMarker(ErrorMarker errorMarker) {
		return errorMarker != null ? errorMarker : ErrorMarker.DEFAULT;
	}

	// Improve error handling in unit tests - not thread safe, do not use in production code!
	public static void enableDebugging() {
		debug = true;
	}

}
