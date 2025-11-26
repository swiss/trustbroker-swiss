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

package swiss.trustbroker.wstrust.service;

import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

public class RequestLocalContextHolder {

	private static final ThreadLocal<SoapMessageHeader> requestContext = new ThreadLocal<>();

	private RequestLocalContextHolder() {
	}

	public static void setRequestContext(SoapMessageHeader requestHeader) {
		requestContext.set(requestHeader);
	}

	public static SoapMessageHeader getRequestContext() {
		return requestContext.get();
	}

	public static void destroyRequestContext() {
		requestContext.remove();
	}

}
