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

package swiss.trustbroker.api.accessrequest.dto;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import swiss.trustbroker.api.saml.service.OutputService;

/**
 * HTTP request/response related inputs for access request.
 */
@Data
@Builder
@AllArgsConstructor(staticName = "of")
public class AccessRequestHttpData {

	private HttpServletRequest httpServletRequest;

	private HttpServletResponse httpServletResponse;

	/**
	 * Service for outputting SAML.
	 */
	private OutputService outputService;

	/**
	 * Return URL from request.
	 */
	private String returnUrl;

	public static AccessRequestHttpData of(HttpServletRequest httpServletRequest) {
		return AccessRequestHttpData.builder()
									.httpServletRequest(httpServletRequest)
									.build();
	}

}
