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

package swiss.trustbroker.wsfed.controller;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;
import swiss.trustbroker.wsfed.service.WsFedService;

@Controller
@AllArgsConstructor
@Slf4j
@ConditionalOnProperty(value = "trustbroker.config.wsfed.enabled", havingValue = "true")
public class WsFedController {

	private final WsFedService wsFedService;

	private final List<OutputService> outputServices;

	/**
	 * Web traffic dispatcher handling WS-Fed requests including SAML Redirect and UI interaction
	 *
	 * @param request  is the web input according to servlet spec
	 * @param response is the web response according to servlet spec
	 * @return redirect routing or null when no redirect is needed.
	 */
	@GetMapping(path = { ApiSupport.WSFED_API })
	public String handleIncomingGetMessages(HttpServletRequest request, HttpServletResponse response) {
		if (!wsFedService.isWsFed(request)) {
			throw new RequestDeniedException(String.format("Expected WS-Fed request on path=%s", ApiSupport.WSFED_API));
		}
		var url = wsFedService.processWsFedRequest(request, response, outputServices);
		return WebSupport.getViewRedirectResponse(url);
	}

}
