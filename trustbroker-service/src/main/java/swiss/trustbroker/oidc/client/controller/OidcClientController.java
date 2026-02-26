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

package swiss.trustbroker.oidc.client.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.oidc.client.service.OidcClientService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * OIDC client side controller accepting responses from an OIDC CP.
 */
@Controller
@AllArgsConstructor
@Slf4j
public class OidcClientController {

	private final OidcClientService oidcClientService;

	@SuppressWarnings("java:S3752") // GET and POST are OK here depending on ResponseMode
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST },
			path ={ ApiSupport.OIDC_RESPONSE_URL, ApiSupport.OIDC_RESPONSE_URL + "/{realm}"})
	public String authorizationCodeResponseQuery(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			@PathVariable(name = "realm", required = false) String realm,
			@RequestParam(name = "state", required = false) String state,
			@RequestParam(name = "code", required = false) String code,
			@RequestParam(name = "error", required = false) String error,
			@RequestParam(name = "error_description", required = false) String errorDescription,
			@RequestParam(name = "error_uri", required = false) String errorUri) {
		log.info("Received authorization code response with method={} for realm={} state={} code=*** error={}",
				httpServletRequest.getMethod(), realm, state, error);
		if (state == null) {
			throw new RequestDeniedException(
					String.format("Missing state in OIDC authorization code response for realm=%s", realm));
		}
		if (error != null) {
			return oidcClientService.handleFailedCpResponse(httpServletRequest, httpServletResponse, state,
					error, errorDescription, errorUri);
		}
		if (code == null) {
			throw new RequestDeniedException(
					String.format("Missing code in OIDC authorization code response for realm=%s state=%s", realm, state));
		}
		var redirectUrl = oidcClientService.handleSuccessCpResponse(httpServletRequest, httpServletResponse, realm, code, state);
		return WebSupport.getViewRedirectResponse(redirectUrl);
	}

}
