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

package swiss.trustbroker.oidc.sso.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.util.ApiSupport;

@Controller
@Slf4j
public class OidcSessionController {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	public OidcSessionController(RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		this.relyingPartyDefinitions = relyingPartyDefinitions;
		this.trustBrokerProperties = trustBrokerProperties;
	}

	@GetMapping(value = ApiSupport.OIDC_CHECK_3PCOOKIE, produces = "text/html")
	public String getStep1Page(HttpServletRequest request, HttpServletResponse response) {
		String url = request.getRequestURL().toString();
		log.debug("Incoming step1.html request with url={}", url);
		return "/3p-cookies-step1.html";
	}

	@GetMapping(value = "/login-status-iframe", produces = "text/html")
	public String getLoginStatusPage(HttpServletRequest request, HttpServletResponse response) {
		log.debug("Incoming login-status-iframe request with url={}", request.getRequestURL());

		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			var clientId = session.getOidcClientId();
			var cookieValue = "/realms/" + OidcUtil.getRealmFromRequestUrl(request.getRequestURI());
			var sessionCookie = OidcSessionSupport.createOidcSsoSessionCookie(clientId, cookieValue, request,
					relyingPartyDefinitions, trustBrokerProperties);
			response.addCookie(sessionCookie);
			log.debug("Set cookie on login-status-iframe response with name={} value={}", sessionCookie.getName(), cookieValue);
		}

		return "/login-status-iframe.html";
	}

	Cookie getCookieByName(HttpServletRequest request, String cookieName) {
		for (var cookie : request.getCookies()) {
			var name = cookie.getName();
			if (name.equals(cookieName)) {
				return cookie;
			}
		}
		return null;
	}

	@GetMapping(value = "/login-status-iframe-init")
	public ResponseEntity<Object> initIFramePage(HttpServletRequest request, HttpServletResponse response) {
		String clientId = request.getParameter(OidcUtil.OIDC_CLIENT_ID);
		if (log.isDebugEnabled()) {
			log.debug("client_id={}", StringUtil.clean(clientId));
		}

		String origin = request.getParameter("origin");
		if (log.isDebugEnabled()) {
			log.debug("origin={}", StringUtil.clean(origin));
		}

		return ResponseEntity.status(200).build();
	}

}
