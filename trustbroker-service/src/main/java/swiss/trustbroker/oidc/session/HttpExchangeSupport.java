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

package swiss.trustbroker.oidc.session;

import java.util.Arrays;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.ApiSupport;

/**
 * Log-able web input (where we do not expected any StringUtil.clean modified data) and other helpers.
 */
@Slf4j
@AllArgsConstructor
@Data
public class HttpExchangeSupport {

	private static final ThreadLocal<HttpExchangeSupport> runningHttpExchange = new ThreadLocal<>();

	private final HttpServletRequest request;

	private final HttpServletResponse response;

	// per default, we do all the OIDC session checking only on our well known sub-paths
	private boolean oidcRequest;

	// detected in HTTP request
	private String oidcClientId;

	// load from session DB
	private TomcatSession oidcSession;

	// currently only used to retain a handle to the SSO across the OIDC logout for the later handling
	private StateData ssoState;

	// prevent multiple logs
	private boolean authContextHandled;

	public static HttpExchangeSupport begin(HttpServletRequest request, HttpServletResponse response) {
		var exchange = new HttpExchangeSupport(request, response, false, null, null, null, false);
		runningHttpExchange.set(exchange);
		return runningHttpExchange.get();
	}

	public static void end() {
		runningHttpExchange.remove();
	}

	// OIDC/spring-sec integration only, not so nice hack just tio habe HTTP data in scrips
	public static HttpServletRequest getRunningHttpRequest() {
		var entry = runningHttpExchange.get();
		if (entry != null) {
			return entry.request;
		}
		return null;
	}

	public static HttpServletResponse getRunningHttpResponse() {
		var entry = runningHttpExchange.get();
		if (entry != null) {
			return entry.response;
		}
		return null;
	}

	public static TomcatSession getRunningHttpSession() {
		var entry = runningHttpExchange.get();
		if (entry != null) {
			return entry.oidcSession;
		}
		return null;
	}

	public static StateData getRunningSsoState() {
		var entry = runningHttpExchange.get();
		if (entry != null) {
			return entry.ssoState;
		}
		return null;
	}

	public static HttpExchangeSupport getRunningHttpExchange() {
		return runningHttpExchange.get();
	}

	public static boolean isRunningOidcExchange() {
		var entry = runningHttpExchange.get();
		if (entry != null) {
			return entry.oidcRequest;
		}
		return false;
	}

	public static void setRunningOidcClientId(String clientId) {
		var entry = getRunningHttpExchange();
		entry.oidcRequest = true;
		entry.oidcClientId = clientId;
	}

	public static String getRunningOidcClientId() {
		var entry = getRunningHttpExchange();
		return entry != null ? entry.oidcClientId : null;
	}

	public static boolean isRunningUserInfoExchange() {
		var request = getRunningHttpRequest();
		return request != null && ApiSupport.isUserInfoRequest(request.getRequestURI());
	}

	// The container session attached by TomcatSessionManager based on BSESSION cookie OR BESESSION_CLIENT_ID cookie
	// depending on if we could somehow identify the client.
	public static HttpSession getSession(HttpServletRequest request) {
		if (request == null) {
			request = getRunningHttpRequest();
		}
		if (request != null) {
			return request.getSession(false);
		}
		return null;
	}

	public static String getCookiesAsString(HttpServletRequest request) {
		final var cookies = new StringBuilder();
		if (request != null) {
			var cookieObjs = request.getCookies();
			if (cookieObjs != null) {
				Arrays.stream(cookieObjs).forEach(c -> cookies.append(c.getName()).append(" "));
			}
		}
		return cookies.toString();
	}

	public static boolean isRunningLogoutRequest(HttpServletRequest request) {
		request = request != null ? request : getRunningHttpRequest();
		return request != null && ApiSupport.isLogoutRequest(request.getRequestURI());
	}

}
