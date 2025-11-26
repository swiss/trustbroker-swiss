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

package swiss.trustbroker.util;

import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsUtils;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.dto.CorsPolicies;

// CORS spec:  https://www.w3.org/TR/2020/SPSD-cors-20200602/
// Fetch spec: https://www.w3.org/TR/fetch-metadata/
// Agent spec: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode
// Keycloak: https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/services/resources/Cors.java
// Keycloak heavily makes use of core checks (grep for Cors.add in the keycloak source).
@Slf4j
public class CorsSupport {

	public static final String ALL_ORIGINS = "*";

	public static final Set<String> DEFAULT_ORIGINS = Set.of(ALL_ORIGINS);

	public static final String DEFAULT_METHODS = "GET, HEAD, OPTIONS"; // sufficient for /userinfo, configuration

	public static final String DEFAULT_HEADERS =
			"Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization";

	public static final String DEFAULT_MAXAGE = "3600"; // 1 hour in seconds

	private CorsSupport() {}

	// NOTE: This also works for /userinfo but trustbroker-oidcclient not propagate it
	public static void setAccessControlHeaders(HttpServletRequest request, HttpServletResponse response,
			CorsPolicies corsPolicies, Set<String> ownOrigins) {
		// preserve already set header
		var originSet = response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
		if (originSet != null) {
			log.debug("Preserving {}={} and all other AC headers", HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, originSet);
			return;
		}
		var allowedOrigins = getAllowedOrigins(corsPolicies, ownOrigins);
		var origin = getAllowedOrigin(request, allowedOrigins);
		if (origin == null) {
			return;
		}

		// trusted OIDC client (checked by caller)
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);

		// we allow tokens to be sent to all endpoints (Keycloak is a bit more picky)
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

		// if preflight not handled by spring-security
		var isPreflight = CorsUtils.isPreFlightRequest(request);
		if (isPreflight) {
			response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
					corsPolicies == null ? DEFAULT_HEADERS : String.join(", ", corsPolicies.getAllowedHeaders()));
			response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
					corsPolicies == null ? DEFAULT_METHODS : String.join(", ", corsPolicies.getAllowedMethods()));
			response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE, DEFAULT_MAXAGE);
		}
	}

	private static Set<String> getAllowedOrigins(CorsPolicies corsPolicies, Set<String> ownOrigins) {
		if (corsPolicies == null) {
			return DEFAULT_ORIGINS;
		}
		Set<String> result = null;
		if (CollectionUtils.isNotEmpty(ownOrigins)) {
			result = new HashSet<>(ownOrigins);
		}
		if (CollectionUtils.isNotEmpty(corsPolicies.getAllowedOrigins())) {
			if (result == null) {
				result = new HashSet<>(corsPolicies.getAllowedOrigins());
			}
			else {
				result.addAll(corsPolicies.getAllowedOrigins());
			}
		}
		return result;
	}

	/**
	 *
	 * @param request received from HTTP client
	 * @param allowedOrigins may be null
	 * @return request's origin header if in allowedOrigins (truncated to scheme, host, port)
	 */
	public static String getAllowedOrigin(HttpServletRequest request, Set<String> allowedOrigins) {
		// agent needs to send its address
		var origin = WebUtil.getOriginOrReferer(request);
		if (origin == null) {
			log.debug("Agent did not send HTTP {} => skipping CORS headers, browser might complain", HttpHeaders.ORIGIN);
			return null;
		}
		// validate / convert referrer fallback
		var validatedOrigin = WebUtil.getValidOrigin(origin);
		if (validatedOrigin == null) {
			log.error("Agent sent {}={} - not a valid origin", HttpHeaders.ORIGIN, origin);
			return null;
		}
		if (validatedOrigin.equals(origin)) {
			log.debug("Received valid origin={}", origin);
		}
		else {
			// we fall back to referrer if there is no origin, which contains a trailing slash (and/or path), so this is expected
			log.debug("Extracted result={} from origin={} (or referer)", validatedOrigin, origin);
		}

		// check against explicitly configured origins (global defaults or later per Oidc Client if needed)
		if (allowedOrigins != null && !allowedOrigins.contains(ALL_ORIGINS) &&
				!WebUtil.isAllowedOriginOrReferer(allowedOrigins, origin, validatedOrigin)) {
			log.warn("Agent sent {}={} not accepted by allowedOrigins={}, rely on global defaults, browser might block",
					HttpHeaders.ORIGIN, origin, allowedOrigins);
			return null;
		}

		log.debug("Returning url={} for accepted {}={} matching allowedOrigins={}",
				validatedOrigin, HttpHeaders.ORIGIN, origin, allowedOrigins);
		return validatedOrigin;
	}

}
