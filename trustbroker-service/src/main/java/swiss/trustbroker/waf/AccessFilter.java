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

package swiss.trustbroker.waf;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Filter that responds with a 404 for URLs that we do not want to expose the Angular UI
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
@Slf4j
public class AccessFilter implements Filter {

	private final String allAllowedPathsRegex;

	private final Pattern allAllowedPaths;

	private final String internalAllowedPathsRegex;

	private final Pattern internalAllowedPaths;

	private final String frontendApiPathsRegex;

	private final Pattern frontendApiPaths;

	private final String externalApiPathsRegex;

	private final Pattern externalApiPaths;

	private final TrustBrokerProperties trustBrokerProperties;

	public AccessFilter(TrustBrokerProperties trustBrokerProperties) {
		this.trustBrokerProperties = trustBrokerProperties;
		allAllowedPathsRegex = allAllowedPathsRegex(trustBrokerProperties);
		allAllowedPaths = Pattern.compile(allAllowedPathsRegex);
		internalAllowedPathsRegex = getInternalAllowedPathsRegex();
		internalAllowedPaths = Pattern.compile(internalAllowedPathsRegex);
		frontendApiPathsRegex = getFrontendApiPathsRegex();
		frontendApiPaths = Pattern.compile(frontendApiPathsRegex);
		externalApiPathsRegex = getExternalApiPathsRegex();
		externalApiPaths = Pattern.compile(externalApiPathsRegex);
	}

	// all request paths that are allowed by this filter
	private static String allAllowedPathsRegex(TrustBrokerProperties trustBrokerProperties) {
		var perimeterPaths = WebSupport.getOwnPerimeterPaths(trustBrokerProperties);
		var perimeterPathsRegex = perimeterPaths
				.stream()
				.map(Pattern::quote) // escape regex characters
				.collect(Collectors.joining("|"));
		return "^("
				// SPA - see app-routing-module and AppController code
				+ "/app|/app/.*"
				// APIs (/adfs/ls included below)
				+ "|/api/v1/.*"
				// configured endpoints:
				+ "|" + perimeterPathsRegex
				// default SAML endpoints
				+ "|/adfs/.*|/FederationMetadata/.*|/federationmetadata/.*"
				// assets referenced by UI (some of which are unfortunately in the context root)
				+ "|/assets/.*|/js/.*|/[^/]*.(js|css|woff2?|ttf|eot|svg)"
				+ "|/index.html"
				+ "|/favicon.ico"
				+ "|/robots.txt"
				// OIDC services (spring-authorization-server and Keycloak compatibility)
				+ "|/oauth2/.*|/login/.*|/login|/logout|/logout/.*|/realms/.*|/saml2/.*|/userinfo|/.well-known/openid-configuration"
				+ ")$";
	}

	// internal only paths - currently static (but sub-path details depend on Spring config)
	private static String getInternalAllowedPathsRegex() {
		return "^("
				+ "/actuator/health|/actuator/health/liveness|/actuator/health/readiness|/actuator/info"
				+ "|" + ApiSupport.RECONFIG_URL
				+ "|" + ApiSupport.CONFIG_STATUS_API
				+ "|" + ApiSupport.CONFIG_SCHEMAS_API + "/.*"
				+ ")$";
	}

	// APIs used by the frontend
	private static String getFrontendApiPathsRegex() {
		return "^("
				+ "|" + ApiSupport.WEB_RESOURCE_PATH + "/.*"
				+ "|" + ApiSupport.CONFIG_FRONTEND_API
				+ "|" + ApiSupport.ACCESS_REQUEST_URL + "/.*"
				+ "|" + ApiSupport.ANNOUNCEMENTS_URL + "/.*"
				+ "|" + ApiSupport.HRD_URL + "/.*"
				+ "|" + ApiSupport.SSO_URL + "/.*"
				+ ")$";
	}

	// externally accessible APIs within the frontend API paths
	private static String getExternalApiPathsRegex() {
		return "^("
				+ "|" + ApiSupport.ACCESS_REQUEST_TRIGGER_URL
				+ "|" + ApiSupport.ACCESS_REQUEST_COMPLETE_URL + "/.*"
				+ ")$";
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;
		var path = WebUtil.urlDecodeValue(httpRequest.getRequestURI());

		// firewall
		if (internalAllowedPaths.matcher(path).matches()) {
			if (WebSupport.isClientOnIntranet(httpRequest, trustBrokerProperties.getNetwork())) {
				processRequest(path, httpRequest, httpResponse, chain);
			}
			else {
				blockAndLogRequest(httpRequest, httpResponse, Level.DEBUG, "Internal path called from Internet");
			}
		}
		else if (allAllowedPaths.matcher(path).matches()) {
			processRequest(path, httpRequest, httpResponse, chain);
		}
		else {
			blockAndLogRequest(httpRequest, httpResponse, Level.DEBUG, "Blocked path called");
		}
	}

	private void processRequest(String path, HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain chain)
			throws IOException, ServletException {
		if (frontendApiPaths.matcher(path).matches()
				&& !externalApiPaths.matcher(path).matches()
				&& !isRequestFromFrontend(httpRequest)) {
			blockAndLogRequest(httpRequest, httpResponse, Level.WARN, "Internal frontend API called without frontend referer");
		}
		else {
			if (validateAndBlockRequest(httpRequest, httpResponse,
					trustBrokerProperties.getBlockedHeaderNames(), httpRequest::getHeader, "Header")) {
				return;
			}
			if (validateAndBlockRequest(httpRequest, httpResponse,
					trustBrokerProperties.getBlockedRequestParameterNames(), httpRequest::getParameter, "Parameter")) {
				return;
			}
			chain.doFilter(httpRequest, httpResponse);
		}
	}

	private boolean isRequestFromFrontend(HttpServletRequest httpRequest) {
		var referer = WebUtil.getReferer(httpRequest);
		return WebSupport.isOwnOrigin(trustBrokerProperties, WebUtil.getValidatedUri(referer));
	}

	private void blockAndLogRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			Level level, String reason) throws IOException {
		// favicon.ico by browser to be handled silently, shall come from assets (see test)
		if (log.isEnabledForLevel(level)) {
			var path = httpRequest.getRequestURI();
			log.atLevel(level).log("{} - sending HTTP/404 NOT FOUND for path='{}' clientNetwork={} referer={} userAgent='{}'"
							+ " allowedAll='{}' allowedInternal='{}' frontendApis='{}' externalApis='{}'",
					reason, path, WebSupport.getClientNetwork(httpRequest, trustBrokerProperties.getNetwork()),
					StringUtil.clean(WebUtil.getReferer(httpRequest)), StringUtil.clean(WebSupport.getUserAgent(httpRequest)),
					allAllowedPathsRegex, internalAllowedPathsRegex, frontendApiPathsRegex, externalApiPathsRegex);
		}
		httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
	}

	// validate headers or parameters against a blocked list and send 404 if any are found
	private boolean validateAndBlockRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			List<String> blockedNames, Function<String, String> getter, String type) throws IOException {
		if (CollectionUtils.isEmpty(blockedNames)) {
			return false;
		}
		var blockedValues = blockedNames.stream().map(name -> checkBlocked(name, getter)).filter(Objects::nonNull).toList();
		if (blockedValues.isEmpty()) {
			return false;
		}
		// block and log
		if (log.isWarnEnabled()) {
			var path = httpRequest.getRequestURI();
			log.warn("Sending HTTP/404 NOT FOUND for path='{}' clientNetwork={} referer={} userAgent='{}' found blocked{}Values={}",
					path, WebSupport.getClientNetwork(httpRequest, trustBrokerProperties.getNetwork()),
					StringUtil.clean(WebUtil.getReferer(httpRequest)), StringUtil.clean(WebSupport.getUserAgent(httpRequest)),
					type, blockedValues);
		}
		httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
		return true;
	}

	// returns a non-null string for logging if blocked
	private static String checkBlocked(String name, Function<String, String> getter) {
		var value = getter.apply(name);
		if (value != null) {
			return StringUtil.clean(name) + '=' + StringUtil.clean(value);
		}
		return null;
	}
}
