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

package swiss.trustbroker.oidc.tx;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsUtils;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.CorsPolicies;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.oidc.session.TomcatSessionManager;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.CorsSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Transaction boundary filter.
 * Also handles access to Keycloak-specific paths to be redirected to Spring authorization server.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 4)
@AllArgsConstructor
@Slf4j
public class OidcTxFilter implements Filter {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties properties;

	private final TomcatSessionManager tomcatSessionManager;

	private final ApiSupport apiSupport;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// original
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;

		// wrapped to manipulate request/response data
		var wrappedRequest = new OidcTxRequestWrapper(httpRequest);
		var frameAncestorHandler = new OidcFrameAncestorHandler(wrappedRequest, relyingPartyDefinitions, properties);
		var wrappedResponse = new OidcTxResponseWrapper(wrappedRequest, httpResponse, relyingPartyDefinitions, properties,
				apiSupport, frameAncestorHandler);

		try {
			// transaction start
			HttpExchangeSupport.begin(httpRequest, httpResponse);
			tomcatSessionManager.load(wrappedRequest);

			// prepare HTTP security headers
			var path = httpRequest.getRequestURI();
			validateAndSetSecurityHeaders(httpRequest, wrappedResponse, path);

			// let spring-security handle if we did not already send a redirect
			if (CorsUtils.isPreFlightRequest(httpRequest)) {
				log.debug("Security headers handled for PREFLIGHT on path path={}", path);
			}
			else if (handleOidcPromptNone(httpRequest, wrappedResponse)) {
				log.debug("Aborting processing with prompt=none on path={}", path);
			}
			else if (response.isCommitted()) {
				log.info("Aborting processing on already committed web stream on path={}", path);
			}
			// configuration handling: Support cors headers without preflight and handle Issuer
			else if (ApiSupport.isOidcConfigPath(path) && properties.getOidc().isUseKeycloakIssuerId()) {
				wrappedResponse.catchOutputStream();
				chain.doFilter(wrappedRequest, wrappedResponse);
				patchOpenIdConfiguration(path, wrappedResponse);
			}
			else {
				// stop here to check on requests, responses, sessions
				OidcSessionSupport.checkSessionOnFederationRedirect(path, httpRequest);
				chain.doFilter(wrappedRequest, wrappedResponse);
			}

			// post-processing
			if (ApiSupport.isOidcSessionPath(path)) {
				FragmentUtil.checkAndRememberFragmentMode(wrappedRequest);
				OidcSessionSupport.rememberAcrValues(wrappedRequest);
			}
		}
		finally {
			// transaction end
			tomcatSessionManager.save();
			HttpExchangeSupport.end();
		}
	}

	void validateAndSetSecurityHeaders(HttpServletRequest httpRequest, OidcTxResponseWrapper wrappedResponse, String path) {
		// general security headers for all paths (some can be disabled by properties):
		wrappedResponse.headerBuilder()
				.hsts()
				.contentTypeOptions()
				.referrerPolicy()
				.robotsTag();

		// validate if we know this client or at least the called URL seems unproblematic
		if (ApiSupport.isOidcCheck3pCookie(path)) {
			validateRequestAndAddCorsHeaders(httpRequest, path, wrappedResponse);
			var perimeter = WebUtil.getValidOrigin(httpRequest.getRequestURL().toString());
			wrappedResponse.headerBuilder()
					.oidc3pCookieOptions(WebUtil.getOriginOrReferer(httpRequest), perimeter);
		}
		else if (ApiSupport.isOidcSessionPath(path)) {
			validateRequestAndAddCorsHeaders(httpRequest, path, wrappedResponse);
			wrappedResponse.headerBuilder()
					.oidcCspFrameOptions(WebSupport.getOwnOrigins(properties));
		}
		else if (ApiSupport.isSamlPath(path)) {
			wrappedResponse.headerBuilder()
					.samlCsp()
					.defaultFrameOptions();
		}
		else if (ApiSupport.isFrontendPath(path)) {
			wrappedResponse.headerBuilder()
					.frontendCsp()
					.defaultFrameOptions();
		}
		else {
			wrappedResponse.headerBuilder()
					.defaultCsp()
					.defaultFrameOptions();
		}
	}

	private static String getKeycloakRealm(String path) {
		if (path.startsWith(ApiSupport.KEYCLOAK_REALMS)) {
			var pathElements = path.split("/");
			return pathElements.length >= 3 ? pathElements[2] : null;
		}
		return null;
	}

	private void validateRequestAndAddCorsHeaders(HttpServletRequest request, String path, OidcTxResponseWrapper response) {
		var origin = WebUtil.getOrigin(request);
		if (origin == null) {
			return; // no CORS required
		}
		// CORS headers need ACL checking, so we need the OIDC client to check HTTP origin against redirectUris.
		// As the client_id is part of the SAML federation handling (broker protocol) we also handle CORS on /saml2 endpoint.
		// Observed OIDC clients doing OPTIONS pre-flight requests on the openid-configuration so allow '*' there too.
		var oidcClient = relyingPartyDefinitions.getOidcClientByPredicate(cl -> cl.isTrustedOrigin(origin));
		if (oidcClient.isPresent() || ApiSupport.isOidcConfigPath(path)) {
			var corsPolicies = CorsPolicies.builder()
					.allowedOrigins(List.of(origin, properties.getPerimeterUrl())) // validated origin plus SAML perimeter
					.allowedMethods(properties.getCors().getAllowedMethods())
					.allowedHeaders(properties.getCors().getAllowedHeaders())
					.build();
			CorsSupport.setAccessControlHeaders(request, response, corsPolicies, WebSupport.getOwnOrigins(properties));
		}
	}

	// Support OIDC clients connecting to Keycloak validating the issuer ID containing /realms/X
	private void patchOpenIdConfiguration(String path, OidcTxResponseWrapper response) throws IOException {
		var realmName = getKeycloakRealm(path);
		var config = response.getBody();
		if (realmName != null && config != null) {
			var issuer = properties.getOidc().getIssuer();
			var configString = new String(config, StandardCharsets.UTF_8);
			config = configString
					.replaceAll(issuer, issuer + ApiSupport.KEYCLOAK_REALMS + "/" + realmName)
					.replace(ApiSupport.SPRING_OAUTH2, "")
					.replace(ApiSupport.OIDC_AUTH, ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.KEYCLOAK_AUTH)
					.replace(ApiSupport.OIDC_TOKEN, ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.OIDC_TOKEN)
					.replace(ApiSupport.OIDC_KEYS, ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.KEYCLOAK_CERTS)
					.replace(ApiSupport.OIDC_USERINFO, ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.OIDC_USERINFO)
					.replace(ApiSupport.OIDC_LOGOUT, ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.OIDC_LOGOUT)
					.replace(ApiSupport.OIDC_INTROSPECT,
							ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.OIDC_TOKEN + ApiSupport.OIDC_INTROSPECT)
					.replace(ApiSupport.OIDC_REVOKE,
							ApiSupport.PROTOCOL_OPENIDCONNECT + ApiSupport.OIDC_TOKEN + ApiSupport.OIDC_REVOKE)
					.getBytes(StandardCharsets.UTF_8);
			log.debug("Patching back .well-known response urls with realm={}", realmName);
		}
		response.patchOutputStream(config);
	}

	private boolean handleOidcPromptNone(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (OidcUtil.isOidcPromptNone(request)) {
			var clientId = OidcSessionSupport.getOidcClientId(request, relyingPartyDefinitions);
			var session = HttpExchangeSupport.getRunningHttpSession();
			var principal = OidcSessionSupport.getAuthenticatedPrincipal(session);
			if (principal != null) {
				log.debug("prompt=none ignored, clientId={} already logged in as principal={}", clientId, principal.getName());
				return false;
			}
			var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
			var redirectUri = OidcUtil.getRedirectUriFromRequest(request);
			if (client.isEmpty() || redirectUri == null) {
				log.warn("prompt=none ignored, clientId={} not define dor no redirect_uri", clientId);
				return false;
			}
			var acl = client.get().getRedirectUris();
			if (acl != null && UrlAcceptor.isRedirectUrlOkForAccess(redirectUri, acl.getAcNetUrls())) {
				var state = StringUtil.clean(request.getParameter(OidcUtil.OIDC_STATE_ID));
				var traceId = TraceSupport.getOwnTraceParent();
				var errorPage = apiSupport.getErrorPageUrl(StandardErrorCode.REQUEST_DENIED.getLabel(), traceId);
				var redirectUrl = OidcExceptionHelper.getOidcErrorLocation(redirectUri,
						"login_required", "no session on prompt=none", errorPage,
						properties.getOidc().getIssuer(), state);
				log.debug("No authenticated OIDC session on prompt=none, redirecting to redirectUrl={}", redirectUrl);
				response.sendRedirect(redirectUrl);
				return true;
			}
		}
		return false;
	}

}
