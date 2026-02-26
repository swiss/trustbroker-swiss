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

package swiss.trustbroker.oidc.tx;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsUtils;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.CorsPolicies;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.script.service.ScriptService;
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

	private final ApiSupport apiSupport;

	private final ScriptService scriptService;

	private final SessionTxWrapper sessionTxWrapper;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// original
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;
		var path = httpRequest.getRequestURI();

		// wrapped to manipulate request/response data
		var wrappedRequest = new OidcTxRequestWrapper(httpRequest);
		var frameAncestorHandler = new OidcFrameAncestorHandler(wrappedRequest, relyingPartyDefinitions, properties);
		var wrappedResponse = new OidcTxResponseWrapper(wrappedRequest, httpResponse, relyingPartyDefinitions, properties,
				apiSupport, frameAncestorHandler);

		try {
			// web exchange begin (potentially business transactional)
			HttpExchangeSupport.begin(httpRequest, wrappedResponse);
			catchOutputStream(httpRequest, wrappedResponse);

			// prepare HTTP security headers
			validateAndSetSecurityHeaders(httpRequest, wrappedResponse, path);

			// stateless spring-security redirect handling
			if (CorsUtils.isPreFlightRequest(httpRequest)) {
				log.debug("HTTP security headers handled for OPTIONS/PREFLIGHT on path path={}", path);
			}
			// stateless assert of pre-emptive output stream flushing
			else if (response.isCommitted()) {
				log.info("HTTP request committed on path={}", path);
			}
			// stateless configuration handling (support cors headers without preflight and handle issuer)
			else if (ApiSupport.isOidcConfigPath(path) && properties.getOidc().isUseKeycloakIssuerId()) {
				wrappedResponse.catchOutputStream();
				chain.doFilter(wrappedRequest, wrappedResponse);
				handlePenTestRequest();
				patchOpenIdConfiguration(path, wrappedResponse);
			}
			// stateful OIDC federation handling including acr_values and response_mode post-processing
			else if (ApiSupport.isOidcSessionPath(path)) {
				sessionTxWrapper.doFilter(wrappedRequest, wrappedResponse, chain);
				handlePenTestRequest();
			}
			// stateless resources or SAML handling
			else {
				chain.doFilter(wrappedRequest, wrappedResponse);
				handlePenTestRequest();
			}
		}
		catch (CannotAcquireLockException ex) {
			if (!ApiSupport.isReadyOnlyAccess(path)) {
				throw ex;
			}
			// state change failure not security relevant, so just ignore
			log.warn("Try saving ready-only session failed: {}", ex.getMessage());
		}
		finally {
			HttpExchangeSupport.end();
			flushOutputStream(wrappedResponse);
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
		// Web resources (before SAML as this is within ApiPath)
		if (ApiSupport.isWebResourcePath(path)) {
			wrappedResponse.headerBuilder()
						   .defaultCsp()
						   .defaultFrameOptions();
		}
		// OIDC rp side
		else if (ApiSupport.isOidcSessionPath(path)) {
			validateRequestAndAddCorsHeaders(httpRequest, path, wrappedResponse);
			wrappedResponse.headerBuilder()
						   .oidcCspFrameOptions(WebSupport.getOwnOrigins(properties));
		}
		// SAML and APIS that lead to SAML responses
		else if (ApiSupport.isSamlPath(path) || ApiSupport.isApiPath(path)) {
			wrappedResponse.headerBuilder()
						   .samlCsp()
						   .defaultFrameOptions();
		}
		// SPA
		else if (ApiSupport.isFrontendPath(path)) {
			wrappedResponse.headerBuilder()
						   .frontendCsp()
						   .defaultFrameOptions();
		}
		// keycloak compat
		else if (ApiSupport.isOidcCheck3pCookie(path)) {
			validateRequestAndAddCorsHeaders(httpRequest, path, wrappedResponse);
			var perimeter = WebUtil.getValidOrigin(httpRequest.getRequestURL().toString());
			wrappedResponse.headerBuilder()
						   .oidc3pCookieOptions(WebUtil.getOriginOrReferer(httpRequest), perimeter);
		}
		// fallback
		else {
			wrappedResponse.headerBuilder()
						   .defaultCsp()
						   .defaultFrameOptions();
		}
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
			List<String> allowedOrigins = new ArrayList<>();
			allowedOrigins.add(properties.getPerimeterUrl()); // validated origin plus SAML perimeter
			if (oidcClient.isEmpty()) {
				log.warn("No OIDC client with matching ACUrl for origin=\"{}\" called on path=\"{}\" - origin not trusted",
						StringUtil.clean(origin), StringUtil.clean(path));
			}
			else {
				allowedOrigins.add(origin);
				OidcTxUtil.validateKeycloakRealm(path, oidcClient.get(), origin);
			}
			var corsPolicies = CorsPolicies.builder()
					.allowedOrigins(allowedOrigins)
					.allowedMethods(properties.getCors().getAllowedMethods())
					.allowedHeaders(properties.getCors().getAllowedHeaders())
					.build();
			CorsSupport.setAccessControlHeaders(request, response, corsPolicies, WebSupport.getOwnOrigins(properties));
		}
	}

	// buffer some responses to make sure frameworks to not write to client before TX commit (TX are on OIDC and SAML federation)
	private void catchOutputStream(HttpServletRequest httpRequest, OidcTxResponseWrapper wrappedResponse) {
		var path = httpRequest.getRequestURI();
		// optimize (do not cache assets and other resources)
		if (ApiSupport.isSamlPath(path) || ApiSupport.isOidcSessionPath(path)
				|| WebSupport.penTestingModeEnabled(httpRequest, properties)) {
			wrappedResponse.catchOutputStream();
			var penTestMarker = properties.getPublicPenTestCookie();
			if (penTestMarker != null) {
				var scenario = WebUtil.getAny(penTestMarker, httpRequest);
				HttpExchangeSupport.setRunningPenTestScenario(scenario);
			}
		}
	}

	// flush buffered data after TX commit
	private void flushOutputStream(OidcTxResponseWrapper wrappedResponse) throws IOException {
		wrappedResponse.flushOutputStream();
	}

	// Support OIDC clients connecting to Keycloak validating the issuer ID containing /realms/X
	private void patchOpenIdConfiguration(String path, OidcTxResponseWrapper response) throws IOException {
		var realmName = OidcTxUtil.getKeycloakRealm(path);
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
			// replace on output stream, discarding original body
			response.setContentLengthLong(config.length);
			response.flushOutputStream(config);
		}
	}

	private void handlePenTestRequest() {
		if (HttpExchangeSupport.isRunningPenTestScenario()) {
			scriptService.processOnMessage();
		}
	}

}
