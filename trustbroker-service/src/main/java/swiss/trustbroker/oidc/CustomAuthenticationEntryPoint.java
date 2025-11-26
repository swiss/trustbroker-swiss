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

package swiss.trustbroker.oidc;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@AllArgsConstructor
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	// Configure the trigger for the AuthnRequest towards XTB/CP that is federated with the client
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {

		// OIDC pre-conditions
		var clientId = OidcSessionSupport.getOidcClientId(request, relyingPartyDefinitions);
		checkClientKnown(clientId, request); // we have an Oidc.Client
		checkRelyingPartyKnown(clientId, request); // we have an enabled RelyingParty

		// OIDC /introspect requires an authorized client (self or delegated)
		checkHttpSessionRequired(request);

		// let spring-sec handle client authentication otherwise except for unauthenticated /authorize
		if (!ApiSupport.isOidcAuthPath(request.getRequestURI())) {
			log.debug("Skip handling federated login on requestUri={}", request.getRequestURI());
			return;
		}

		// handle federated login on /authorize based on a temporary HTTP session identified by BSESSION cookies per client_id
		// NOTE: /saml2/authenticate for the IDP login side is defined by spring-authorization-server
		var loginFormUrl = ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH + clientId;
		AuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(loginFormUrl);
		if (log.isDebugEnabled()) {
			log.debug("Entry point for clientId={} url={}", StringUtil.clean(clientId), StringUtil.clean(loginFormUrl));
		}
		entryPoint.commence(request, response, authException);
	}

	private void checkRelyingPartyKnown(String clientId, HttpServletRequest request) {
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, trustBrokerProperties, false);
		if (relyingPartyDefinitions.isRpDisabled(relyingParty, request, trustBrokerProperties.getNetwork())) {
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.INVALID_REQUEST, String.format(
					"Disabled clientId on request='%s %s' in request from %s",
					request.getMethod(), request.getRequestURI(),
					WebSupport.getClientHint(request, trustBrokerProperties.getNetwork())), "Disabled client_id");
		}
	}

	private void checkClientKnown(String clientId, HttpServletRequest request) {
		if (clientId == null) {
			var headers = request.getHeaderNames() != null ? Collections.list(request.getHeaderNames()) : List.of();
			var params = request.getParameterNames() != null ? Collections.list(request.getParameterNames()) : List.of();
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.INVALID_REQUEST, String.format(
					"Missing clientId on request='%s %s' with headers='%s' parameters='%s' in request from %s",
					request.getMethod(), request.getRequestURI(),
					headers, params,
					WebSupport.getClientHint(request, trustBrokerProperties.getNetwork())), "Missing client_id");
		}
	}

	private void checkHttpSessionRequired(HttpServletRequest request) {
		// Implement rfc7662 unauthorized client.
		// Switch to OAuth2AuthorizationService.findByToken instead of HTTP session as soon as tokens live longer than sessions.
		// Required when HTTP sessions are invalidated after /authorize and /token, /introspect, /userinfo etc.
		var isIntrospect = request.getRequestURI().contains(ApiSupport.OIDC_INTROSPECT);
		if (isIntrospect && HttpExchangeSupport.getRunningHttpSession() == null) {
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, String.format(
					"Accessing endpoint=%s requires authentication and OIDC session was not found for client %s",
					request.getRequestURI(),
					WebSupport.getClientHint(request, trustBrokerProperties.getNetwork())), "Session required");
		}
	}

}
