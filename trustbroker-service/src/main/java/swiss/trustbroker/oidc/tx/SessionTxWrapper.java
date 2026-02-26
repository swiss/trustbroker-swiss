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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.oidc.session.TomcatSessionManager;
import swiss.trustbroker.util.ApiSupport;

/**
 * Wrap transactional Tomcat session loading and session around a servlet API filter chain.
 */
@Component
@AllArgsConstructor
@Slf4j
public class SessionTxWrapper {

	private final TomcatSessionManager tomcatSessionManager;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties properties;

	private final ApiSupport apiSupport;

	@Transactional
	public void doFilter(OidcTxRequestWrapper request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		try {
			tomcatSessionManager.load(request);

			if (!oidcPromptNoneRedirectDone(request, response)) {
				OidcSessionSupport.checkSessionOnFederationRedirect(request.getRequestURI(), request);
				chain.doFilter(request, response);
			}

			// post-processing
			FragmentUtil.checkAndRememberFragmentMode(request);
			OidcSessionSupport.rememberAcrValues(request);
		}
		finally {
			tomcatSessionManager.save();
		}
	}

	private boolean oidcPromptNoneRedirectDone(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (OidcUtil.isOidcPromptNone(request)) {
			var clientId = OidcSessionSupport.getOidcClientId(request, relyingPartyDefinitions);
			var session = HttpExchangeSupport.getRunningHttpSession();
			var principal = OidcSessionSupport.getAuthenticatedPrincipal(session);
			if (principal != null) {
				log.info("OIDC prompt=none succeeded, clientId={} principal={} already logged in on path={}",
						clientId, principal.getName(), request.getRequestURI());
				return false;
			}
			var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
			var redirectUri = OidcUtil.getRedirectUriFromRequest(request);
			if (client.isEmpty() || redirectUri == null) {
				log.warn("OIDC prompt=none denied, clientId={} ignored on path={}",	clientId, request.getRequestURI());
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
				log.debug("OIDC prompt=none redirecting, clientId={} not logged in on path={} with cookies='{}'",
						clientId, request.getRequestURI(), request.getCookies());
				response.sendRedirect(redirectUrl);
				return true;
			}
		}
		return false; // non-OIDC case
	}

}
