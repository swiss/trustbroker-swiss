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
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import swiss.trustbroker.audit.dto.OidcAuditData;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.service.SsoService;

// Documentation https://openid.net/specs/openid-connect-rpinitiated-1_0.html
@Component
@AllArgsConstructor
@Slf4j
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final CustomOAuth2AuthorizationService authorizationService;

	private final SsoService ssoService;

	private final VelocityEngine velocityEngine;

	// NOTE: LogoutHandler is called by LogoutFilter after clearing the cookies so session is not addressable anymore
	// We therefore invalidate the OIDC and SSO sessions in the OidcTxForwardFilter at the end.
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException {
		// find message details
		var clientId = OidcSessionSupport.getOidcClientId(request, relyingPartyDefinitions, properties.getNetwork());
		var originalRedirectUrl = OidcSessionSupport.getRedirectUri(request);
		var stateParam = OidcSessionSupport.getStateParam(request);
		var redirectUrl = originalRedirectUrl;
		if (redirectUrl != null && stateParam != null) {
			redirectUrl = WebUtil.appendQueryParameters(redirectUrl,  Map.of("state", stateParam));
		}

		// Find session details
		var userPrincipal = OidcSessionSupport.getSamlPrincipalFromAuthentication(authentication, request);
		var oidcSessionId = OidcSessionSupport.getOidcSessionId(request, relyingPartyDefinitions, properties.getNetwork()); // optional
		var ssoSessionId = OidcSessionSupport.getSsoSessionId(); // optional
		// BSESSION cookie is discarded via container too using Session.invalidate()
		OidcSessionSupport.discardOidcClientCookie(clientId, response, properties.isSecureBrowserHeaders());
		// Delete token from oauth2_authorization table
		var userPrincipalName = userPrincipal != null ? userPrincipal.getName() : null;
		authorizationService.deleteAuthorizationByClientId(clientId, userPrincipalName);

		if (originalRedirectUrl != null &&
				!OidcConfigurationUtil.isRedirectUrlValid(originalRedirectUrl, clientId, OidcUtil.LOGOUT_REDIRECT_URI,
						relyingPartyDefinitions, registeredClientRepository)) {
			log.debug("Sending HTTP FORBIDDEN for OIDC clientId={} ssoSessionId={} due to invalid redirectUrl={}",
					clientId, ssoSessionId, originalRedirectUrl);
			response.setStatus(HttpStatus.SC_FORBIDDEN);
		}
		else {
			renderResponse(clientId, redirectUrl, ssoSessionId, oidcSessionId, request, response);
		}

		// INFO log how good the logout worked (on valid session we should get userPrincipal too)
		if (log.isInfoEnabled()) {
			log.info("Logout userPrincipal='{}' from clientId={} clientIP={} redirectUrl='{}' httpStatus={} "
							+ "oidcSessionId={} ssoSessionId={}",
					userPrincipalName != null ? userPrincipalName : "ANONYMOUS",
					clientId, WebUtil.getClientIp(request),
					redirectUrl, response.getStatus(),
					oidcSessionId, ssoSessionId // null when called by logout handler (invalidated already)
			);
		}
	}

	private void renderResponse(String clientId, String redirectUrl, String ssoSessionId, String oidcSessionId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var realmName = OidcUtil.getRealmFromRequestUrl(request.getRequestURI());
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, realmName, properties, false);
		var stateData = OidcSessionSupport.getSsoStateDataForClient(ssoService, request, relyingParty, clientId);
		if (stateData != null && stateData.hasSsoState()) {
			discardSsoCookie(response, stateData);
			// for invalid/missing redirectUrl we could get it from the RP config SloResponse
			var nameId = ResponseFactory.createNameId(stateData.getCpResponse());
			var ssoSessionParticipants = stateData.getSsoState().getSsoParticipants();
			var referer = WebUtil.getOriginOrReferer(request);
			log.debug("Rendering OIDC SLO response page for clientId={} realm={} ssoSessionId={} oidcSessionId={} redirectUrl={}"
							+ " referer={}  cpNameId={} ssoSessionParticipants={}",
					clientId, realmName, ssoSessionId, oidcSessionId, redirectUrl, referer, nameId, ssoSessionParticipants);
			redirectUrl = ssoService.computeOidcSingleLogoutUrl(redirectUrl, referer, relyingParty);
			var params = ssoService.buildSloResponseParameters(
					relyingParty, referer, ssoSessionParticipants, nameId, oidcSessionId, redirectUrl);
			VelocityUtil.renderTemplate(
					velocityEngine, response, VelocityUtil.VELOCITY_SLO_TEMPLATE_ID, params.velocityParameters());
		}
		else {
			log.debug("Sending OIDC logout redirect for clientId={} realm={} ssoSessionId={} oidcSessionId={} redirectUrl={}",
					clientId, realmName, ssoSessionId, oidcSessionId, redirectUrl);
			handleRedirectResponse(redirectUrl, response);
		}

		// correlated with initial OIDC session
		var oidcAuditData = OidcAuditData.builder()
										 .oidcClientId(clientId)
										 .ssoSessionId(ssoSessionId)
										 .oidcSessionId(oidcSessionId)
										 .oidcLogoutUrl(redirectUrl != null ? redirectUrl : "missing-from-client")
										 .build();
		ssoService.auditLogoutRequestFromRp(request, null, stateData, relyingParty, oidcAuditData);
	}

	private void discardSsoCookie(HttpServletResponse response, StateData stateData) {
		var expiredCookie = ssoService.generateExpiredCookie(stateData);
		response.addCookie(expiredCookie);
		log.debug("Discarding SSO cookie={} for OIDC domain", expiredCookie.getName());
	}

	private static void handleRedirectResponse(String redirectUrl, HttpServletResponse response) throws IOException {
		// Logout always succeeds even though we cannot find client_id or redirect_uri
		// or even when an id_token_hint has been faked (no benefit in that, see below).
		if (redirectUrl == null) {
			log.debug("Sending HTTP OK due to missing redirectUrl");
			response.setStatus(HttpStatus.SC_OK);
		}
		// BUT: If client_id detection is the fundament in OidcSessionSupport to support sub-sessions,
		// therefore no further validation is required here.
		// Validation is done on the original URL without state.
		else {
			log.debug("Sending HTTP redirect to redirectUrl={}", redirectUrl);
			response.sendRedirect(redirectUrl);
		}
	}

}
