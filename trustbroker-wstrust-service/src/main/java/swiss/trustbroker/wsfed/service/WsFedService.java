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

package swiss.trustbroker.wsfed.service;

import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.service.AuthenticationService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.wsfed.dto.WsFedRequestData;
import swiss.trustbroker.wsfed.util.WsFedUtil;

/**
 * Implements minimal WS-FED sign-in/sign-out integration.
 * <br/>
 * Not (yet) supported services: Metadata, attribute service, pseudonym service.
 * Not (yet) supported attributes: Pointers.
 *
 * @see <a href="https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html">WS-Federation 1.2</a>
 */
@Component
@Slf4j
@AllArgsConstructor
@ConditionalOnProperty(value = "trustbroker.config.wsfed.enabled", havingValue = "true")
public class WsFedService {

	private final RelyingPartySetupService relyingPartySetupService;

	private final AuthenticationService authenticationService;

	private final RelyingPartyService relyingPartyService;

	private final TrustBrokerProperties trustBrokerProperties;

	public String processWsFedRequest(HttpServletRequest request, HttpServletResponse response,
			List<OutputService> outputServices) {
		var requestData = WsFedUtil.createWsFedRequestData(request);
		var referer = WebUtil.getReferer(request);
		var relyingParty = getRelyingParty(requestData, referer);
		if (requestData.getAction().isSignIn()) {
			return processSignIn(request, response, outputServices, relyingParty, requestData);
		}
		else {
			return processSignOut(request, response, outputServices, relyingParty, requestData);
		}
	}

	private RelyingParty getRelyingParty(WsFedRequestData requestData, String referer) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestData.getRealm(), referer, true);
		if (relyingParty == null && requestData.getReplyUrl() != null) {
			var relyingParties = relyingPartySetupService.getRelyingPartiesByAcsUrlMatch(requestData.getReplyUrl());
			if (relyingParties.size() > 1) {
				throw new RequestDeniedException(String.format(
						"Missing RP by realm='%s' or referer='%s' but ambiguous by replyUrl='%s' rpIssuerIds=%s",
						requestData.getRealm(), referer, requestData.getReplyUrl(),
						relyingParties.stream().map(RelyingParty::getId).toList()));
			}
			if (!relyingParties.isEmpty()) {
				relyingParty = relyingParties.get(0);
				log.debug("Missing RP by realm='{}' or referer='{}' but found {} by replyUrl='{}' rpIssuerId={}",
						requestData.getRealm(), referer, relyingParties.size(), requestData.getReplyUrl(), relyingParty.getId());
			}
		}
		if (relyingParty == null) {
			throw new RequestDeniedException(String.format("Missing RP by realm='%s' or referer='%s' or replyUrl='%s'",
					requestData.getRealm(), referer, requestData.getReplyUrl()));
		}
		log.info("Processing WS-FED action={} for rpIssuerId={}", requestData.getAction(), relyingParty.getId());
		validateReplyUrl(relyingParty, requestData.getReplyUrl());
		return relyingParty;
	}

	private static void validateReplyUrl(RelyingParty relyingParty, String replyUrl) {
		var acWhitelist = RelyingParty.initializedAcWhitelist(relyingParty);
		Optional<String> consumer = acWhitelist.findEqualWithDefault(replyUrl);
		if (consumer.isEmpty()) {
			throw new RequestDeniedException(String.format("WS-FED %s='%s' not allowed for rpIssuer='%s'",
					WsFedUtil.REPLY, replyUrl, relyingParty.getId()));
		}
	}

	private String processSignIn(HttpServletRequest request, HttpServletResponse response, List<OutputService> outputServices,
			RelyingParty relyingParty, WsFedRequestData requestData) {
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, relyingParty.getId());
		authnRequest.setAssertionConsumerServiceURL(requestData.getReplyUrl());
		authnRequest.setForceAuthn(requestData.getForceAuth());
		var authLevel = requestData.getAuthLevel();
		if (authLevel != null) {
			var authnContext = SamlFactory.createRequestedAuthnContext(List.of(authLevel), null);
			authnRequest.setRequestedAuthnContext(authnContext);
		}
		if (requestData.getTimestamp() != null) {
			authnRequest.setIssueInstant(requestData.getTimestamp());
		}
		var signatureContext = SignatureContext.forWsFed(requestData.getContext());
		signatureContext.setRequireSignature(false); // internal object, never serialized
		return authenticationService.handleAuthnRequest(outputServices, authnRequest, requestData.getContext(),
				request, response, signatureContext);
	}

	private String processSignOut(HttpServletRequest request, HttpServletResponse response, List<OutputService> outputServices,
			RelyingParty relyingParty, WsFedRequestData requestData) {
		// NameId unknown with WS-Fed
		var logoutRequest = SamlFactory.createLogoutRequest(relyingParty.getId(), trustBrokerProperties.getPerimeterUrl(), null);
		var signatureContext = SignatureContext.forWsFed(null);
		signatureContext.setRequireSignature(false); // internal object, never serialized
		relyingPartyService.handleLogoutRequest(outputServices, logoutRequest, null, request, response, signatureContext);
		log.info("WS-Fed action={} replyUrl='{}'", requestData.getAction(), requestData.getReplyUrl());
		return requestData.getReplyUrl();
	}

	public boolean isWsFed(HttpServletRequest request) {
		if (!WsFedUtil.ALLOWED_METHODS.contains(request.getMethod())) {
			return false;
		}
		return WsFedUtil.getAction(request).isPresent();
	}
}
