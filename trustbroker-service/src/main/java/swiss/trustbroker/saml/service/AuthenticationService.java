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

package swiss.trustbroker.saml.service;

import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.saml.util.SkinnyHrd;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

@Service
@AllArgsConstructor
@Slf4j
public class AuthenticationService {

	private final AssertionConsumerService assertionConsumerService;

	private final RelyingPartyService relyingPartyService;

	private final ClaimsProviderService claimsProviderService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final ApiSupport apiSupport;

	private final AnnouncementService announcementService;

	private final SsoService ssoService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	@SuppressWarnings("java:S1172")
	public String handleSamlResponse(OutputService outputService, ResponseData<Response> responseData,
			HttpServletRequest request, HttpServletResponse response) {
		var statusCode = OpenSamlUtil.getStatusCode(responseData.getResponse());

		if (StatusCode.SUCCESS.equals(statusCode)) {
			var cpResponse = assertionConsumerService.handleSuccessCpResponse(responseData);
			log.debug("Process success SAML response from {} inResponseTo {}", cpResponse.getIssuer(),
					cpResponse.getInResponseTo());
			return relyingPartyService.sendResponseWithSamlResponseFromCp(outputService,
					responseData, cpResponse, request, response);
		}
		else if (isSwitchToEnterprise(responseData, trustBrokerProperties)) {
			// Specific enterprise IdP handling
			var stateData = assertionConsumerService.requestEnterpriseIdp(responseData);
			stateData.setRequestBinding(responseData.getBinding());
			log.debug("Switching IDP from={} to={}", stateData.getIssuer(), trustBrokerProperties.getEnterpriseIdpId());
			claimsProviderService.sendSamlToCpWithMandatoryIds(request, response, stateData,
					trustBrokerProperties.getEnterpriseIdpId());
		}
		else {
			// Generic Responder handling
			var cpResponse = assertionConsumerService.handleFailedCpResponse(responseData);
			log.debug("Process failed SAML response from {} inResponseTo {}", cpResponse.getIssuer(),
					cpResponse.getInResponseTo());
			return relyingPartyService.sendFailedSamlResponseToRp(outputService, responseData, request, response, cpResponse);
		}
		return null;
	}

	static boolean isSwitchToEnterprise(ResponseData<?> responseData, TrustBrokerProperties trustBrokerProperties) {
		var featureEnabled = trustBrokerProperties.isHandleEnterpriseSwitch()
				&& trustBrokerProperties.getEnterpriseIdpId() != null;
		var statusMessage = OpenSamlUtil.getStatusMessage(responseData.getResponse());
		var result = featureEnabled && statusMessage != null && statusMessage.toLowerCase().contains("switch to enterprise");
		log.debug("Deciding switch to enterprise: featureEnabled={} getEnterpriseIdpId={} statusMessage={} result={}",
				featureEnabled, trustBrokerProperties.getEnterpriseIdpId(),
				statusMessage,
				result);
		return result;
	}

	public String handleAuthnRequest(OutputService outputService, AuthnRequest authnRequest,
			HttpServletRequest httpRequest, HttpServletResponse httpResponse, SignatureContext signatureContext) {
		log.debug("Process RP SAML request");
		if (authnRequest.getIssuer() == null) {
			throw new TechnicalException("Issuer is missing from AuthnRequest");
		}

		// find RP
		var referer = WebUtil.getReferer(httpRequest);
		var rpIssuer = authnRequest.getIssuer().getValue();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referer);
		if (relyingPartyDefinitions.isRpDisabled(relyingParty, httpRequest, trustBrokerProperties.getNetwork())) {
			throw new TechnicalException(String.format("RelyingParty=%s disabled", relyingParty.getId()));
		}

		// validate
		validateBinding(relyingParty, signatureContext.getBinding());

		// single CP dispatching))
		var cpSelectionHint = HrdSupport.getClaimsProviderHint(httpRequest, trustBrokerProperties);
		if (cpSelectionHint == null) {
			cpSelectionHint = OpenSamlUtil.extractIdpScoping(authnRequest);
		}

		// SSO enable only if configured, and we do not have load test or hrdHint
		var doSso = doSso(httpRequest, cpSelectionHint, relyingParty);

		// find state
		StateData stateDataByAuthnReq;
		try {
			// security
			signatureContext.setRequireSignature(relyingParty.requireSignedAuthnRequest());
			var validationResult = assertionConsumerService.validateAuthnRequest(authnRequest, httpRequest, signatureContext,
					relyingParty.getSecurityPolicies());

			// state for SSO save pending AuthnRequest as new state until we know the SSO group from the CP chosen CP in HRD
			stateDataByAuthnReq = assertionConsumerService.saveState(authnRequest, validationResult.isSignatureValidated(),
					httpRequest, relyingParty, Optional.empty(), signatureContext.getBinding());
		}
		catch (RequestDeniedException ex) {
			// discontinued stealth mode only (we log the error but analyze requests anyway)
			if (trustBrokerProperties.getSecurity().isSaveStateOnValidationFailure()) {
				assertionConsumerService.saveState(authnRequest, false, httpRequest, relyingParty, Optional.empty(),
						signatureContext.getBinding());
			}
			throw ex;
		}

		// process incoming RP request
		var rpRequest = assertionConsumerService.handleRpAuthnRequest(authnRequest, httpRequest, stateDataByAuthnReq);
		if (rpRequest.isAborted()) {
			return relyingPartyService.sendAbortedSamlResponseToRp(outputService, stateDataByAuthnReq,
					httpRequest, httpResponse, rpRequest, signatureContext.getBinding());
		}

		// allow automated selection of CP with SSO if enabled in the config
		if (doSso) {
			var redirectUrl = skipHrdWithSsoSession(
					authnRequest, httpRequest, referer, rpIssuer, relyingParty, stateDataByAuthnReq, rpRequest);
			if (redirectUrl != null) {
				return redirectUrl;
			}
		}

		// start with announcement screen if feature is enabled on RP, and we have global announcements or AppUrl's on the RP
		// NOTE: In case of skinny UI or OCC monitoring we drop announcement feature, we keep that UI as minimal as possible
		var useSkinnyUi = OperationalUtil.useSkinnyUiForLegacyClients(rpRequest, httpRequest, trustBrokerProperties);
		var skipForMonitoring = OperationalUtil.skipUiFeaturesForAdminAndMonitoringClients(httpRequest, trustBrokerProperties);
		var providerName = authnRequest.getProviderName();
		if (showAnnouncements(relyingParty, providerName, useSkinnyUi, skipForMonitoring, rpRequest.featureConditionSet())) {
			return apiSupport.getAnnouncementsUrl(rpIssuer, authnRequest.getID(), providerName);
		}

		// get HRD CP dispatching data to display HRD screen or forward to CP
		if (rpRequest.hasSingleClaimsProvider()) {
			var cpIssuerId = rpRequest.getClaimsProviders().get(0).getId();
			if (doSso) {
				return handleSingleClaimsProviderSsoRedirect(authnRequest, httpRequest, referer, rpIssuer,
						relyingParty, stateDataByAuthnReq, cpIssuerId);
			}
			return handleSingleClaimsProvider(httpRequest, httpResponse, relyingParty, cpSelectionHint,
					stateDataByAuthnReq, cpIssuerId);
		}

		if (useSkinnyUi != null) {
			return redirectToSkinnyHRD(rpRequest, useSkinnyUi);
		}
		// see angular routing on home/HRD handling
		return apiSupport.getHrdUrl(rpIssuer, authnRequest.getID());
	}

	private boolean showAnnouncements(RelyingParty relyingParty, String providerName,
									  String useSkinnyUi, boolean skipForMonitoring, Set<String> conditions) {
		return announcementService.showAnnouncements(relyingParty.getAnnouncement(), providerName, conditions)
				&& useSkinnyUi == null && !skipForMonitoring;
	}

	private boolean doSso(HttpServletRequest request, String cpSelectionHint, RelyingParty relyingParty) {
		if (relyingParty.isSsoEnabled() && cpSelectionHint != null && !HrdSupport.isHrdHintTest(request, trustBrokerProperties)) {
			log.debug("SSO requires HRD round-trip to get {} for rpIssuer={} cpIssuer={}",
					WebSupport.HTTP_HEADER_DEVICE_ID, relyingParty.getId(), cpSelectionHint);
			return true;
		}
		return cpSelectionHint == null && relyingParty.isSsoEnabled();
	}

	private static void validateBinding(RelyingParty relyingParty, SamlBinding binding) {
		if (!relyingParty.isValidInboundBinding(binding)) {
			throw new RequestDeniedException(String.format("Relying party rpIssuerId=%s does not support inbound binding=%s",
					relyingParty.getId(), binding));
		}
	}

	private String skipHrdWithSsoSession(AuthnRequest authnRequest, HttpServletRequest httpRequest, String referer,
			String rpIssuer, RelyingParty relyingParty, StateData stateData, RpRequest rpRequest) {
		if (!relyingParty.getSso().skipHrdWithSsoSession()) {
			log.debug("SSO: For RP rpIssuerId={} not skipping HRD because skipHrdWithSsoSession=false", rpIssuer);
			return null;
		}
		for (var uiObject : rpRequest.getUiObjects().getTiles()) {
			var cpUrn = uiObject.getUrn();
			var redirectUrl = handleClaimsProviderSso(authnRequest, httpRequest, referer, rpIssuer, relyingParty,
					cpUrn, stateData);
			if (redirectUrl != null) {
				log.info("SSO: Auto-selecting cpId={} for rpIssuerId={} and authnRequestId={} due to active SSO session",
						cpUrn, rpIssuer, authnRequest.getID());
				return redirectUrl;
			}
			else {
				log.debug("SSO: For RP rpIssuerId={} CP cpId={} is not auto-selected for authnRequestId={}",
						rpIssuer, cpUrn, authnRequest.getID());
			}
		}
		return null;
	}

	private String handleSingleClaimsProviderSsoRedirect(AuthnRequest authnRequest, HttpServletRequest httpRequest,
			String referer, String rpIssuer, RelyingParty relyingParty, StateData stateDataByAuthnReq, String claimsProviderUrn) {
		var redirectUrl = handleClaimsProviderSso(authnRequest, httpRequest, referer, rpIssuer, relyingParty,
				claimsProviderUrn, stateDataByAuthnReq);
		if (redirectUrl != null) {
			return redirectUrl;
		}
		// only one CP, still go through HRD page to get the device info needed for SSO
		return apiSupport.getHrdUrl(rpIssuer, authnRequest.getID());
	}

	private String handleSingleClaimsProvider(
			HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			RelyingParty relyingParty, String cpSelectionHint,
			StateData stateDataByAuthnReq, String cpIssuerId) {
		log.debug("Direct cpIssuerId='{}' selection for relyingParty='{}' with ssoEnabled={} hint='{}'",
				cpIssuerId, relyingParty.getId(), relyingParty.isSsoEnabled(), cpSelectionHint);
		claimsProviderService.sendSamlToCpWithMandatoryIds(httpRequest, httpResponse, stateDataByAuthnReq,
				cpIssuerId);
		return null;
	}

	private String handleClaimsProviderSso(AuthnRequest authnRequest, HttpServletRequest httpRequest,
			String referer, String rpIssuer, RelyingParty relyingParty, String claimsProviderUrn,
			StateData stateDataByAuthnReq) {
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(claimsProviderUrn, referer, true);
		if (claimsParty == null) {
			log.error("No configuration for cpId={} for rpIssuerId={} and referer={}", claimsProviderUrn, rpIssuer, referer);
			return null;
		}
		var ssoStateData = ssoService.findValidStateFromCookies(relyingParty, claimsParty, httpRequest.getCookies());
		if (ssoStateData.isPresent()) {
			var operation = ssoService.skipCpAuthentication(claimsParty, relyingParty,
					stateDataByAuthnReq, ssoStateData.get());
			if (operation.skipCpAuthentication()) {
				return apiSupport.getDeviceInfoUrl(claimsProviderUrn, rpIssuer, authnRequest.getID());
			}
			else {
				log.debug("SSO: Do not skip authentication for rpIssuerId={} and cpId={}", rpIssuer, claimsProviderUrn);
			}
		}
		else {
			log.debug("SSO: No state for rpIssuerId={} and cpId={}", rpIssuer, claimsProviderUrn);
		}
		return null;
	}

	private String redirectToSkinnyHRD(RpRequest rpRequest, String skinnyHtml) {
		var uiObjects = rpRequest.getUiObjects();
		var pageContent = SkinnyHrd.buildSkinnyHrdPage(uiObjects.getTiles(), skinnyHtml);
		return apiSupport.getSkinnyHrd(pageContent, rpRequest.getRequestId(), skinnyHtml);
	}

}
