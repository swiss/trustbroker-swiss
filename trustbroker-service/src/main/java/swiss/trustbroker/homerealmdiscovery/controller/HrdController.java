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

package swiss.trustbroker.homerealmdiscovery.controller;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.dto.AnnouncementUiElement;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.dto.SupportInfo;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.saml.dto.DeviceInfoReq;
import swiss.trustbroker.saml.dto.UiObjects;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.ClaimsProviderService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.service.SamlOutputService;
import swiss.trustbroker.saml.util.SamlStatusCode;
import swiss.trustbroker.saml.util.SamlValidationUtil;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * HRD services separated from application namespace.
 */
@Controller
@AllArgsConstructor
@Slf4j
public class HrdController {

	private final TrustBrokerProperties trustBrokerProperties;

	private final AssertionConsumerService assertionConsumerService;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final ClaimsProviderService claimsProviderService;

	private final SsoService ssoService;

	private final StateCacheService stateCacheService;

	private final AnnouncementService announcementService;

	private final ApiSupport apiSupport;

	private final SamlOutputService samlOutputService;

	private final ProfileSelectionService profileSelectionService;

	private final WebResourceProvider resourceCache;

	// Return the list of CP issuers we need to render
	// once the FE has been adapted, id and stateDataByAuthnReq can be changed to required
	@GetMapping(path = "/api/v1/hrd/relyingparties/{issuer}/tiles")
	@ResponseBody
	public UiObjects getHrdTilesForRpIssuer(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			@PathVariable("issuer") String issuer, @RequestParam(value = "session", required = false) String rpAuthnRequestId) {
		rpAuthnRequestId = StringUtil.clean(rpAuthnRequestId);
		var rpIssuer = ApiSupport.decodeUrlParameter(issuer);
		var referer = WebUtil.getReferer(httpRequest);

		// state for current AuthnRequest must exist
		var stateDataByAuthnReq = stateCacheService.findBySpIdResilient(rpAuthnRequestId, this.getClass().getSimpleName());

		var rpRequest = assertionConsumerService.renderUi(rpIssuer, referer, null, httpRequest, null,
				stateDataByAuthnReq.orElse(null));
		return rpRequest.getUiObjects();
	}

	@GetMapping(path = "/api/v1/hrd/relyingparties/{sessionId}/continue")
	public String handleContinueToRp(HttpServletRequest request, HttpServletResponse response,
			@PathVariable(name = "sessionId") String sessionIdEncoded) {
		log.debug("User confirmed continuation to RP");

		var sessionId = ApiSupport.decodeUrlParameter(sessionIdEncoded);
		var stateData = stateCacheService.findMandatoryValidState(sessionId, this.getClass().getSimpleName());
		// avoid loop due to aborted status (no problem if not persisted):
		stateData.getCpResponse().resetErrorPageStatus();
		var rpId = stateData.getRpIssuer();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpId, null);
		var returnUrl = relyingPartyService.sendResponseToRpFromSessionState(samlOutputService, relyingParty, stateData, request,
				response);
		return WebSupport.getViewRedirectResponse(returnUrl);
	}

	@GetMapping(path = "/api/v1/hrd/profiles")
	@ResponseBody
	public ProfileResponse getUserProfiles(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader(WebSupport.HTTP_HEADER_XTB_PROFILE_ID) String id) {
		SamlValidationUtil.validateProfileRequestId(id);
		log.debug("Rendering response for profileId={}", id);
		var stateData = stateCacheService.find(id, this.getClass().getSimpleName());
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null);
		var profileSelection = relyingParty != null ? relyingParty.getProfileSelection() : null;
		var profileSelectionData = ProfileSelectionData.builder()
													   .profileSelectionProperties(profileSelection)
													   .selectedProfileId(id)
													   .applicationName(stateData.getRpApplicationName())
													   .build();
		return profileSelectionService.buildProfileResponse(profileSelectionData, stateData.getCpResponse());
	}

	@PostMapping(path = "/api/v1/hrd/profile")
	@Transactional
	public String selectProfile(HttpServletRequest request, HttpServletResponse response,
			@RequestBody ProfileRequest profileRequest) {
		var redirectUrl = relyingPartyService.sendResponseWithSelectedProfile(samlOutputService,
				profileRequest, request, response);
		return WebSupport.getViewRedirectResponse(redirectUrl);
	}

	@GetMapping(value = "/api/v1/hrd/images/{name}")
	public void getImageByNameWithMediaType(
			HttpServletRequest request, HttpServletResponse response, @PathVariable("name") String imageName) {
		resourceCache.getImageByNameWithMediaType(request, response, imageName);
	}

	@GetMapping(value = ApiSupport.ASSETS_URL + "/**")
	public void getThemeAsset(HttpServletRequest request, HttpServletResponse response) {
		var path = request.getRequestURI();
		var resource = path.substring(ApiSupport.ASSETS_URL.length());
		resourceCache.getThemeAsset(request, response, resource);
	}

	// translations are generic, but we use the HRD namespace for now
	// NOTE: When ops messages or something else pops up, move this code to a TranslationService
	@GetMapping(value = "/api/v1/hrd/translations/{language}")
	public void getTranslationForLanguage(
			HttpServletRequest request, HttpServletResponse response, @PathVariable("language") String language) {
		resourceCache.getTranslationForLanguage(request, response, language);
	}

	/**
	 * CP selection handling called by UI (we have provided with the links earlier) Updates the relay state cache with the CP's
	 * AuthnRequest ID.
	 */
	@GetMapping(path = "/api/v1/hrd/claimsproviders/{cpid}", produces = MediaType.TEXT_HTML_VALUE)
	@Transactional
	public void redirectUserToClaimsProvider(
			HttpServletRequest request,
			HttpServletResponse response,
			@PathVariable("cpid") String cpIssuerId,
			@RequestParam("session") String rpAuthnRequestId) {
		// security
		cpIssuerId = ApiSupport.decodeUrlParameter(cpIssuerId);
		rpAuthnRequestId = StringUtil.clean(rpAuthnRequestId);

		// state for current AuthnRequest must exist
		var stateDataByAuthnReq = stateCacheService.findRequiredBySpId(rpAuthnRequestId, this.getClass().getSimpleName());

		// check SSO
		var rpIssuerId = stateDataByAuthnReq.getRpIssuer();
		var ssoOperation = ssoService.prepareRedirectForDeviceInfoAfterHrd(request.getCookies(), stateDataByAuthnReq, cpIssuerId);
		if (ssoOperation.skipCpAuthentication()) {
			// SSO session joined
			sendDeviceInfoRedirect(response, cpIssuerId, rpIssuerId, rpAuthnRequestId);
			return;
		}
		// internal processing - keep using stateDataByAuthnReq
		var redirectUrl = claimsProviderService.sendSamlToCpWithMandatoryIds(request, response, stateDataByAuthnReq, cpIssuerId);
		sendOkRedirect(response, redirectUrl);
	}

	private void sendDeviceInfoRedirect(HttpServletResponse response, String cpIssuerId, String rpIssuerId,
			String rpAuthnRequestId) {
		var redirectForDeviceInfo = apiSupport.getDeviceInfoUrl(cpIssuerId, rpIssuerId, rpAuthnRequestId);
		log.info("SSO device info redirect of authnRequestId={} for cpIssuer={} to redirectUrl={}",
				rpAuthnRequestId, cpIssuerId, redirectForDeviceInfo);
		sendOkRedirect(response, redirectForDeviceInfo);
	}

	// location header to be handled in hrd-cards.component, a 3xx status code would be handled by the Browser
	private static void sendOkRedirect(HttpServletResponse response, String redirectUrl) {
		if (redirectUrl != null) {
			log.debug("Sending HTTP status OK with location={}", redirectUrl);
			response.setHeader(HttpHeaders.LOCATION, redirectUrl);
			response.setStatus(HttpServletResponse.SC_OK);
		}
	}

	// SSO and device fingerprinting is not an HRD functionality and this one might want to go to a new SSOController instead
	@PostMapping(value = "/api/v1/device/info")
	@ResponseBody
	@Transactional
	public ResponseEntity<ProfileResponse> checkDeviceInfo(
			@RequestBody DeviceInfoReq deviceInfoReq,
			HttpServletRequest request,
			HttpServletResponse response) {

		var authReqId = deviceInfoReq.getId();
		var cpIssuerId = ApiSupport.decodeUrlParameter(deviceInfoReq.getCpUrn());
		var rpIssuerId = ApiSupport.decodeUrlParameter(deviceInfoReq.getRpUrn());
		var referer = WebUtil.getHeader(org.springframework.http.HttpHeaders.REFERER, request);
		var deviceID = WebSupport.getDeviceId(request);

		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuerId, referer);
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, referer);

		// SSO bailout based on previous CP auth
		var stateDataByAuthnReq = findValidStateByAuthnRequestId(authReqId);
		var stateByCookieId = ssoService.findValidStateFromCookies(relyingParty, claimsParty, request.getCookies());
		if (stateByCookieId.isPresent()) {
			log.debug("Session state found based on cookie, checking SSO...");
			var ssoStateData = stateByCookieId.get();
			// SSO established
			// AuthnRequest attributes like QOA etc. have been checked earlier in AssertionConsumerService
			if (ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, deviceID,
					cpIssuerId)) {
				return sendResponseForSso(request, response, relyingParty, claimsParty, ssoStateData, stateDataByAuthnReq);
			}
		}

		// all protocols
		return sendAuthnRequestToSingleIdp(request, response, stateDataByAuthnReq, claimsParty);
	}

	private StateData findValidStateByAuthnRequestId(String authReqId) {
		var stateDataByAuthnReqOpt = stateCacheService.findBySpIdResilient(authReqId, this.getClass().getSimpleName());
		if (stateDataByAuthnReqOpt.isEmpty()) {
			throw new TechnicalException(String.format("State value is missing for request with id=%s", authReqId));
		}
		var stateDataByAuthnReq = stateDataByAuthnReqOpt.get();
		// Post-condition assertion only: Wire related messageId must always match the initiating AuthnRequestId here
		var initiatingRequestId = stateDataByAuthnReq.getSpStateData().getId();
		if (!initiatingRequestId.equals(authReqId)) {
			throw new TechnicalException(String.format("State is not valid for request with id=%s, expected lastConvId=%s",
					authReqId, initiatingRequestId));
		}
		return stateDataByAuthnReq;
	}

	private ResponseEntity<ProfileResponse> sendResponseForSso(HttpServletRequest request, HttpServletResponse response,
			RelyingParty relyingParty, ClaimsParty claimsParty, StateData ssoStateData, StateData stateDataByAuthnReq) {
		log.debug("Established CP identity and accepted fingerprint, sending AuthnResponse");

		var redirectUrl = relyingPartyService.performAccessRequestWithDataRefreshIfRequired(request, relyingParty, claimsParty,
				ssoStateData, stateDataByAuthnReq);
		if (redirectUrl == null) {
			redirectUrl = relyingPartyService.sendAuthnResponseToRpFromState(samlOutputService, request, response,
					ssoStateData, stateDataByAuthnReq);
		}
		if (redirectUrl == null) {
			return null;
		}
		// return relative URL for Angular router:
		redirectUrl = apiSupport.relativeUrl(redirectUrl);
		var profileResponse = ProfileResponse.builder().redirectUrl(redirectUrl).build();
		return new ResponseEntity<>(profileResponse, HttpStatus.OK);
	}

	private ResponseEntity<ProfileResponse> sendAuthnRequestToSingleIdp(HttpServletRequest request,
			HttpServletResponse response, StateData stateDataByAuthnReq, ClaimsParty claimsParty) {
		var deviceId = WebSupport.getDeviceId(request);
		log.debug("Sending request to IDP for device={}", deviceId);

		// CP federation only on valid session on
		if (stateDataByAuthnReq.isValid()) {
			// remember device
			stateDataByAuthnReq.setDeviceId(deviceId);
			stateCacheService.save(stateDataByAuthnReq, this.getClass().getSimpleName());

			// handle CP invocation
			var redirectUrl = claimsProviderService.sendAuthnRequestToCp(request, response, stateDataByAuthnReq, claimsParty);
			if (redirectUrl == null) {
				return null;
			}
			log.debug("Resulting redirectUrl={} for device={}", redirectUrl, deviceId);
			return new ResponseEntity<>(ProfileResponse.builder().redirectUrl(redirectUrl).build(), HttpStatus.OK);
		}
		throw new RequestDeniedException(String.format("Unexpected invalid sessionId=%s", stateDataByAuthnReq.getId()));
	}

	@GetMapping(value = { "/api/v1/announcements/{issuer}/{appName}", "/api/v1/announcements/{issuer}" })
	@ResponseBody
	public List<AnnouncementUiElement> getAnnouncements(HttpServletRequest request, HttpServletResponse response,
			@PathVariable("issuer") String issuer, @PathVariable(required = false, name = "appName") String appName) {

		String decodedIssuer = ApiSupport.decodeUrlParameter(issuer);
		String applicationName = null;
		if (appName != null) {
			applicationName = ApiSupport.decodeUrlParameter(appName);
		}
		log.debug("Requested announcements for issuer={} appName={}", issuer, appName);

		RelyingParty relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(decodedIssuer, null);
		if (relyingParty == null) {
			log.error("RP config was not found for issuer={} appName={}, no announcements will be shown", decodedIssuer,
					applicationName);
			return Collections.emptyList();
		}

		List<Announcement> announcementsForApplication =
				announcementService.getAnnouncementsForApplication(relyingParty, relyingParty.getAnnouncement(), applicationName);

		// adminlogin cookie shall let users pass
		var skipDisabling = OperationalUtil.skipUiFeaturesForAdminAndMonitoringClients(request, trustBrokerProperties);

		// HRD on client to display tiles with or without disabling
		return announcementsForApplication.stream()
				.map(announcementEntity -> AnnouncementUiElement.builder()
																.type(announcementEntity.getType())
																.applicationAccessible(announcementService.isRpAppAccessible(announcementEntity) || skipDisabling)
																.message(announcementEntity.getMessage())
																.title(announcementEntity.getTitle())
																.url(announcementEntity.getUrl())
																.phoneNumber(announcementEntity.getPhoneNumber())
																.emailAddress(announcementEntity.getEmailAddress())
																.validTo(announcementEntity.getValidTo())
																.build())
				.toList();
	}

	// redirect to HRD for the given session
	@GetMapping(path = "/api/v1/hrd/{session}/continue")
	public String backToHrd(HttpServletRequest request, HttpServletResponse response, @PathVariable("session") String session) {
		var sessionId = ApiSupport.decodeUrlParameter(session);
		var stateData = stateCacheService.find(sessionId, HrdController.class.getSimpleName());
		var rpIssuerId = stateData.getRpIssuer();
		var authnRequestId = stateData.getSpStateData().getId();
		var redirectUrl = apiSupport.getHrdUrl(rpIssuerId, authnRequestId);
		log.info("Redirecting sessionId={} back to HRD for re-login with rpIssuerId={} authnRequestId={}",
				sessionId, rpIssuerId, authnRequestId);
		return WebSupport.getViewRedirectResponse(redirectUrl);
	}

	@GetMapping(path = "/api/v1/support/{errorCode}/{session}")
	@ResponseBody
	public SupportInfo fetchSupportInfo(HttpServletRequest request, HttpServletResponse response,
			@PathVariable("errorCode") String errorCode, @PathVariable("session") String session) {
		var sessionId = ApiSupport.decodeUrlParameter(session);
		var builder = SupportInfo.builder();
		var flow = getFlowForSessionId(sessionId, errorCode);
		if (flow.isPresent()) {
			builder.appUrl(flow.get().getAppUrl());
			builder.emailAddress(flow.get().getSupportEmail());
			builder.phoneNumber(flow.get().getSupportPhone());
		}
		// else: the default support is shown with general contact information
		var result = builder.build();
		log.debug("Returning supportInfo={} for errorCode={} sessionId={}", result, errorCode, sessionId);
		return result;
	}

	Optional<Flow> getFlowForSessionId(String sessionId, String errorCode) {
		var stateDataOpt = stateCacheService.findOptional(sessionId, HrdController.class.getSimpleName());
		if (stateDataOpt.isEmpty()) {
			log.info("Session not found for flow lookup: sessionId={}", sessionId);
			return Optional.empty();
		}
		var stateData = stateDataOpt.get();
		var flowPolicy = stateData.getCpResponse() != null ? stateData.getCpResponse().getFlowPolicy() : null;
		if (flowPolicy != null) {
			log.debug("CP response of sessionId={} contains flow policy={} ", sessionId, flowPolicy);
			return Optional.of(flowPolicy);
		}
		var rpIssuerId = stateData.getRpIssuer();
		var referrer = stateData.getRpReferer();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, referrer, true);
		if (relyingParty == null) {
			log.error("RP not found for flow lookup: rpIssuerId={} referrer={} for sessionId={}", rpIssuerId, referrer, sessionId);
			return Optional.empty();
		}
		var flowOpt = relyingParty.getFlows()
				.stream()
				.filter(flow -> SamlStatusCode.toUiErrorCode(flow.getId()).equals(errorCode))
				.findFirst();
		log.debug("RP rpIssuerId={} of sessionId={} has errorCode={} flowPolicy={} ",
				relyingParty.getId(), sessionId, errorCode, flowOpt.orElse(null));
		return flowOpt;
	}

}
