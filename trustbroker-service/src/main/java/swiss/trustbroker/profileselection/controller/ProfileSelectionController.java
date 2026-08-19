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

package swiss.trustbroker.profileselection.controller;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.service.RedirectOutputService;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.profileselection.service.ProfileSelectionServiceFactory;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.util.SamlValidationUtil;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Controller for profile selection services.
 */
@Controller
@AllArgsConstructor
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.profileselection.enabled")
public class ProfileSelectionController {

	private final ProfileSelectionServiceFactory profileSelectionServiceFactory;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	private final List<OutputService> outputServices;

	private final RedirectOutputService redirectOutputService;

	@GetMapping(path = ApiSupport.API_CONTEXT + "/hrd/profiles")
	@ResponseBody
	public ProfileResponse getUserProfiles(@RequestHeader(WebSupport.HTTP_HEADER_XTB_PROFILE_ID) String id) {
		SamlValidationUtil.validateProfileRequestId(id);
		log.debug("Rendering response for profileId={}", id);
		var stateData = stateCacheService.find(id, this.getClass().getSimpleName());
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null);
		var profileSelection = relyingParty != null ? relyingParty.getProfileSelection() : null;
		var hasAccessRequest = relyingParty != null && relyingParty.hasAccessRequest();
		var profileSelectionData = ProfileSelectionData.builder()
		                                               .profileSelectionProperties(profileSelection)
		                                               .selectedProfileId(id)
		                                               .applicationName(stateData.getRpApplicationName())
		                                               .ignoreEmptyProfiles(!hasAccessRequest)
		                                               .build();
		var idmLookup = relyingParty != null ? relyingParty.getIdmLookup() : null;
		var profileSelectionService = profileSelectionServiceFactory.getProfileSelectionService(idmLookup);
		return profileSelectionService.buildProfileResponse(profileSelectionData, stateData.getCpResponse());
	}

	@PostMapping(path = ApiSupport.API_CONTEXT + "/hrd/profile")
	public String selectProfile(HttpServletRequest request, HttpServletResponse response,
			@RequestBody ProfileRequest profileRequest) {
		var redirectUrl = relyingPartyService.sendResponseWithSelectedProfile(outputServices,
				profileRequest, request, response);
		redirectUrl = redirectOutputService.handleRedirect(request, response, redirectUrl);
		return WebSupport.getViewRedirectResponse(redirectUrl);
	}
}
