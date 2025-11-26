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

package swiss.trustbroker.sso.controller;

import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.controller.AbstractSamlController;
import swiss.trustbroker.saml.dto.SsoParticipants;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;
import swiss.trustbroker.util.WebSupport;

/**
 * SSO services
 */
@Controller
@Slf4j
public class SsoController extends AbstractSamlController {

	private final SsoService ssoService;

	public SsoController(
			TrustBrokerProperties trustBrokerProperties,
			SamlValidator samlValidator,
			SsoService ssoService) {
		super(trustBrokerProperties, samlValidator);
		this.ssoService = ssoService;
	}

	// Return the list of participants in a particular SSO group
	@GetMapping(path = "/api/v1/sso/participants/{ssoGroupName}")
	@ResponseBody
	public List<SsoParticipants> getSsoParticipantsForGroup(HttpServletRequest request, HttpServletResponse response,
			@PathVariable(name = "ssoGroupName") String ssoGroupName) {
		var cookieNameParams = SsoService.SsoCookieNameParams.of(ssoGroupName);
		var deviceId = WebSupport.getDeviceId(request);
		// return a singleton list for API consistency with the generic method
		return Collections.singletonList(ssoService.getSsoParticipants(cookieNameParams, request.getCookies(), deviceId));
	}

	// Return the list of participants in all SSO groups
	@GetMapping(path = "/api/v1/sso/participants")
	@ResponseBody
	public List<SsoParticipants> getSsoParticipants(HttpServletRequest request, HttpServletResponse response) {
		return getSsoParticipants(request);
	}

	private List<SsoParticipants> getSsoParticipants(HttpServletRequest request) {
		var deviceId = WebSupport.getDeviceId(request);
		return ssoService.getAllSsoParticipants(request.getCookies(), deviceId);
	}

	// Perform logout only if there is a single active SSO group
	// returns the active list if more than one group is active or if the logout failed
	@DeleteMapping(path = "/api/v1/sso/rp/{rpId}")
	@ResponseBody
	@Transactional
	public List<SsoParticipants> logoutSsoParticipantIfOnlyGroup(HttpServletRequest request, HttpServletResponse response,
			@PathVariable(name = "rpId") String rpId) {
		var relyingPartyId = ApiSupport.decodeUrlParameter(rpId);
		var result = getSsoParticipants(request);
		if (result.size() == 1) {
			var ssoGroupName = result.get(0).getSsoGroupName();
			if (logoutSsoParticipantAndClearCookies(request, response, ssoGroupName, relyingPartyId, null, null)) {
				return Collections.emptyList();
			}
		}
		return result;
	}

	// Selected a single SSO participant or group for logout
	@DeleteMapping(path = "/api/v1/sso/group/{ssoGroupName}/{rpId}/{cpId}/{subjectNameId}")
	@Transactional
	public void logoutSsoParticipant(HttpServletRequest request, HttpServletResponse response,
			@PathVariable(name = "ssoGroupName") String ssoGroupName, @PathVariable(name = "rpId") String rpId,
			@PathVariable(name = "cpId") String cpId, @PathVariable(name = "subjectNameId") String subjId) {
		var relyingPartyId = ApiSupport.decodeUrlParameter(rpId);
		var claimsProviderId = ApiSupport.decodeUrlParameter(cpId);
		var subjectNameId = ApiSupport.decodeUrlParameter(subjId);
		boolean success = logoutSsoParticipantAndClearCookies(request, response, ssoGroupName,
				relyingPartyId, claimsProviderId, subjectNameId);

		// response to UI
		var referer = WebUtil.getHeader(org.springframework.http.HttpHeaders.REFERER, request);
		var location = referer + "?status=" + (success ? HttpServletResponse.SC_OK : HttpServletResponse.SC_NOT_FOUND);
		log.debug("Redirecting to {}", location);
		// change DELETE to GET
		response.setStatus(HttpServletResponse.SC_SEE_OTHER);
		response.setHeader(HttpHeaders.LOCATION, location);
	}

	private boolean logoutSsoParticipantAndClearCookies(HttpServletRequest request, HttpServletResponse response,
			String ssoGroupName, String rpId, String cpId, String subjectNameId) {

		var cookieNameParams = SsoService.SsoCookieNameParams.of(ssoGroupName, cpId, subjectNameId);
		var deviceId = WebSupport.getDeviceId(request);
		var clearCookies = ssoService.logoutSsoParticipantById(cookieNameParams, request.getCookies(), deviceId, rpId);

		// clean session cookies
		WebUtil.addCookies(response, clearCookies);
		return !clearCookies.isEmpty();
	}

}
