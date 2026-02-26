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

package swiss.trustbroker.monitoring.service;

import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.ClaimsProviderService;

@Service
@Slf4j
@AllArgsConstructor
public class MonitoringService {

	private final AssertionConsumerService assertionConsumerService;

	private final ClaimsProviderService claimsProviderService;

	@Transactional
	public int triggerMonitoring(HttpServletRequest request, HttpServletResponse response,
			RelyingParty relyingParty, String cpId) {
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, relyingParty.getId());
		var acsUrl = request.getRequestURI();
		log.debug("Using this request URL as ACS URL: '{}'", acsUrl);
		authnRequest.setAssertionConsumerServiceURL(acsUrl);
		var relayState = request.getParameter(SamlIoUtil.SAML_RELAY_STATE);
		var stateData = assertionConsumerService.saveState(authnRequest, relayState, false, request, relyingParty,
				Optional.empty(), SamlBinding.POST);
		var rpRequest = assertionConsumerService.handleRpAuthnRequest(authnRequest, request, stateData);
		var uiObjects = filterUiObjectsForCp(rpRequest.getUiObjects().getTiles(), cpId);
		if (uiObjects.size() == 1) {
			claimsProviderService.sendSamlToCpWithMandatoryIds(request, response, stateData, uiObjects.get(0).getUrn());
		}
		return uiObjects.size();
	}

	private static List<UiObject> filterUiObjectsForCp(List<UiObject> uiObjects, String cpId) {
		var cpUrnUrlDecoded = WebUtil.urlDecodeValue(cpId);
		var cpUrnBase64 = Base64Util.urlDecode(cpId, true);
		if (StringUtils.isNotEmpty(cpUrnUrlDecoded) || StringUtils.isNotEmpty(cpUrnBase64)) {
			uiObjects = uiObjects.stream()
					.filter(obj -> (obj.getUrn().equals(cpUrnUrlDecoded) || obj.getUrn().equals(cpUrnBase64)))
					.toList();
		}
		return uiObjects;
	}
}
