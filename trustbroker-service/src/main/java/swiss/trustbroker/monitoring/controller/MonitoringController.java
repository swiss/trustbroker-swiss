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

package swiss.trustbroker.monitoring.controller;

import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.monitoring.dto.MonitoringResponse;
import swiss.trustbroker.monitoring.dto.Status;
import swiss.trustbroker.saml.controller.AbstractSamlController;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.ClaimsProviderService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;

/**
 * Monitoring API
 */
@Controller
@Slf4j
public class MonitoringController extends AbstractSamlController {

	private final RelyingPartySetupService relyingPartySetupService;

	private final AssertionConsumerService assertionConsumerService;

	private final ClaimsProviderService claimsProviderService;

	public MonitoringController(TrustBrokerProperties trustBrokerProperties, SamlValidator samlValidator,
			RelyingPartySetupService relyingPartySetupService, AssertionConsumerService assertionConsumerService,
			ClaimsProviderService claimsProviderService) {
		super(trustBrokerProperties, samlValidator);
		this.relyingPartySetupService = relyingPartySetupService;
		this.assertionConsumerService = assertionConsumerService;
		this.claimsProviderService = claimsProviderService;
	}

	/**
	 * Triggers a SAML login on the provided RP / CP pair.<br/>
	 * IDs can be plain text (unless they contain '?' or '/' that would affect the parsing of the path),
	 * URL encoded, or Base64 URL encoded
	 * @param request
	 * @param response
	 * @param rpId required to determine the RP
	 * @param cpId optional to filter the list of CPs for the RP
	 * @return MonitoringResponse.INVALID if rpId plus cpId does not lead to a pair of exactly one RP and CP / null otherwise
	 */
	@GetMapping({ ApiSupport.MONITORING_ACS_URL,
			ApiSupport.MONITORING_ACS_URL + "/{rpId}",
			ApiSupport.MONITORING_ACS_URL + "/{rpId}/{cpId}" })
	@ResponseBody
	public MonitoringResponse monitorRelyingParty(HttpServletRequest request, HttpServletResponse response,
			@PathVariable(name = "rpId", required = false) String rpId,
			@PathVariable(name = "cpId", required = false) String cpId) {
		if (StringUtils.isEmpty(rpId)) {
			rpId = request.getParameter("rpId");
		}
		if (StringUtils.isEmpty(cpId)) {
			cpId = request.getParameter("cpId");
		}
		if (StringUtils.isEmpty(rpId)) {
				log.error("Missing RP ID");
				return MonitoringResponse.INVALID;
		}
		var relyingParty = getRelyingParty(rpId);
		if (relyingParty == null) {
			log.error("RP not found for rpId={}", rpId);
			return MonitoringResponse.INVALID;
		}
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, relyingParty.getId());
		var acsUrl = request.getRequestURI();
		log.debug("Using this request URL as ACS URL: '{}'", acsUrl);
		authnRequest.setAssertionConsumerServiceURL(acsUrl);
		var stateData = assertionConsumerService.saveState(authnRequest, false, request, relyingParty,
				Optional.empty(), SamlBinding.POST);
		var rpRequest = assertionConsumerService.handleRpAuthnRequest(authnRequest, request, stateData);
		var uiObjects = filterUiObjectsForCp(rpRequest.getUiObjects().getTiles(), cpId);
		if (uiObjects.isEmpty()) {
			log.error("Could not find CP matching cpId={} for RP rpId={}", cpId, rpId);
			return MonitoringResponse.builder().numCp(0).status(Status.INVALID).build();
		}
		if (uiObjects.size() > 1) {
			log.error("Found multiple CP matching cpId={} for RP rpId={}", cpId, rpId);
			return MonitoringResponse.builder().numCp(uiObjects.size()).status(Status.INVALID).build();
		}
		claimsProviderService.sendSamlToCpWithMandatoryIds(request, response, stateData,
				uiObjects.get(0).getUrn());

		// redirect tp CP, no response
		return null;
	}

	private RelyingParty getRelyingParty(String rpId) {
		var rpIssuer = WebUtil.urlDecodeValue(rpId);
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, null, true);
		if (relyingParty == null) {
			rpIssuer = Base64Util.urlDecode(rpId, true);
			relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, null, true);
		}
		if (relyingParty != null) {
			log.debug("Monitoring for RP {}", rpIssuer);
			return relyingParty;
		}
		return null;
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

	/**
	 * Processes the CP response to the request triggered by the monitoring.<br/>
	 * Note: No signature check other validation of the SAML response content is performed.
	 * @param request
	 * @param rpId
	 * @param cpId
	 * @return MonitoringResponse.UP for status code SUCCESS / MonitoringResponse.DOWN otherwise
	 */
	@PostMapping({ ApiSupport.MONITORING_ACS_URL,
			ApiSupport.MONITORING_ACS_URL + "/{rpId}",
			ApiSupport.MONITORING_ACS_URL + "/{rpId}/{cpId}" })
	@ResponseBody
	public MonitoringResponse monitorRelyingPartyResponse(HttpServletRequest request,
			@PathVariable(name = "rpId", required = false) String rpId,
			@PathVariable(name = "cpId", required = false) String cpId) {
		MessageContext messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
		var message = decodeSamlMessage(messageContext);
		validateSamlMessage(message, null);
		if (!(message instanceof Response)) {
			log.error("Unexpected responseType={} for RP='{}' / CP='{}'", message.getClass().getName(), rpId, cpId);
			return MonitoringResponse.DOWN;
		}
		var samlResponse = (Response) message;
		var statusCode = OpenSamlUtil.getStatusCode(samlResponse);
		if (!StatusCode.SUCCESS.equals(statusCode)) {
			log.error("Consumed response {} has status={} for RP='{}' / CP='{}'",
					samlResponse.getID(), statusCode, rpId, cpId);
			return MonitoringResponse.DOWN;
		}
		log.debug("Received SUCCESS SAML Response {} for RP='{}' / CP='{}'", samlResponse.getID(), rpId, cpId);
		return MonitoringResponse.UP;
	}

}
