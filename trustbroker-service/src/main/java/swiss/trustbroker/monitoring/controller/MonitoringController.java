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

package swiss.trustbroker.monitoring.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.monitoring.dto.MonitoringResponse;
import swiss.trustbroker.monitoring.dto.Status;
import swiss.trustbroker.monitoring.service.MonitoringService;
import swiss.trustbroker.saml.controller.AbstractSamlController;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;

/**
 * Monitoring API
 */
@RestController
@Slf4j
public class MonitoringController extends AbstractSamlController {

	private final RelyingPartySetupService relyingPartySetupService;

	private final MonitoringService monitoringService;

	public MonitoringController(TrustBrokerProperties trustBrokerProperties, SamlValidator samlValidator,
			RelyingPartySetupService relyingPartySetupService, MonitoringService monitoringService) {
		super(trustBrokerProperties, samlValidator);
		this.relyingPartySetupService = relyingPartySetupService;
		this.monitoringService = monitoringService;
	}

	/**
	 * Triggers a SAML login on the provided RP / CP pair.<br/>
	 * IDs can be plain text (unless they contain '?' or '/' that would affect the parsing of the path),
	 * URL encoded, or Base64 URL encoded
	 *
	 * @param request
	 * @param response
	 * @param rpId     required to determine the RP
	 * @param cpId     optional to filter the list of CPs for the RP
	 * @return MonitoringResponse.INVALID if rpId plus cpId does not lead to a pair of exactly one RP and CP / null otherwise
	 */
	@GetMapping({ ApiSupport.MONITORING_ACS_URL,
			ApiSupport.MONITORING_ACS_URL + "/{rpId}",
			ApiSupport.MONITORING_ACS_URL + "/{rpId}/{cpId}" })
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
		var numCps = monitoringService.triggerMonitoring(request, response, relyingParty, cpId);
		if (numCps == 0) {
			log.error("Could not find CP matching cpId={} for RP rpId={}", cpId, rpId);
			return MonitoringResponse.builder()
									 .numCp(numCps)
									 .status(Status.INVALID)
									 .build();
		}
		if (numCps > 1) {
			log.error("Found multiple CP matching cpId={} for RP rpId={}", cpId, rpId);
			return MonitoringResponse.builder()
									 .numCp(numCps)
									 .status(Status.INVALID)
									 .build();
		}
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

	/**
	 * Processes the CP response to the request triggered by the monitoring.<br/>
	 * Note: No signature check other validation of the SAML response content is performed.
	 *
	 * @param request
	 * @param rpId
	 * @param cpId
	 * @return MonitoringResponse.UP for status code SUCCESS / MonitoringResponse.DOWN otherwise
	 */
	@PostMapping({ ApiSupport.MONITORING_ACS_URL,
			ApiSupport.MONITORING_ACS_URL + "/{rpId}",
			ApiSupport.MONITORING_ACS_URL + "/{rpId}/{cpId}" })
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
