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

package swiss.trustbroker.oidc.client.service;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.oidc.client.controller.OidcClientController;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;

@Service
@Slf4j
@AllArgsConstructor
public class OidcClientService {

	private final AuthorizationCodeFlowService authorizationCodeFlowService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	private final AssertionConsumerService assertionConsumerService;

	private final List<OutputService> outputServices;

	private final RelyingPartyService relyingPartyService;

	@Transactional
	public String handleSuccessCpResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			String realm, String code, String state) {
		var stateData = stateCacheService.findRequiredBySpId(state, OidcClientController.class.getSimpleName());

		log.debug("Processing successful authorization code response for realm={} stateData={} code=***",
				realm, stateData.getId());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(stateData.getCpIssuer(), null);
		var cpResponse = authorizationCodeFlowService.handleCpResponse(realm, code, claimsParty, stateData);
		var referer = WebUtil.getOriginOrReferer(httpServletRequest);
		cpResponse = assertionConsumerService.handleSuccessCpResponse(claimsParty, stateData, cpResponse, referer, null);
		var responseData = buildResponseData(stateData, null);
		var redirectUrl = relyingPartyService.sendResponseWithSamlResponseFromCp(outputServices,
				responseData, stateData, cpResponse, httpServletRequest, httpServletResponse);
		log.debug("Redirecting authorization code response to location={}", redirectUrl);
		return redirectUrl;
	}

	@Transactional
	public String handleFailedCpResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			String state, String error, String errorDescription, String errorUri) {
		var stateData = stateCacheService.findRequiredBySpId(state, OidcClientController.class.getSimpleName());
		log.debug("Processing failed authorization code response for stateData={} code=*** error={}", stateData.getId(), error);
		// error handling in AssertionConsumerService is still based on SAML response
		var response = SamlFactory.createResponse(Response.class, stateData.getCpIssuer());
		var status = SamlFactory.createResponseStatus(error, errorDescription, StatusCode.RESPONDER);
		response.setStatus(status);
		var responseData = buildResponseData(stateData, response);
		var cpResponse = CpResponse.builder()
								   .issuer(stateData.getCpIssuer()) // not verified
								   .build();
		cpResponse = assertionConsumerService.handleFailedCpResponse(responseData, stateData, cpResponse);
		log.error("Failed OIDC response from cpIssuerId={} error=\"{}\" errorDescription=\"{}\" errorUri=\"{}\"",
				cpResponse.getIssuer(), StringUtil.clean(error), StringUtil.clean(errorDescription), StringUtil.clean(errorUri));
		return relyingPartyService.sendFailedSamlResponseToRp(outputServices, responseData, httpServletRequest,
				httpServletResponse, cpResponse);
	}

	private static ResponseData<Response> buildResponseData(StateData stateData, Response response) {
		var binding = stateData.getSpStateData()
							   .getRequestBinding();
		var signatureContext = SignatureContext.forBinding(binding, null);
		return ResponseData.of(response, stateData.getId(), signatureContext);
	}

}
