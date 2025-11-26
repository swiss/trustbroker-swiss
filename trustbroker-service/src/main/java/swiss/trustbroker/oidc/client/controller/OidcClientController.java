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

package swiss.trustbroker.oidc.client.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.oidc.client.service.AuthorizationCodeFlowService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * OIDC client side controller accepting responses from an OIDC CP.
 */
@Controller
@AllArgsConstructor
@Slf4j
public class OidcClientController {

	private final AuthorizationCodeFlowService authorizationCodeFlowService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	private final AssertionConsumerService assertionConsumerService;

	private final OutputService outputService;

	private final RelyingPartyService relyingPartyService;

	@SuppressWarnings("java:S3752") // GET and POST are OK here depending on ResponseMode
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST },
			path ={ ApiSupport.OIDC_RESPONSE_URL, ApiSupport.OIDC_RESPONSE_URL + "/{realm}"})
	public String authorizationCodeResponseQuery(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			@PathVariable(name = "realm", required = false) String realm,
			@RequestParam(name = "state", required = false) String state,
			@RequestParam(name = "code", required = false) String code,
			@RequestParam(name = "error", required = false) String error,
			@RequestParam(name = "error_description", required = false) String errorDescription,
			@RequestParam(name = "error_uri", required = false) String errorUri) {
		log.info("Received authorization code response with method={} for realm={} state={} code=*** error={}",
				httpServletRequest.getMethod(), realm, state, error);
		if (state == null) {
			throw new RequestDeniedException(
					String.format("Missing state in OIDC authorization code response for realm=%s", realm));
		}
		var stateData = stateCacheService.findRequiredBySpId(state, OidcClientController.class.getSimpleName());
		if (error != null) {
			return handleFailedCpResponse(httpServletRequest, httpServletResponse, stateData,
					error, errorDescription, errorUri);
		}
		if (code == null) {
			throw new RequestDeniedException(
					String.format("Missing code in OIDC authorization code response for realm=%s state=%s", realm, state));
		}
		var redirectUrl = handleSuccessCpResponse(httpServletRequest, httpServletResponse, realm, code, stateData);
		return WebSupport.getViewRedirectResponse(redirectUrl);
	}

	private String handleSuccessCpResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			String realm, String code, StateData stateData) {
		log.debug("Processing successful authorization code response for realm={} stateData={} code=***",
				realm, stateData.getId());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(stateData.getCpIssuer(), null);
		var cpResponse = authorizationCodeFlowService.handleCpResponse(realm, code, claimsParty, stateData);
		var referer = WebUtil.getOriginOrReferer(httpServletRequest);
		cpResponse = assertionConsumerService.handleSuccessCpResponse(claimsParty, stateData, cpResponse, referer, null);
		var responseData = buildResponseData(stateData, null);
		var redirectUrl = relyingPartyService.sendResponseWithSamlResponseFromCp(outputService,
				responseData, stateData, cpResponse, httpServletRequest, httpServletResponse);
		log.debug("Redirecting authorization code response to location={}", redirectUrl);
		return redirectUrl;
	}

	private String handleFailedCpResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			StateData stateData, String error, String errorDescription, String errorUri) {
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
		return relyingPartyService.sendFailedSamlResponseToRp(outputService, responseData, httpServletRequest,
				httpServletResponse, cpResponse);
	}

	private static ResponseData<Response> buildResponseData(StateData stateData, Response response) {
		var binding = stateData.getSpStateData().getRequestBinding();
		var signatureContext = SignatureContext.forBinding(binding, null);
		return ResponseData.of(response, stateData.getId(), signatureContext);
	}

}
