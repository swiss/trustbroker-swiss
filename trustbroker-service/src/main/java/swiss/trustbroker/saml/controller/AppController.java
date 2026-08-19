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

package swiss.trustbroker.saml.controller;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.service.RedirectOutputService;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.service.ArtifactResolutionService;
import swiss.trustbroker.saml.service.AuthenticationService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;
import swiss.trustbroker.util.WebSupport;

/**
 * This is the main controller for SAML POST and federation metadata related interaction.
 * <br/>
 * Note that we offer the /trustbroker alternative for backward
 * compat and to possibly get out of the ADFS's way for migration if running on same host name.
 */
@Controller
@ConditionalOnBooleanProperty(value = "trustbroker.config.saml.enabled", matchIfMissing = true)
public class AppController extends AbstractSamlController {

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final SsoService ssoService;

	private final AuthenticationService authenticationService;

	private final ArtifactResolutionService artifactResolutionService;

	private final List<OutputService> outputServices;

	private final RedirectOutputService redirectOutputService;

	@Autowired
	public AppController(
			RelyingPartyService relyingPartyService,
			TrustBrokerProperties trustBrokerProperties,
			SamlValidator samlValidator,
			RelyingPartySetupService relyingPartySetupService,
			SsoService ssoService,
			ArtifactResolutionService artifactResolutionService,
			AuthenticationService authenticationService,
			RedirectOutputService redirectOutputService,
			List<OutputService> outputServices) {
		super(trustBrokerProperties, samlValidator);
		this.relyingPartyService = relyingPartyService;
		this.relyingPartySetupService = relyingPartySetupService;
		this.ssoService = ssoService;
		this.artifactResolutionService = artifactResolutionService;
		this.authenticationService = authenticationService;
		this.redirectOutputService = redirectOutputService;
		this.outputServices = outputServices;
	}

	/**
	 * Web traffic dispatcher handling SAML POST and UI interaction.
	 *
	 * @param request  is the web input according to servlet spec
	 * @param response is the web response according to servlet spec
	 * @return redirect routing or null when no redirect is needed.
	 */
	@PostMapping(path = { ApiSupport.SAML_API, ApiSupport.ADFS_ENTRY_URL,
			ApiSupport.ADFS_ENTRY_URL_TRAILING_SLASH, ApiSupport.XTB_LEGACY_ENTRY_URL },
			consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public String handleIncomingPostMessages(HttpServletRequest request, HttpServletResponse response) {
		return handleIncomingMessage(request, response, SamlBinding.POST);
	}

	/**
	 * Web traffic dispatcher handling SAML Redirect and UI interaction.
	 *
	 * @param request  is the web input according to servlet spec
	 * @param response is the web response according to servlet spec
	 * @return redirect routing or null when no redirect is needed.
	 */
	@GetMapping(path = { ApiSupport.SAML_API, ApiSupport.ADFS_ENTRY_URL,
			ApiSupport.ADFS_ENTRY_URL_TRAILING_SLASH, ApiSupport.XTB_LEGACY_ENTRY_URL })
	public String handleIncomingGetMessages(HttpServletRequest request, HttpServletResponse response) {
		return handleIncomingMessage(request, response, SamlBinding.REDIRECT);
	}

	/**
	 * Web traffic dispatcher handling SAML SOAP <strong>without</strong> UI interaction.
	 * Only <code>LogoutRequest</code> is supported at the moment.
	 *
	 * @param request  is the web input according to servlet spec
	 * @param response is the web response according to servlet spec
	 * @return redirect routing or null when no redirect is needed.
	 */
	@PostMapping(path = { ApiSupport.SAML_API, ApiSupport.ADFS_ENTRY_URL,
			ApiSupport.ADFS_ENTRY_URL_TRAILING_SLASH, ApiSupport.XTB_LEGACY_ENTRY_URL },
			consumes = { MediaType.TEXT_XML_VALUE, WebUtil.MEDIA_TYPE_SOAP_12 })
	public String handleIncomingSoapMessages(HttpServletRequest request, HttpServletResponse response) {
		return handleIncomingMessage(request, response, SamlBinding.SOAP);
	}

	private String handleIncomingMessage(HttpServletRequest request, HttpServletResponse response, SamlBinding expectedBinding) {
		MessageContext messageContext;
		SignatureContext signatureContext;
		if (OpenSamlUtil.isSamlArtifactRequest(request)) {
			validateProtocolRestrictions(SamlBinding.ARTIFACT);
			messageContext = artifactResolutionService.decodeSamlArtifactRequest(request);
			signatureContext = SignatureContext.forArtifactBinding();
		}
		else if (expectedBinding == SamlBinding.REDIRECT) {
			validateProtocolRestrictions(SamlBinding.REDIRECT);
			if (!OpenSamlUtil.isSamlRedirectRequest(request)) {
				throw new RequestDeniedException(String.format(
						"GET %s without any SAML message dropped", request.getRequestURI()));
			}
			messageContext = OpenSamlUtil.decodeSamlRedirectMessage(request);
			signatureContext = SignatureContext.forRedirectBinding(WebUtil.getUrlWithQuery(request));
		}
		else if (expectedBinding == SamlBinding.SOAP) {
			validateProtocolRestrictions(SamlBinding.SOAP);
			messageContext = OpenSamlUtil.decodeSamlSoapMessage(request);
			signatureContext = SignatureContext.forSoapBinding();
		}
		else {
			validateProtocolRestrictions(SamlBinding.POST);
			if (!OpenSamlUtil.isSamlPostRequest(request)) {
				throw new RequestDeniedException(String.format(
						"POST %s without any SAML message dropped", request.getRequestURI()));
			}
			messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
			signatureContext = SignatureContext.forPostBinding();
		}
		return processMessageContext(messageContext, response, request, signatureContext);
	}

	private void validateProtocolRestrictions(SamlBinding binding) {
		if (!binding.isIn(trustBrokerProperties.getSaml().getBindings())) {
			throw new RequestDeniedException(
					String.format("Binding=%s not enabled: %s",
							binding, trustBrokerProperties.getSaml().getBindings()));
		}
	}

	private void validateProtocolRestrictionsForMessage(SAMLObject message, SamlBinding binding) {
		// other request types require redirects and don't work with SOAP binding
		if (binding == SamlBinding.SOAP && !(message instanceof LogoutRequest)) {
			throw new RequestDeniedException(
					String.format("Binding=%s not supported for message=%s",
							binding, message.getClass().getName()));
		}
	}

	private String processMessageContext(MessageContext messageContext, HttpServletResponse response,
			HttpServletRequest request, SignatureContext signatureContext) {

		var message = decodeAndValidateMessage(messageContext);
		validateProtocolRestrictionsForMessage(message, signatureContext.getBinding());

		switch (message) {
			case AuthnRequest authnRequest -> {
				var relayState = SAMLBindingSupport.getRelayState(messageContext);
				var redirectUrl = authenticationService.handleAuthnRequest(outputServices, authnRequest, relayState,
						request, response, signatureContext);
				redirectUrl = redirectOutputService.handleRedirect(request, response, redirectUrl);
				return WebSupport.getViewRedirectResponse(redirectUrl);
			}
			case Response samlResponse -> {
				var relayState = OpenSamlUtil.extractRelayStateAsSessionId(messageContext);
				var redirectUrl = authenticationService.handleSamlResponse(outputServices,
						ResponseData.of(samlResponse, relayState, signatureContext), request, response);
				redirectUrl = redirectOutputService.handleRedirect(request, response, redirectUrl);
				return WebSupport.getViewRedirectResponse(redirectUrl);
			}
			case LogoutResponse logoutResponse -> {
				var relayState = OpenSamlUtil.extractRelayStateAsSessionId(messageContext);
				ssoService.handleLogoutResponse(logoutResponse, relayState, request);
			}
			case LogoutRequest logoutRequest -> {
				var relayState = SAMLBindingSupport.getRelayState(messageContext);
				relyingPartyService.handleLogoutRequest(outputServices, logoutRequest, relayState,
						request, response, signatureContext);
			}
			default -> handleUnsupportedMessage(message);
		}
		return null;
	}

	private SAMLObject decodeAndValidateMessage(MessageContext messageContext) {
		SAMLObject message = decodeSamlMessage(messageContext);
		validateSamlMessage(message, relyingPartySetupService.getPartySecurityPolicies(message));
		return message;
	}

	// Use @Endpoint instead? Would require tweaking interceptor chain (see WsTrustEndpoint etc. via Spring EndpointMapping)
	@PostMapping(path = ApiSupport.ARP_URL)
	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) {
		validateProtocolRestrictions(SamlBinding.ARTIFACT);
		artifactResolutionService.resolveArtifact(request, response);
	}

}
