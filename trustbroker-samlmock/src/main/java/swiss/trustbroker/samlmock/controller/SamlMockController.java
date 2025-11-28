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

package swiss.trustbroker.samlmock.controller;

import java.io.IOException;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.samlmock.SamlMockProperties;
import swiss.trustbroker.samlmock.service.SamlMockFileService;
import swiss.trustbroker.samlmock.service.SamlMockMessageService;
import swiss.trustbroker.samlmock.service.SamlMockMetadataService;

/**
 * This controller handles all the mock services from RP -> XTB and CP -> XTB
 */
@Controller
@Slf4j
@AllArgsConstructor
public class SamlMockController {

	private static final String NAVIGATE_RESPONSE_FROM_XTB = "responseFromXTB";

	private static final String NAVIGATE_SELECT_AUTHN_REQ = "selectRequest";

	private static final String NAVIGATE_SELECT_RESPONSE = "selectResponse";

	private static final String NAVIGATE_REFRESH_MOCK_DATA = "refreshMockData";

	private static final String SAML_POST_TARGET_URL = "samlPostTargetUrl";

	private static final String TB_APPLICATION_URL = "tbApplicationUrl";

	private final SamlMockProperties properties;

	private final SamlMockFileService fileService;

	private final SamlMockMetadataService metadataService;

	private final SamlMockMessageService messageService;

	@GetMapping(path = "/")
	public String homePage(Model model) {
		return showAllSamples(model);
	}

	@GetMapping(path = "/authn/samples")
	public String showAllSamples(Model model) {
		try {
			var sampleMap = messageService.buildEncodedRequestMap();
			model.addAttribute("requests", sampleMap);
			model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
			model.addAttribute("testCpIssuer", properties.getTestCpIssuer());
			model.addAttribute("testRpIssuer", properties.getTestRpIssuer());
			return NAVIGATE_SELECT_AUTHN_REQ;
		}
		catch (TrustBrokerException e) {
			log.error("Loading request samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	@GetMapping(path = "/auth/saml2/idp/samples")
	public String mockCpResponseCpInitiated(Model model) {
		try {
			var acsUrl = properties.getConsumerUrl();
			var relayState = "MOCK_" + UUID.randomUUID();
			return mockCpResponseProcessing(model, acsUrl, null, null, relayState,
					properties.isKeepSampleUrlsforCpInitiated(), StatusResponseType.class);
		}
		catch (TrustBrokerException e) {
			log.error("Loading CP initiated response samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	@PostMapping(path = "/auth/saml2/idp/samples")
	public String mockCpResponse(Model model, HttpServletRequest request) {
		try {
			var samlMessage = messageService.decodeRequest(request);
			var samlRequest = samlMessage.message();
			var requestId = samlRequest.getID();
			var keepSampleUrls = false;
			var acsUrl = request.getParameter(HttpHeaders.REFERER);
			Class<? extends StatusResponseType> allowedResponseType = null;
			if (samlRequest instanceof AuthnRequest authnRequest) {
				acsUrl = authnRequest.getAssertionConsumerServiceURL();
				allowedResponseType = Response.class;
			}
			else if (samlRequest instanceof LogoutRequest) {
				log.info("LogoutRequest - destination from sample files is used");
				keepSampleUrls = true; // no ACS URL in LogoutRequest
				allowedResponseType = LogoutResponse.class;
			}
			return mockCpResponseProcessing(model, acsUrl, samlRequest.getIssuer(), requestId,
					samlMessage.relayState(), keepSampleUrls, allowedResponseType);
		}
		catch (TrustBrokerException e) {
			log.error("Loading response samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private String mockCpResponseProcessing(Model model, String acsUrl, Issuer samlRequestIssuer, String requestId,
			String relayState, boolean keepSampleUrls, Class<? extends StatusResponseType> allowedResponses) {
		var responses = messageService.getCpResponses(acsUrl, samlRequestIssuer, requestId, relayState,
				keepSampleUrls, allowedResponses);
		model.addAttribute("responses", responses);
		model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
		return NAVIGATE_SELECT_RESPONSE;
	}

	@GetMapping(path = "/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
	@ResponseBody
	public String handleMetadata() {
		try {
			var entityDescriptor = metadataService.generateMetadata();
			var domDescriptor = SamlUtil.marshallMessage(entityDescriptor);
			SamlUtil.removeNewLinesFromCertificates(domDescriptor);
			return SerializeSupport.prettyPrintXML(domDescriptor);
		}
		catch (MessageEncodingException e) {
			log.error("Could not generate metadata: {}", e.getMessage(), e);
			throw new TechnicalException(String.format("Could not generate metadata: %s", e.getMessage()), e);
		}
	}

	// SOAP request - manual implementation for mock to avoid a separate @Endpoint
	@PostMapping(path = "/authn/arp")
	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) throws IOException {
		try {
			messageService.resolveArtifact(request, response);
		}
		catch (TrustBrokerException e) {
			log.error("Handling artifact resolve failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	// endpoint for system test: processes a SAML POST request, stores the message in the artifact map, and
	// returns a SAML artifact request that can be forwarded to the target recipient
	@PostMapping(path = "/authn/artifact")
	public void cacheArtifact(HttpServletRequest request, HttpServletResponse response) {
		try {
			messageService.cacheArtifact(request, response);
		}
		catch (TrustBrokerException e) {
			log.error("Handling artifact request failed: {}", e.getInternalMessage());
			throw e;
		}

	}

	@PostMapping(path = { "/authn/consumer", "/auth/saml2/slo", "/auth/saml/slo" })
	public String handleSamlPost(Model model, HttpServletRequest request) {
		return mockSamlMessageConsumer(model, request);
	}

	@GetMapping(path = { "/authn/consumer", "/auth/saml2/slo", "/auth/saml/slo" })
	public String handleSamlGet(Model model, HttpServletRequest request) {
		return mockSamlMessageConsumer(model, request);
	}

	// Display the returned XTB SAMl Response in the UI on RP side.
	// For LogoutResponse the destination is the referrer + /auth/saml2/slo when not explicitly configured on XTB
	// /auth/saml2/slo used by some clients supported as well.
	public String mockAssertionConsumer(Model model, HttpServletRequest request) {
		var messageXml = validateResponseAndExtractMessage(request);

		model.addAttribute(SamlIoUtil.SAML_RESPONSE_NAME, messageXml);
		model.addAttribute(SAML_POST_TARGET_URL, properties.getSamlPostTargetUrl());
		model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	public String mockSamlMessageConsumer(Model model, HttpServletRequest request) {
		if (request.getParameter(SamlIoUtil.SAML_REQUEST_NAME) != null) {
			if (log.isInfoEnabled()) {
				log.info("Received SAML {} request from referrer={}",
						request.getMethod(), StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
			}
			return mockCpResponse(model, request);
		}
		else if (request.getParameter(SamlIoUtil.SAML_RESPONSE_NAME) != null) {
			if (log.isInfoEnabled()) {
				log.info("Received SAML {} response from referrer={}",
						request.getMethod(), StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
			}
			return mockAssertionConsumer(model, request);
		}
		else if (request.getParameter(SamlIoUtil.SAML_ARTIFACT_NAME) != null) {
			if (log.isInfoEnabled()) {
				log.info("Received SAML {} artifact message from referrer={}",
						request.getMethod(), StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
			}
			return mockAssertionConsumer(model, request);
		}
		log.error("Missing SAMLRequest/SAMLResponse/SAMLart parameter in method={} query: {}",
				request.getMethod(), request.getQueryString());
		throw new RequestDeniedException("Missing SAMLRequest/SAMLResponse parameter in query");
	}

	@GetMapping(path = "/auth/http/slo")
	public String mockSloHttpNotificationConsumer(HttpServletRequest request) {
		if (log.isInfoEnabled()) {
			log.info("Received HTTP GET single logout notification from referrer={}",
					StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
		}
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	@GetMapping(path = "/auth/oidc/slo")
	public String mockSloOidcNotificationConsumer(HttpServletRequest request) {
		var issuerId = request.getParameter("iss");
		var sessionId = request.getParameter("sid");
		if (log.isInfoEnabled()) {
			log.info("Received OIDC GET single logout notification for issuerId={} sessionId={} from referrer={}",
					StringUtil.clean(issuerId), StringUtil.clean(sessionId),
					StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
		}
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	@PostMapping(path = { "/accessrequest/consumer" })
	public String mockAccessRequestConsumer(HttpServletRequest request) {
		try {
			validateResponseAndExtractMessage(request);

			var application = getMandatoryQueryParameter(request, "appl");
			var language = getMandatoryQueryParameter(request, "language");
			var cicd = getMandatoryQueryParameter(request, "CICD");
			var returnUrl = getMandatoryQueryParameter(request, "returnURL");
			if (log.isInfoEnabled()) {
				log.info("Received access request for application={}, language={}, CICD={}, returning to {}",
						StringUtil.clean(application), StringUtil.clean(language), StringUtil.clean(cicd),
						StringUtil.clean(returnUrl));
			}
			validateReturnUrl(returnUrl);
			return UrlBasedViewResolver.REDIRECT_URL_PREFIX + returnUrl;
		}
		catch (TrustBrokerException e) {
			log.error("Handling access request failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private void validateReturnUrl(String returnUrl) {
		for (var validReturnUrl : properties.getValidReturnUrls()) {
			if (returnUrl.startsWith(properties.getTbApplicationUrl())) {
				log.debug("returnUrl={} starts with validReturnUrl={}", StringUtil.clean(returnUrl), validReturnUrl);
				return;
			}
		}
		throw new TechnicalException(String.format("returnUrl='%s' is not in validReturnUrls=%s",
				StringUtil.clean(returnUrl), properties.getValidReturnUrls()));
	}

	private static String getMandatoryQueryParameter(HttpServletRequest request, String queryParam) {
		var param = request.getParameter(queryParam);
		if (param == null) {
			log.error("Missing parameter={} in query: {}", queryParam, request.getQueryString());
			throw new TechnicalException(String.format("Missing parameter %s in query: %s", queryParam,
					request.getQueryString()));
		}
		return param;
	}

	private String validateResponseAndExtractMessage(HttpServletRequest request) {
		try {
			var samlResponse = messageService.decodeAndValidateResponse(request);
			var domMessage = SamlUtil.marshallMessage(samlResponse.message());
			return SerializeSupport.prettyPrintXML(domMessage);
		}
		catch (MessageEncodingException ex) {
			log.error("Validating response failed: {}", ex.getMessage(), ex);
			throw new TechnicalException(String.format("Validating response failed: %s", ex.getMessage()), ex);
		}
	}

	@GetMapping(path = "/authn/samples/refresh")
	public String refreshMockData() {
		fileService.refreshMockData();
		return NAVIGATE_REFRESH_MOCK_DATA;
	}


}
