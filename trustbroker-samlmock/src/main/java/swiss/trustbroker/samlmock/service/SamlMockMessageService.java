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

package swiss.trustbroker.samlmock.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.TreeMap;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.impl.AuthnRequestImpl;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.dto.ArtifactPeer;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.common.saml.dto.SignatureValidationParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.EncryptionUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.samlmock.SamlMockProperties;
import swiss.trustbroker.samlmock.dto.SamlMockCpResponse;
import swiss.trustbroker.samlmock.dto.SamlMockMessage;
import swiss.trustbroker.samlmock.dto.SamlMockRpRequest;

@Component
@Slf4j
public class SamlMockMessageService {

	// 2min before XTB blocks and reload is required
	private static final int MAX_AUTHN_REQUEST_VALIDITY_SEC = 120;

	// 2h before XTB blocks and E2E auth needs to be restarted
	private static final int MAX_ASSERTION_VALIDITY_SEC = 7200;

	private static final String RELAY_STATE_PREFIX = "RELAY_";

	private static final String AUTHN_REQUEST_ID_PREFIX = "AuthnRequest_";

	private final SamlMockProperties properties;

	private final SamlMockFileService fileService;

	private final ArtifactCacheService artifactCacheService;

	private final VelocityEngine velocityEngine;

	private final Random random;

	@Autowired
	@SuppressWarnings("java:S2245") // insecure random is fine for the mock
	public SamlMockMessageService(SamlMockProperties properties, SamlMockFileService fileService,
			ArtifactCacheService artifactCacheService, VelocityEngine velocityEngine) {
		this.properties = properties;
		this.fileService = fileService;
		this.artifactCacheService = artifactCacheService;
		this.velocityEngine = velocityEngine;
		random = new Random();
	}

	public Map<String, SamlMockRpRequest> buildEncodedRequestMap() {
		var uuid = UUID.randomUUID();
		var sampleFiles = fileService.getMockRequestNames();
		Map<String, SamlMockRpRequest> sampleMap = new TreeMap<>();
		sampleFiles.stream().forEach(fileName -> addRequestFromFile(uuid, sampleMap, fileName));
		return sampleMap;
	}

	private void addRequestFromFile(UUID uuid, Map<String, SamlMockRpRequest> sampleMap, String fileName) {
		var data = fileService.getMockRequestFile(fileName);
		RequestAbstractType request = SamlIoUtil.unmarshallXmlFile(fileName, new ByteArrayInputStream(data));
		var sign = true;
		request.setIssueInstant(Instant.now());
		request.setID(AUTHN_REQUEST_ID_PREFIX + uuid);
		if (request instanceof AuthnRequest authnRequest) {
			authnRequest.setAssertionConsumerServiceURL(getAcsUrlForRequest(request));
			setAuthnRequestConditions(authnRequest.getConditions());
			sign = request.getSignature() != null;
		}
		if (sign || properties.isSignAuthnRequest()) {
			resignSamlObject(request);
		}
		var tbConsumerUrl = request.getDestination();
		// AuthnRequest without a Destination
		if (tbConsumerUrl == null) {
			tbConsumerUrl = properties.getConsumerUrl();
		}

		var encodedPostMessage = SamlUtil.encode(request);
		var rpRequest = new SamlMockRpRequest();
		rpRequest.setSamlPostRequest(encodedPostMessage);
		// The SAML message is commonly not signed for redirect requests as the signature is part of the binding
		request.setSignature(null);
		var relayState = RELAY_STATE_PREFIX + uuid;
		rpRequest.setRelayState(relayState);
		var acsUrl = addUriParameter(tbConsumerUrl, SamlIoUtil.SAML_RELAY_STATE, relayState);
		rpRequest.setAcsUrl(acsUrl);
		var encodedRedirectMessage = SamlIoUtil.encodeSamlRedirectData(request);
		rpRequest.setSamlRedirectRequest(encodedRedirectMessage);
		// arpEntityId (getArtifactResolutionIssuer) determines the RP config used during artifact resolution
		// use the mock ID, so we only need to configure an artifact resolution / metadata URL for this RP
		var encodedArtifactMessage = SamlIoUtil.encodeSamlArtifactData(velocityEngine,
				artifactCacheService.getArtifactMap(), request, buildArtifactResolutionParameters(), relayState);
		rpRequest.setSamlArtifactRequest(encodedArtifactMessage);
		var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
		rpRequest.setSigAlg(sigAlg);
		var signature = SamlIoUtil.buildEncodedSamlRedirectSignature(request, fileService.getAuthnRequestCredential(),
				sigAlg, relayState, encodedRedirectMessage);
		rpRequest.setSignature(signature);
		sampleMap.put(fileName, rpRequest);
	}

	private String getAcsUrlForRequest(RequestAbstractType request) {
		if (request instanceof AuthnRequestImpl authnRequest && properties.isUseOriginalAcr()) {
			return authnRequest.getAssertionConsumerServiceURL();
		}
		var acsUrl = properties.getAssertionConsumerServiceUrl();
		// allow two different ACS URLs with the same SamlMock / application
		var localhost = "http://localhost:";
		var localIp = "http://127.0.0.1:";
		if (acsUrl.startsWith(localhost) && request.getDestination() != null && request.getDestination().startsWith(localIp)) {
			acsUrl = acsUrl.replace(localhost, localIp);
			log.info("Request targets {}, repointed ACS URL to {}", request.getDestination(), acsUrl);
		}
		return acsUrl;
	}

	private static String addUriParameter(String url, String name, String value) {
		try {
			var uri = new URIBuilder(url).addParameter(name, value);
			return uri.toString();
		}
		catch (URISyntaxException ex) {
			log.error("URL={} is invalid", url, ex);
			throw new TechnicalException(String.format("URL=%s is invalid", url), ex);
		}
	}

	private static void setAuthnRequestConditions(Conditions conditions) {
		if (conditions != null) {
			conditions.setNotBefore(Instant.now());
			conditions.setNotOnOrAfter(Instant.now().plusSeconds(MAX_AUTHN_REQUEST_VALIDITY_SEC));
		}
	}

	public Map<String, SamlMockCpResponse> getCpResponses(String acsUrl, Issuer samlRequestIssuer,
			String requestId, String relayState, boolean keepSampleUrls, Class<? extends StatusResponseType> allowedResponses) {
		var sampleFiles = fileService.getMockResponseNames();
		var requestIssuer = getAuthnRequestIssuer(samlRequestIssuer, properties.getIssuer());
		return getEncodedResponseMap(sampleFiles, requestId, acsUrl, relayState, requestIssuer, keepSampleUrls, allowedResponses);
	}

	private static String getAuthnRequestIssuer(Issuer issuer, String confIssuer) {
		if (issuer == null) {
			return confIssuer;
		}
		return issuer.getValue();
	}

	private Map<String, SamlMockCpResponse> getEncodedResponseMap(List<String> fileNames, String authnRequestId,
			String acsUrlFromInput, String relayState, String requestIssuer,
			boolean keepSampleUrls, Class<? extends StatusResponseType> allowedResponses) {
		Map<String, SamlMockCpResponse> sampleMap = new TreeMap<>();
		fileNames.stream()
				.forEach(fileName ->
						addResponseFromFile(
								authnRequestId, acsUrlFromInput, relayState, requestIssuer, keepSampleUrls, allowedResponses,
								sampleMap, fileName)
				);
		return sampleMap;
	}

	@SuppressWarnings("java:S107") // internal method of mock, might split it to reduce parameter count
	private void addResponseFromFile(String authnRequestId, String acsUrlFromInput, String relayState, String requestIssuer,
			boolean keepSampleUrls, Class<? extends StatusResponseType> allowedResponses,
			Map<String, SamlMockCpResponse> sampleMap, String fileName) {
		try {
			// update response to be valid again
			var data = fileService.getMockResponseFile(fileName);
			StatusResponseType response = SamlIoUtil.unmarshallXmlFile(fileName, new ByteArrayInputStream(data));
			if (!allowedResponses.isInstance(response)) {
				log.debug("Ignoring response from file={} of class={} expected={}",
						fileName, response.getClass().getSimpleName(), allowedResponses.getSimpleName());
				return;
			}
			validateSAMLMockResponseSample(response, fileName);
			response.setIssueInstant(Instant.now());
			response.setInResponseTo(authnRequestId);

			StatusResponseType responseToEncrypt = SamlIoUtil.unmarshallXmlFile(fileName, new ByteArrayInputStream(data));
			var overrideDestination = keepSampleUrls ? response.getDestination() : null;
			var acsUrl = computeDestination(acsUrlFromInput, requestIssuer, overrideDestination, fileName);

			correctResponse(authnRequestId, fileName, response, acsUrl);
			correctResponse(authnRequestId, fileName, responseToEncrypt, acsUrl);

			// patch issuer references in response elements
			if (response instanceof Response authnResponse) {
				correctAssertion(authnRequestId, requestIssuer, acsUrl, keepSampleUrls, authnResponse);
				resignAllResponseElements(authnResponse);

				if (responseToEncrypt instanceof Response authnResponseToEncrypt) {
					correctAssertion(authnRequestId, requestIssuer, acsUrl, keepSampleUrls, authnResponseToEncrypt);

					reEncryptAssertions(authnResponseToEncrypt);
					resignStatusResponse(authnResponseToEncrypt, fileService.getResponseCredential());
				}
			}
			else {
				resignStatusResponse(response, null);
			}

			// marshal
			var encodedPostMessage = SamlUtil.encode(response);
			var encodedArtifactMessage = SamlIoUtil.encodeSamlArtifactData(velocityEngine,
					artifactCacheService.getArtifactMap(), response, buildArtifactResolutionParameters(), relayState);
			var encodedEncryptedResponse = SamlUtil.encode(responseToEncrypt);

			// provide to client for selection, they work for 1-2 minutes
			var cpResponse = new SamlMockCpResponse();
			cpResponse.setSamlPostResponse(encodedPostMessage);
			cpResponse.setSamlArtifactResponse(encodedArtifactMessage);
			cpResponse.setRelayState(relayState);
			cpResponse.setAcsUrl(response.getDestination());
			cpResponse.setSamlEncryptedResponse(encodedEncryptedResponse);
			sampleMap.put(fileName, cpResponse);
		}
		catch (TrustBrokerException e) {
			log.error("Could not parse file={} message={}", fileName, e.getInternalMessage(), e);
		}
		catch (RuntimeException ex) {
			log.error("Could not parse file={} message={}", fileName, ex.getMessage(), ex);
		}
	}

	private ArtifactResolutionParameters buildArtifactResolutionParameters() {
		return ArtifactResolutionParameters.of(properties.getArtifactResolutionServiceUrl(),
				SamlMockConstants.ENDPOINT_INDEX, properties.getArtifactResolutionIssuer());
	}

	private void reEncryptAssertions(Response authnResponseToEncrypt) {
		List<Assertion> assertions = new ArrayList<>(authnResponseToEncrypt.getAssertions());
		if (!CollectionUtils.isEmpty(assertions)) {
			authnResponseToEncrypt.getAssertions()
								  .clear();
			// re-encrypt all assertions
			for (Assertion assertion : assertions) {
				resignAssertion(assertion, fileService.getResponseCredential());
				EncryptedAssertion encryptedAssertion = getEncryptedAssertion(assertion, properties);
				addEncryptedAssertionToResponse(encryptedAssertion, authnResponseToEncrypt);
			}
		}
	}

	private static void correctResponse(String authnRequestId, String fileName, StatusResponseType response, String acsUrl) {
		validateSAMLMockResponseSample(response, fileName);
		response.setIssueInstant(Instant.now());
		response.setInResponseTo(authnRequestId);
		response.setDestination(acsUrl);
	}

	private static void correctAssertion(String authnRequestId, String requestIssuer, String acsUrl, boolean keepSampleUrls,
			Response authnResponse) {
		List<Assertion> assertions = authnResponse.getAssertions();
		if (!CollectionUtils.isEmpty(assertions)) {
			// make all assertions valid
			for (Assertion assertion : assertions) {
				assertion.setIssueInstant(Instant.now());
				setSubjectConfirmation(authnRequestId, assertion, acsUrl);
				if (!keepSampleUrls) {
					setAudience(requestIssuer, authnResponse);
				}
				updateConditionTimestamps(assertion);
				setAuthnStatement(assertion);
			}
		}
		// use own signer to make valid for caller
	}

	private static void addEncryptedAssertionToResponse(EncryptedAssertion encryptedAssertion, Response response) {
		if (encryptedAssertion != null) {
			response.getEncryptedAssertions()
					.add(encryptedAssertion);
		}
	}

	private EncryptedAssertion getEncryptedAssertion(Assertion assertion, SamlMockProperties properties) {
		if (properties.getEncryptionKeystore() != null && properties.getEncryptionPassword() != null &&
				properties.getDataEncryptionAlgorithm() != null && assertion != null) {
			return EncryptionUtil.encryptAssertion(assertion, fileService.getEncryptionCredential(),
					properties.getDataEncryptionAlgorithm(), properties.getKeyEncryptionAlgorithm(),
					Encrypter.KeyPlacement.valueOf(properties.getKeyPlacement()), "mock:issuer", properties.isEmitSki());
		}

		return null;
	}

	private void resignAllResponseElements(Response response) {
		var credential = fileService.getResponseCredential();
		// sign a random assertion - XTB should handle it correctly in any case
		var idToSign = pickRandomSignedAssertionId(response.getAssertions());
		for (Assertion assertion : response.getAssertions()) {
			if (idToSign.equals(assertion.getID())) {
				resignAssertion(assertion, credential);
				log.debug("Assertion signature updated: {}", assertion.getID());
			}
			else if (assertion.isSigned()) {
				// clear (invalid) signature
				assertion.setSignature(null);
				log.debug("Assertion signature removed: {}", assertion.getID());
			}
		}
		resignStatusResponse(response, credential);
	}

	private String pickRandomSignedAssertionId(List<Assertion> assertions) {
		var signedAssertions = assertions.stream()
				.filter(assertion -> assertion.getSignature() != null)
				.toList();
		if (signedAssertions.isEmpty()) {
			return "";
		}
		return signedAssertions.get(random.nextInt(signedAssertions.size()))
							   .getID();
	}

	// set destination either from config (if set) or keep the one in the message
	private String computeDestination(String acsUrlFromInput, String requestIssuer, String overrideDestination,
			String fileName) {
		var acsUrl = acsUrlFromInput;
		var acsUrlSrc = "AuthnRequest message";
		var acsUrlFromConfig = properties.getSamlPostTargetUrl();
		if (acsUrlFromConfig != null) {
			acsUrl = acsUrlFromConfig;
			acsUrlSrc = "samlPostTargetUrl config";
		}
		// the map is mainly for LogoutRequest, it does not override an existing ACS URL set above
		if (acsUrl == null) {
			var acsUrlMapFromConfig = properties.getSamlPostTargetUrlMap();
			if (acsUrlMapFromConfig != null) {
				var acsUrlFromMap = acsUrlMapFromConfig.get(requestIssuer);
				if (acsUrlFromMap != null) {
					acsUrl = acsUrlFromMap;
					acsUrlSrc = "samlPostTargetUrlMap config";
				}
			}
		}
		if (overrideDestination != null) {
			acsUrl = overrideDestination;
			acsUrlSrc = "Sample destination";
		}
		log.info("Patching destination in sample {} using acsUrl from {} resulting in {}", fileName, acsUrlSrc, acsUrl);
		return acsUrl;
	}

	// Mock should not check response validity as we want to be able to produce anything to send to XTB
	private static void validateSAMLMockResponseSample(StatusResponseType response, String sample) {
		if (response == null) {
			log.error("Response is null in file with name={}", sample);
			throw new TechnicalException(String.format("Response is null in file with name=%s", sample));
		}
	}

	private static void setAuthnStatement(Assertion assertion) {
		if (assertion.getAuthnStatements().isEmpty()) {
			return;
		}
		assertion.getAuthnStatements().get(0).setAuthnInstant(Instant.now());
		if (assertion.getAuthnStatements().get(0).getSessionNotOnOrAfter() != null) {
			assertion.getAuthnStatements().get(0)
					 .setSessionNotOnOrAfter(Instant.now().plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
		}
	}

	private static void updateConditionTimestamps(Assertion assertion) {
		if (assertion.getConditions() != null) {
			if (assertion.getConditions().getNotBefore() != null) {
				assertion.getConditions().setNotBefore(Instant.now());
			}
			if (assertion.getConditions().getNotOnOrAfter() != null) {
				assertion.getConditions().setNotOnOrAfter(Instant.now().plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
			}
		}
	}

	private static void setSubjectConfirmation(String authnRequestId, Assertion assertion, String issuer) {
		if (assertion == null) {
			return;
		}
		var subject = assertion.getSubject();
		List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
		if (!CollectionUtils.isEmpty(subjectConfirmations)) {
			var subjectConfirmationData = subjectConfirmations.get(0).getSubjectConfirmationData();
			if (subjectConfirmationData != null) {
				if (subjectConfirmationData.getNotBefore() != null) {
					subjectConfirmationData.setNotBefore(Instant.now());
				}
				subjectConfirmationData.setInResponseTo(authnRequestId);
				if (subjectConfirmationData.getNotOnOrAfter() != null) {
					subjectConfirmationData.setNotOnOrAfter(Instant.now().plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
				}
			}
			if (subjectConfirmationData != null && subjectConfirmationData.getRecipient() != null) {
				log.info("Updating SubjectConfirmation.Recipient from '{}' to '{}'",
						subjectConfirmationData.getRecipient(), issuer);
				subjectConfirmationData.setRecipient(issuer);
			}
		}
	}

	private static void setAudience(String audienceUri, Response authnResponse) {
		var assertions = authnResponse.getAssertions();
		if (CollectionUtils.isEmpty(assertions)) {
			return;
		}
		var conditions = assertions.get(0)
								   .getConditions();
		if (conditions == null) {
			return;
		}
		List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
		if (!CollectionUtils.isEmpty(audienceRestrictions)) {
			List<Audience> audiences = audienceRestrictions.get(0)
														   .getAudiences();
			if (!audiences.isEmpty() && audienceUri != null) {
				log.info("Updating subjectConfirmationData.AudienceURI from '{}' to '{}'", audiences.get(0).getURI(),
						audienceUri);
				audiences.clear();
				var audience = OpenSamlUtil.buildSamlObject(Audience.class);
				audience.setURI(audienceUri);
				audiences.add(audience);
			}
		}
	}

	private void resignAssertion(Assertion assertion, Credential credential) {
		if (assertion.getSignature() != null) {
			var newSignature = SamlFactory.prepareSignableObject(
					assertion, credential, null, null, null);
			SamlUtil.signSamlObject(assertion, newSignature, properties.getSkinnyAssertionNamespaces());
			if (log.isTraceEnabled()) {
				log.trace("Response assertion signed: {}", OpenSamlUtil.samlObjectToString(assertion));
			}
		}
	}

	private void resignStatusResponse(StatusResponseType response, Credential credential) {
		if (response.getSignature() != null) {
			if (credential == null) {
				credential = fileService.getResponseCredential();
			}
			var newSignature = SamlFactory.prepareSignableObject(
					response, credential, null, null, null);
			SamlUtil.signSamlObject(response, newSignature);
			if (log.isTraceEnabled()) {
				log.trace("Response signed: {}", OpenSamlUtil.samlObjectToString(response, false, true));
			}
		}
	}

	public void resignSamlObject(SignableSAMLObject request) {
		var newSignature = SamlFactory.prepareSignableObject(
				request, fileService.getAuthnRequestCredential(), null, null, null);
		SamlUtil.signSamlObject(request, newSignature);
		if (log.isTraceEnabled()) {
			log.trace("Request {} signed: {}", request.getClass().getSimpleName(),
					OpenSamlUtil.samlObjectToString(request, false, true));
		}
	}

	public SamlMockMessage<StatusResponseType> decodeAndValidateResponse(HttpServletRequest request) {
		var peer = buildArtifactPeer(false);
		var messageContext = decodeSamlMessage(request, peer);
		if (messageContext.getMessage() instanceof StatusResponseType samlResponse) {
			validateResponse(messageContext, samlResponse);
			var relayState = SAMLBindingSupport.getRelayState(messageContext);
			return new SamlMockMessage<>(samlResponse, relayState);
		}
		log.error("Invalid response type class={}", messageContext.getMessage().getClass().getName());
		throw new RequestDeniedException(String.format("Invalid response type class=%s",
				messageContext.getMessage().getClass().getName()));
	}

	public SamlMockMessage<RequestAbstractType> decodeRequest(HttpServletRequest request) {
		var peer = buildArtifactPeer(true);
		var messageContext = decodeSamlMessage(request, peer);
		if (messageContext.getMessage() instanceof RequestAbstractType samlRequest) {
			var relayState = SAMLBindingSupport.getRelayState(messageContext);
			return new SamlMockMessage<>(samlRequest, relayState);
		}
		log.error("Invalid request type class={}", messageContext.getMessage().getClass().getName());
		throw new RequestDeniedException(String.format("Invalid request type class=%s",
				messageContext.getMessage().getClass().getName()));
	}

	public MessageContext decodeSamlMessage(HttpServletRequest request, ArtifactPeer peer) {
		if (OpenSamlUtil.isSamlArtifactRequest(request)) {
			if (log.isInfoEnabled()) {
				log.info("Decoding received SAML Artifact={} peer={}",
						StringUtil.clean(SamlIoUtil.getSamlArtifactDataFromHttpProtocol(request)), peer);
			}
			// credential is always same side for SamlMock as the same issuerId is used for both sides
			var credential = properties.isArtifactResolutionIssuerIsRp() ?
					fileService.getAuthnRequestCredential() : fileService.getResponseCredential();
			var signatureParameters = Optional.of(SignatureParameters.builder()
																	 .credential(credential)
																	 .build());
			return OpenSamlUtil.decodeSamlArtifactMessage(request, properties.getArtifactResolutionIssuer(),
					peer, signatureParameters, SignatureValidationParameters.of(false, Collections.emptyList()),
					Optional.empty());
		}
		if (OpenSamlUtil.isSamlRedirectRequest(request)) {
			log.info("Decoding received SAML REDIRECT message");
			return OpenSamlUtil.decodeSamlRedirectMessage(request);
		}
		else {
			log.info("Decoding received SAML POST message");
			return OpenSamlUtil.decodeSamlPostMessage(request);
		}
	}

	public static void validateResponse(MessageContext messageContext, StatusResponseType samlResponse) {
		var relayState = messageContext.ensureSubcontext(SAMLBindingContext.class)
									   .getRelayState();
		var inResponseTo = samlResponse.getInResponseTo();
		var relayStateOk = relayState != null && relayState.startsWith(RELAY_STATE_PREFIX);
		var inResponseToOk = inResponseTo != null && inResponseTo.startsWith(AUTHN_REQUEST_ID_PREFIX);
		if (!relayStateOk) {
			log.error("Invalid response RelayState: {}", relayState);
		}
		if (!inResponseToOk) {
			log.error("Invalid response InResponseTo: {}", inResponseTo);
		}
		if (relayStateOk && inResponseToOk) {
			var relayStateId = relayState.substring(RELAY_STATE_PREFIX.length());
			var inResponseToId = inResponseTo.substring(AUTHN_REQUEST_ID_PREFIX.length());
			if (relayStateId.equals(inResponseToId)) {
				log.info("Response ID: {}, matching InResponseTo {}, RelayState: {}", samlResponse.getID(), inResponseTo,
						relayState);
			}
			else {
				log.error("Mismatch between RelayState {} and InResponseTo {}", relayState, inResponseTo);
			}
		}
	}

	private ArtifactPeer buildArtifactPeer(boolean rpSide) {
		return ArtifactPeer.builder()
						   .metadataUrl(properties.getMetadataUrl())
						   .artifactResolutionUrl(properties.getArpUrl())
						   .peerRole(rpSide ? SPSSODescriptor.DEFAULT_ELEMENT_NAME : IDPSSODescriptor.DEFAULT_ELEMENT_NAME)
						   .connectTimeout(Duration.ofSeconds(30))
						   .build();
	}

	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) throws IOException {
		var artifactResolve = SoapUtil.extractSamlObjectFromEnvelope(request.getInputStream(), ArtifactResolve.class);
		var artifactId = artifactResolve.getArtifact().getValue();
		log.info("Received ArtifactResolve with id={} from issuerId={} for artifact={}",
				artifactResolve.getID(), artifactResolve.getIssuer().getValue(), artifactId);

		var message = artifactCacheService.retrieveArtifact(artifactId);
		if (message.isPresent() && message.get() instanceof SignableSAMLObject samlObject && !samlObject.isSigned()) {
			resignSamlObject(samlObject);
		}
		var artifactResponse = SamlFactory.createArtifactResponse(
				artifactResolve, message, properties.getArtifactResolutionIssuer());
		resignSamlObject(artifactResponse);
		SoapUtil.sendSoap11Response(response, artifactResponse);
		artifactCacheService.removeArtifact(artifactId);
		log.info("Sent ArtifactResponse for artifact={}", artifactResolve.getArtifact());
	}

	public void cacheArtifact(HttpServletRequest request, HttpServletResponse response) {
		var messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
		var endpointUrl = calculateEndpoint(request, messageContext);
		var issuer = calculateIssuer(messageContext);
		var relayState = SAMLBindingSupport.getRelayState(messageContext);
		log.info("Received SAML POST message of type={} for endpoint={} relayState={} issuer={}",
				messageContext.getMessage().getClass().getName(), endpointUrl, relayState, issuer);
		var arParams = buildArtifactResolutionParameters();
		if (messageContext.getMessage() instanceof SAMLObject samlObject) {
			var context = OpenSamlUtil.createMessageContext(samlObject, null, endpointUrl, relayState);
			OpenSamlUtil.initAndEncodeSamlArtifactMessage(response, context, issuer, velocityEngine,
					arParams, artifactCacheService.getArtifactMap());
			log.info("Returned SAML artifact message with artifactIssuer={} to sender", properties.getArtifactResolutionIssuer());
		}
		else {
			log.error("Invalid artifact message type class={}", messageContext.getMessage().getClass().getName());
			throw new RequestDeniedException(String.format("Invalid message type class=%s",
					messageContext.getMessage().getClass().getName()));
		}
	}


	private static String calculateIssuer(MessageContext messageContext) {
		if (messageContext.getMessage() instanceof RequestAbstractType samlMessage) {
			return samlMessage.getIssuer().getValue();
		}
		if (messageContext.getMessage() instanceof StatusResponseType samlMessage) {
			return samlMessage.getIssuer().getValue();
		}
		log.error("Invalid message type class={}", messageContext.getMessage().getClass().getName());
		throw new RequestDeniedException(String.format("Invalid message type class=%s",
				messageContext.getMessage().getClass().getName()));
	}

	private static String calculateEndpoint(HttpServletRequest request, MessageContext messageContext) {
		var endpoint = OpenSamlUtil.getEndpoint(messageContext);
		var endpointUrl = WebUtil.getReferer(request);
		log.debug("Request referrerUrl={}", endpointUrl);
		if (endpoint != null) {
			endpointUrl = endpoint.getLocation();
			log.debug("Request endpointUrl={}", endpointUrl);
		}
		// endpoint is mandatory for the response, just use our URL if the calling test did not provide anything else
		if (endpointUrl == null) {
			endpointUrl = request.getRequestURI();
			log.debug("Request uri={}", endpointUrl);
		}
		return endpointUrl;
	}

}
