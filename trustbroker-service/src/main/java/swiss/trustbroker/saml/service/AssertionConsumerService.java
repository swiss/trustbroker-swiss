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

package swiss.trustbroker.saml.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.Banner;
import swiss.trustbroker.config.dto.GuiFeatures;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.saml.dto.UiBanner;
import swiss.trustbroker.saml.dto.UiDisableReason;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.dto.UiObjects;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.saml.util.SamlStatusCode;
import swiss.trustbroker.saml.util.SamlValidationUtil;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

@Service
@AllArgsConstructor
@Slf4j
public class AssertionConsumerService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	private final ScriptService scriptService;

	private final AuditService auditService;

	private final AnnouncementService announcementService;

	private final HrdService hrdService;

	private final QoaMappingService qoaMappingService;

	public CpResponse handleSuccessCpResponse(ResponseData<Response> responseData) {
		// message assertions
		var response = responseData.getResponse();
		OpenSamlUtil.checkResponseLimitations(response, "CP response processing");

		// session state
		var idpStateData = retrieveValidStateDataForResponse(responseData);

		// validation
		var responseIssuer = OpenSamlUtil.getMessageIssuerId(responseData.getResponse());
		var referrer = idpStateData.getReferer();
		var claimsParty = getClaimsPartyForResponseIssuer(responseIssuer, referrer, idpStateData.getIssuer());
		var decryptionCredentials = claimsParty.getCpDecryptionCredentials();
		var requireEncryptedAssertion = claimsParty.requireEncryptedAssertion();
		var responseAssertions = SamlUtil.getResponseAssertions(responseData.getResponse(), decryptionCredentials, requireEncryptedAssertion);
		validateResponse(true, responseData, idpStateData, claimsParty, responseAssertions);

		log.debug("CP response assertion validated");

		// internal processing context
		List<Definition> cpAttributeDefinitions = claimsParty.getAttributesDefinitions();
		var cpResponse = extractCpResponseDto(response, responseAssertions, cpAttributeDefinitions);
		// Known attributes from config as a default before we offer the opportunity to modify it in the CP/RP BeforeIdm scripts
		cpResponse.setHomeName(relyingPartySetupService.getHomeName(claimsParty, responseAssertions, cpResponse));
		return handleSuccessCpResponse(claimsParty, idpStateData, cpResponse, referrer, response);
	}

	// response is optional
	public CpResponse handleSuccessCpResponse(ClaimsParty claimsParty, StateData idpStateData,
			CpResponse cpResponse, String referrer, Response response) {
		// Make RP issuer available to scripts in case AfterIdm hooks need to have it as input
		cpResponse.setRpIssuer(idpStateData.getRpIssuer());
		var rpIssuer = idpStateData.getRpIssuer();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referrer);
		cpResponse.setClientName(relyingPartySetupService.getRpClientName(relyingParty));
		cpResponse.setCustomIssuer(trustBrokerProperties.getIssuer()); // allows to use it as input too
		// Defaults (OIDC does not set them)
		if (cpResponse.getOriginalNameId() == null) {
			cpResponse.setOriginalNameId(cpResponse.getNameId());
		}
		if (cpResponse.getNameIdFormat() == null) {
			cpResponse.setNameIdFormat(NameIDType.UNSPECIFIED);
		}
		// clear consumed OIDC nonce if set
		idpStateData.getSpStateData().setOidcNonce(null);

		// make some RpRequest related data available in response phase (why not the whole RPRequest object?)
		var rpStateData = idpStateData.getSpStateData();
		if (rpStateData != null) {
			cpResponse.setRpContext(rpStateData.getRpContext());
			cpResponse.setRpReferer(rpStateData.getReferer());
			cpResponse.setRpContextClasses(rpStateData.getContextClasses());
			// propagate applicationName and OIDC client_id for scripting
			cpResponse.setOidcClientId(rpStateData.getOidcClientId());
			cpResponse.setApplicationName(rpStateData.getApplicationName());
		}

		// Scripts BeforeIdm CP side
		scriptService.processCpBeforeIdm(cpResponse, response, claimsParty.getId(), referrer);

		// Original CpResponse before filtering the attributes
		cpResponse.setOriginalAttributes(new HashMap<>(cpResponse.getAttributes()));

		// Filter CP attributes
		var attributesDefinitions = claimsParty.getAttributesDefinitions();
		ResponseFactory.filterCpAttributes(cpResponse, attributesDefinitions, trustBrokerProperties.getSaml());

		var idmLookUp = relyingPartySetupService.getIdmLookUp(relyingParty);
		idmLookUp.ifPresent(idmLookup -> cpResponse.setIdmLookup(idmLookup.shallowClone()));

		//set clientExtId
		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(relyingParty));

		// mapping
		SubjectNameMapper.adjustSubjectNameId(cpResponse, claimsParty);

		// scripts BeforeIdm RP side (see test DeriveClaimProviderNameFromNameIdFormat.groovy for an example to derive HomeName)
		scriptService.processRpBeforeIdm(cpResponse, response, rpIssuer, referrer);

		// session for SSO
		idpStateData.setCpResponse(cpResponse);
		stateCacheService.save(idpStateData, this.getClass().getSimpleName());

		return cpResponse;
	}

	public CpResponse handleFailedCpResponse(ResponseData<Response> responseData) {
		// message assertions
		OpenSamlUtil.checkResponsePresent(responseData.getResponse(), "CP failed response processing");

		// session state
		var idpStateData = retrieveValidStateDataForResponse(responseData);

		// validation
		var cpResponse = validateAndGetCpResponse(responseData, idpStateData);

		return handleFailedCpResponse(responseData, idpStateData, cpResponse);
	}

	public CpResponse handleFailedCpResponse(ResponseData<Response> responseData, StateData idpStateData, CpResponse cpResponse) {
			// take over displaying stuff
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				idpStateData.getRpIssuer(),
				idpStateData.getRpReferer());
		var flows = relyingParty.getFlows();
		log.debug("Checking {} FlowPolicies of rpIssuerId={}", flows.size(), relyingParty.getId());
		for (var flowPolicy : flows) {
			var samlCode = SamlStatusCode.addNamespace(trustBrokerProperties.getSaml(),
					flowPolicy.getId(), flowPolicy.getNamespacePrefix());
			if (handleResponderErrors(responseData.getResponse(), StatusCode.RESPONDER, samlCode, trustBrokerProperties)) {
				log.debug("Responder error handled according to flowPolicy={}", flowPolicy);
				if (flowPolicy.showErrorPage()) {
					cpResponse.abort(StatusCode.RESPONDER, flowPolicy);
					// state still required for interactive error handling / showing support page details
					return cpResponse;
				}
			}
		}
		return cpResponse;
	}

	static boolean handleResponderErrors(Response response,
			String requiredStatus, String requiredNestedStatus, TrustBrokerProperties trustBrokerProperties) {
		var featureEnabled = trustBrokerProperties.isHandleResponderErrors();
		var statusCode = OpenSamlUtil.getStatusCode(response);
		var nestedStatusCode = OpenSamlUtil.getNestedStatusCode(response);
		var statusMessage = OpenSamlUtil.getStatusMessage(response);
		var result = featureEnabled &&
				(requiredStatus == null || requiredStatus.equals(statusCode)) &&
				((nestedStatusCode != null && nestedStatusCode.equals(requiredNestedStatus)) ||
						(statusMessage != null && statusMessage.equals(requiredNestedStatus)));
		log.debug("Deciding responder display: featureEnabled={} requiredStatus={} requiredNestedStatus={} statusCode={} "
						+ "statusMessage={} nestedStatusCode={} result={}",
				featureEnabled, requiredStatus, requiredNestedStatus, statusCode, statusMessage, nestedStatusCode, result);
		return result;
	}

	private StateData retrieveValidStateDataForResponse(ResponseData<Response> responseData) {
		var relayState = responseData.getRelayState();
		SamlValidationUtil.validateRelayState(responseData);
		var idpStateData = stateCacheService.find(relayState, this.getClass().getSimpleName());
		AssertionValidator.validCpSession(idpStateData);
		return idpStateData;
	}

	private void validateResponse(boolean expectSuccess, ResponseData<Response> responseData, StateData idpStateData,
			ClaimsParty claimsParty, List<Assertion> responseAssertions) {
		var expectedIssuer = idpStateData.getIssuer();
		if (claimsParty.getId().equals(expectedIssuer)) {
			expectedIssuer = claimsParty.getResponseIssuer();
		}
		validateBinding(claimsParty, responseData.getBinding(), idpStateData.getRequestedResponseBinding());
		var existingRelayState = idpStateData.getRelayState();
		List<Credential> claimTrustCred = claimsParty.getCpTrustCredential();
		var expectedAudienceId = claimsParty.getAuthnRequestIssuerId();
		var spStateData = idpStateData.getSpStateData();
		var rpQoa = getRpQoa(idpStateData, spStateData);

		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer(expectedIssuer)
				.expectedAudience(expectedAudienceId)
				.expectSuccess(expectSuccess)
				.expectedRelayState(existingRelayState)
				.expectedCpComparison(idpStateData.getComparisonType())
				.expectedCpContextClasses(idpStateData.getContextClasses())
				.expectedRpId(spStateData.getOidcClientId() != null ?
						spStateData.getOidcClientId() : idpStateData.getRpIssuer())
				.build();

		AssertionValidator.validateResponse(responseData, responseAssertions, claimTrustCred,
				trustBrokerProperties, claimsParty, rpQoa, expectedValues);
	}

	private Qoa getRpQoa(StateData idpStateData, StateData spStateData) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				idpStateData.getRpIssuer(), null);
		var rpQoa = qoaMappingService.getQoaConfiguration(spStateData, relyingParty);
		return rpQoa != null ? rpQoa.config() : null;
	}

	private static void validateBinding(ClaimsParty claimsParty, SamlBinding actualBinding,
			SamlBinding requestedResponseBinding) {
		if (!claimsParty.isValidInboundBinding(actualBinding)) {
			throw new RequestDeniedException(String.format("ClaimsParty cpIssuerId=%s does not support inbound binding=%s",
					claimsParty.getId(), actualBinding));
		}
		if (!actualBinding.compatibleWithRequestedBinding(requestedResponseBinding)) {
			throw new RequestDeniedException(
					String.format("ClaimsParty cpIssuerId=%s responded with binding=%s instead of requested protocolBinding=%s",
							claimsParty.getId(), actualBinding, requestedResponseBinding));
		}
	}

	private static CpResponse extractCpResponseDto(Response response, List<Assertion> assertions,
			List<Definition> cpAttributeDefinitions) {
		var cpResponse = new CpResponse();

		// assertions input (actually only one, we throw an exception if list.size > 1 before)
		// for multiple assertions we would need to also support that on the CpResponse to prevent losing data
		for (Assertion assertion : assertions) {

			// Subject
			extractSubjectAttributes(cpResponse, assertion);

			// AuthnStatement
			List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
			if (!authnStatements.isEmpty() && authnStatements.get(0).getAuthnContext() != null) {
				cpResponse.setContextClasses(getContextClassRefsFromStatement(authnStatements));
			}

			// AttributeStatements
			if (CollectionUtils.isEmpty(assertion.getAttributeStatements())) {
				log.debug("Ignoring AttributeStatements={}", assertion.getAttributeStatements());
				continue;
			}
			List<Attribute> assertionAttributes = assertion.getAttributeStatements().get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				var values = SamlUtil.getValuesFromAttribute(attribute);
				if (namespaceUri == null || values.isEmpty()) {
					log.debug("Ignoring namespaceUri={} value={}", namespaceUri, values);
					continue;
				}
				var def = DefinitionUtil.findSingleValueByNameOrNamespace(namespaceUri, null, cpAttributeDefinitions);
				// Fallback necessary only for OriginalAttributes
				var definition = def.orElseGet(() -> Definition.ofNameAndSource(namespaceUri, ClaimSource.CP.name()));
				cpResponse.setAttributes(definition, values); // free to be processed afterward
				if (CoreAttributeName.AUTH_LEVEL.getNamespaceUri().equals(namespaceUri)) {
					cpResponse.setAuthLevel(values.get(0));
					log.debug("Got authLevel={} from cpIssuer={}", cpResponse.getAuthLevel(),
							OpenSamlUtil.getMessageIssuerId(response));
				}
			}

		}

		// all the rest from CP
		cpResponse.setInResponseTo(response.getInResponseTo());
		cpResponse.setIssuer(OpenSamlUtil.getMessageIssuerId(response));
		cpResponse.setDestination(response.getDestination());

		// just in case, should already have been done via state
		TraceSupport.switchToConversationFromSamlId(response.getInResponseTo());

		return cpResponse;
	}

	private static List<String> getContextClassRefsFromStatement(List<AuthnStatement> authnStatements) {
		var authnContextClassRef = authnStatements.get(0).getAuthnContext().getAuthnContextClassRef();
		return authnContextClassRef != null && authnContextClassRef.getURI() != null ?
				List.of(authnContextClassRef.getURI()) : Collections.emptyList();
	}

	private static void extractSubjectAttributes(CpResponse cpResponse, Assertion assertion) {
		if (assertion == null || assertion.getSubject() == null) {
			if (log.isDebugEnabled()) {
				log.debug("Assertion={} Subject=null ignored, not mapping subject data",
						OpenSamlUtil.samlObjectToString(assertion, true));
			}
			return;
		}

		// map subject to CpResponse bean, so we can access data in scripting
		// NOTE: This also makes the name identifier SAML attribute available on OIDC side
		var subject = assertion.getSubject();
		var nameId = subject.getNameID().getValue();
		cpResponse.setNameId(nameId);
		cpResponse.setOriginalNameId(nameId);
		cpResponse.setNameIdFormat(SamlUtil.getAssertionNameIDFormat(assertion));
		cpResponse.setAttribute(CoreAttributeName.NAME_ID.getName(), CoreAttributeName.NAME_ID.getNamespaceUri(), nameId);
		if (CollectionUtils.isNotEmpty(subject.getSubjectConfirmations())) {
			cpResponse.setSubjectConfirmationMethod(subject.getSubjectConfirmations().get(0).getMethod());
		}
	}

	public RpRequest handleRpAuthnRequest(AuthnRequest authnRequest, HttpServletRequest httpRequest, StateData stateData) {
		if (authnRequest == null) {
			throw new RequestDeniedException("RP AuthnRequest is missing!");
		}

		// UI dispatch
		var rpIssuer = OpenSamlUtil.getMessageIssuerId(authnRequest);
		var applicationName = authnRequest.getProviderName();
		var result = createUiObjects(rpIssuer, authnRequest.getID(), applicationName, httpRequest, stateData);

		// track RPs
		auditAuthnRequestFromRp(authnRequest, httpRequest, stateData);

		// hook to validate the SAML directly (cannot be done in BeforeHrd because eof device redirects
		scriptService.processRequestValidation(result, authnRequest);

		return result;
	}

	private void auditAuthnRequestFromRp(AuthnRequest authnRequest, HttpServletRequest request, StateData stateData) {
		var relyingParty = relyingPartySetupService
				.getRelyingPartyByIssuerIdOrReferrer(OpenSamlUtil.getMessageIssuerId(authnRequest), null, true);
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(authnRequest)
				.mapFrom(request)
				.mapFrom(relyingParty)
				.build();
		auditDto.setSide(DestinationType.RP.getLabel());
		auditService.logInboundFlow(auditDto);
	}

	private RpRequest createUiObjects(String rpIssuer, String requestId, String applicationName,
									  HttpServletRequest httpRequest, StateData stateData) {
		var referer = WebUtil.getReferer(httpRequest);
		return renderUi(rpIssuer, referer, applicationName, httpRequest, requestId, stateData);
	}

	// This method decides what we have in the SAML POST form target. Priorities:
	// AuthnRequest.AssertionConsumerServiceUrl:
	// - Incoming AuthnRequest.AssertionConsumerServiceUrl (authorized against ACWhitelist in AssertionValidator)
	// - Best matching entry from ACWhitelist when the AuthnRequest just contains an Issuer ID
	// Note that in CpResponse this can be overridden:
	// - CpResponse.rpDestination for the SAMl Response.Destination
	// - CpResponse.rpRecipient for the Assertion.SubjectConfirmationData.Recipient
	// HTTP Header:
	// - HTTP Referer is best matched against RP ACWhitelist picking first entry that contains the Referer value
	// - HTTP Origin was dropped because we actually never used it anywhere an ambiguity hurts here
	String getAssertionConsumerServiceUrl(final String consumerUrl,
			final String referer, final String origin, RelyingParty relyingParty) {
		var acWhitelist = relyingParty != null && relyingParty.getAcWhitelist() != null ?
				relyingParty.getAcWhitelist() : new AcWhitelist(new ArrayList<>());

		var rpIssuer = relyingParty != null ? relyingParty.getId() : null;
		if (log.isDebugEnabled()) {
			log.debug("Checking AuthRequest from rpIssuer={} with consumerUrl={} referer={} origin={} against ACWhitelist={}",
					rpIssuer, consumerUrl, referer, origin, CollectionUtil.toLogString(acWhitelist.getAcUrls()));
		}

		//  may be signed AuthnRequest
		Optional<String> consumer;
		// use default?
		if (consumerUrl == null) {
			consumer = acWhitelist.getDefault();
			log.debug("rpIssuerId={} did not send an ACS URL - using default={}", rpIssuer, consumer.orElse(null));
		}
		else {
			consumer = acWhitelist.findFirst(String::equals, consumerUrl);
		}

		// internal AuthnRequest for monitoring
		if (consumer.isEmpty() && consumerUrl != null && consumerUrl.startsWith(ApiSupport.MONITORING_ACS_URL)) {
			consumer = Optional.of(ApiSupport.MONITORING_ACS_URL);
		}

		// unsigned HTTP headers
		if (consumer.isEmpty() && referer != null) {
			consumer = acWhitelist.findFirst(String::startsWith, referer);
		}
		if (consumer.isEmpty() && origin != null) {
			consumer = acWhitelist.findFirst(String::startsWith, origin);
		}

		// block
		if (consumer.isEmpty()) {
			if (!trustBrokerProperties.getSecurity().isValidateAcs()) {
				log.warn("trustbroker.config.security.validateAcs=false: Accepting AssertionConsumerServiceUrl={} "
								+ " httpReferer={} and origin={} not having a match in ACWhitelist ACWhitelist={} for rpIssuer={}",
						consumerUrl, referer, origin, CollectionUtil.toLogString(acWhitelist.getAcUrls()), rpIssuer);
				return consumerUrl;
			}
			throw new RequestDeniedException(String.format("Got a SAML message with AssertionConsumerServiceUrl=%s "
							+ "httpReferer=%s and origin=%s not having a match in ACWhitelist ACWhitelist=%s."
							+ " Please add an entry to rpIssuer=%s and in case referer is null fix RP to send it or an ACSUrl "
							+ "instead.",
					consumerUrl, referer, origin, CollectionUtil.toLogString(acWhitelist.getAcUrls()), rpIssuer));
		}

		return consumer.get();
	}

	// In the discontinued stealth mode we also needed to save this state as well to be able to analyse the SAMLResponse
	public StateData saveState(AuthnRequest authnRequest, boolean signatureValidated, HttpServletRequest request,
			RelyingParty relyingParty, Optional<StateData> ssoState, SamlBinding requestBinding) {
		// without a consumer URL we at least need something from the config
		var referer = WebUtil.getReferer(request);
		var rpIssuer = WebUtil.getOrigin(request);
		var ascUrl = getAssertionConsumerServiceUrl(
				authnRequest.getAssertionConsumerServiceURL(), referer, rpIssuer, relyingParty);

		// RP using relay state?
		var spRelayState = request.getParameter(SamlIoUtil.SAML_RELAY_STATE);
		if (log.isDebugEnabled()) {
			log.debug("Inbound SP RelayState: {}", StringUtil.clean(spRelayState));
		}

		// incoming AuthnRequest.ID initially used as session ID
		var authnRequestId = authnRequest.getID();
		SamlUtil.validateSessionId(authnRequestId, "AuthnRequestID used as SP state ID");

		// remember RP for AuthnRequest/response exchange OR as initiator for SSO
		var rpContexts = WebSupport.getHttpContext(request, trustBrokerProperties.getNetwork());

		var qoa = qoaMappingService.getQoaConfiguration(authnRequest.getProviderName(), referer, relyingParty);
		var dropQoa = qoa != null ? qoa.replaceInboundQoas() : Boolean.FALSE;
		var contextClasses = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest, dropQoa, QoaMappingUtil.getReplacementAcClasses(qoa));
		var comparisonType = OpenSamlUtil.extractAuthnRequestComparison(authnRequest);
		var qoaComparisonType = QoaComparison.ofLowerCase(comparisonType != null ? comparisonType.toString() : null);

		var providerName = authnRequest.getProviderName();
		var hrdHint = OpenSamlUtil.extractIdpScoping(authnRequest);

		// support overriding providerName with configured applicationName to resolve problems inconsitent setups
		if (relyingParty.getApplicationName() != null) {
			log.debug("Apply configured applicationName={} overriding providerName={}",
					relyingParty.getApplicationName(), providerName);
			providerName = relyingParty.getApplicationName();
		}

		// support correlation with OIDC invocation in scripts too on SAML side (if login was trigger by client_id)
		var oidcClientId = OidcSessionSupport.getSamlExchangeAcsUrlClientId(ascUrl);
		var conversationId = TraceSupport.switchToConversationFromSamlId(authnRequestId);
		var requestedResponseBinding = SamlBinding.of(authnRequest.getProtocolBinding());

		// sp state data
		var spStateData = StateData.builder().id(authnRequestId)
								   .lastConversationId(conversationId) // from SAML POST peer, if coming from us
								   .issuer(OpenSamlUtil.getMessageIssuerId(authnRequest))
								   .referer(referer)
								   .rpContext(rpContexts)
								   .relayState(spRelayState)
								   .contextClasses(contextClasses)
								   .comparisonType(qoaComparisonType)
								   .assertionConsumerServiceUrl(ascUrl)
								   .applicationName(providerName)
								   .oidcClientId(oidcClientId)
								   .issueInstant(authnRequest.getIssueInstant().toString())
								   .requestBinding(requestBinding)
								   .requestedResponseBinding(requestedResponseBinding)
								   .hrdHint(hrdHint)
								   .build();

		StateData stateData;
		if (ssoState.isEmpty()) {
			var relayState = SamlUtil.generateRelayState();
			// using relay state as state ID (must surely be a valid ID)
			SamlUtil.validateSessionId(relayState, "XTB relay state used as session ID");
			stateData = StateData.builder()
								 .id(relayState)
								 .relayState(relayState)
								 .build();
			log.debug("No SSO or no SSO state yet, created new one: {}", relayState);
		}
		else {
			stateData = ssoState.get();
			log.debug("Using existing SSO state {}", stateData.getId());
		}

		// refresh on sessiondb
		stateData.setSpStateData(spStateData);

		// Keep the following in sync with SsoService.copyToSsoStateAndInvalidateAuthnRequestState
		stateData.setLastConversationId(spStateData.getLastConversationId()); // conversation the same for CP and RP side
		// RP side default is false, so CPs can override the global default:
		stateData.setForceAuthn(OpenSamlUtil.isForceAuthnRequest(authnRequest) || relyingParty.forceAuthn(false));
		stateData.setSignedAuthnRequest(signatureValidated);

		stateCacheService.save(stateData, this.getClass().getSimpleName());
		return stateData;
	}

	private static Map<String, String> getRpContext(StateData stateData) {
		Map<String, String> rpContext = new HashMap<>();
		if (stateData != null) {
			rpContext.putAll(stateData.getSpStateData() != null ?
					stateData.getSpStateData().getRpContext() : stateData.getRpContext());
		}
		return rpContext;
	}

	// The CP list is influenced by the following resolution:
	// - SetupRP.xml containing a direct mapping of 1 to n CPs
	// - Check against Client_Network header to support silent routing in case of 1:1 mapping with INTRANET or INTERNET
	// - Check HRD hint parameter/header/cookie to directly identify a CP, so we skip the HRD screen
	public RpRequest getRpRequestDetails(
			String rpIssuer, String referer, String applicationName,
			HttpServletRequest request, String requestId, StateData stateData) {
		// output
		List<ClaimsProvider> cpMappings = new ArrayList<>();

		// request mapping towards processing
		var rpRequest = RpRequest.builder()
				.claimsProviders(cpMappings) // pass on per request handling copy, uiObjects stay empty (render later)
				.rpIssuer(rpIssuer)
				.requestId(requestId)
				.referer(referer)
				.contextClasses(QoaMappingUtil.getRpContextClasses(stateData))
				.applicationName(applicationName)
				.context(getRpContext(stateData)) // RP initiated internal state
				.build();

		// pre-conditions
		if (StringUtils.isEmpty(rpIssuer) && StringUtils.isEmpty(referer)) {
			log.warn("Cannot derive RP setup without any input data");
			return rpRequest;
		}

		// SetupRp.xml directly
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referer);
		if (relyingParty != null && relyingParty.getClaimsProviderMappings() != null &&
				relyingParty.getClaimsProviderMappings().getClaimsProviderList() != null) {
			log.debug("Found {} entries for rpIssuer='{}' and referrer='{}' in SetupRP",
					cpMappings.size(), rpIssuer, referer);
			cpMappings.addAll(relyingParty.getClaimsProviderMappings().getClaimsProviderList());
		}

		// we should have something now
		if (cpMappings.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Missing SetupRP.xml/*/ClaimsProviderMappings entries for rpIssuer='%s' referrer='%s' (cannot dispatch CP)",
					rpIssuer, referer));
		}

		// apply HRD hint, overrides network and any other selection, so we can simulate INTRANET even if only on INTERNET
		var cpSelectionHint = HrdSupport.getClaimsProviderHint(request, trustBrokerProperties);
		if (cpSelectionHint == null && stateData != null) {
			cpSelectionHint = stateData.getRpHrdHint();
		}

		// Allow script to override manipulate cpMappings before we do it internally
		scriptService.processHrdSelection(rpRequest);

		// throw out all CPs not valid for current network, cookies, ....
		cpMappings = new ArrayList<>(rpRequest.getClaimsProviders()); // in case script has constructed a new (immutable) list
		cpMappings = HrdSupport.reduceClaimsProviderMappings(request, rpIssuer, applicationName,
				cpSelectionHint, cpMappings, trustBrokerProperties, hrdService);
		rpRequest.setClaimsProviders(cpMappings); // because our own reduction logic also might create a new list

		// If groovy script manipulates the classrefs we need dto make sure that this gets persisted
		updateSpStateDataOnHrdChanges(stateData, rpRequest);

		return rpRequest;
	}

	private void updateSpStateDataOnHrdChanges(StateData stateData, RpRequest rpRequest) {
		if (stateData != null && stateData.getSpStateData() != null) {
			var spStateDate = stateData.getSpStateData();
			// improve and store RpRequest instead of partial fields only
			var changed = !CollectionUtils.isEqualCollection(stateData.getRpContextClasses(), rpRequest.getContextClasses());
			changed = changed || !spStateDate.getRpContext().equals(rpRequest.getContext()); // works for String values
			if (changed) {
				spStateDate.setContextClasses(rpRequest.getContextClasses());
				spStateDate.setComparisonType(rpRequest.getComparisonType());
				spStateDate.getRpContext().putAll(rpRequest.getContext());
				stateCacheService.save(stateData, this.getClass().getSimpleName());
			}
		}
	}

	// Show HRD screen when we have multiple CPs
	public RpRequest renderUi(String rpIssuer, String referer, String applicationName,
							  HttpServletRequest httpRequest, String requestId, StateData stateData) {
		var rpRequest = getRpRequestDetails(rpIssuer, referer, applicationName, httpRequest, requestId, stateData);
		var uiObjects = new UiObjects();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referer);

		var globalDisabledAppNames = getGlobalDisabledAppNames(relyingParty, httpRequest, rpRequest);

		var hrdBanners = trustBrokerProperties.getGui().hasFeature(GuiFeatures.HRD_BANNERS);
		var enrichedClaimsProviders = enrichClaimsProviders(rpRequest.getClaimsProviders(), relyingParty, referer, stateData,
				globalDisabledAppNames);
		var displayedClaimsProviders = filterDisplayedClaimsProviders(requestId, enrichedClaimsProviders);
		displayedClaimsProviders.forEach(
						mapping -> {
							uiObjects.addTile(
									createUiElement(mapping.getLeft(), mapping.getRight(), hrdBanners));
							uiObjects.addBanner(
									createBanner(mapping.getLeft(), hrdBanners));
		});
		if (hrdBanners) {
			// global banners
			trustBrokerProperties.getGui().getBanners().stream()
					.filter(Banner::isGlobal)
					.forEach(
							globalBanner -> uiObjects.addBanner(createBannerFromConfig(globalBanner, null))
					);
		}
		uiObjects.setBanners(orderAndLimitBanners(uiObjects.getBanners(), trustBrokerProperties.getGui().getMaxBanners()));
		uiObjects.setTiles(orderUiObjects(uiObjects.getTiles()));
		rpRequest.setUiObjects(uiObjects);

		log.debug("HRD final selecting uiObjects='{}'", uiObjects);
		return rpRequest;
	}

	private List<Pair<ClaimsProvider, UiDisableReason>> enrichClaimsProviders(List<ClaimsProvider> claimsProviders,
			RelyingParty relyingParty, String referer, StateData stateData, ArrayList<String> globalDisabledAppNames) {
		return claimsProviders
				.stream()
				.map(mapping -> checkCpEnabled(mapping, relyingParty, referer, stateData, globalDisabledAppNames))
				.toList();
	}

	private Pair<ClaimsProvider, UiDisableReason> checkCpEnabled(ClaimsProvider mapping,
			RelyingParty relyingParty, String referer, StateData stateData, ArrayList<String> globalDisabledAppNames) {
		var spStateData = stateData != null ? stateData.getSpStateData() : null;
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(mapping.getId(), referer);
		var rpQoaConfig = qoaMappingService.getQoaConfiguration(spStateData, relyingParty);
		var cpCanFulfillQoa = qoaMappingService.canCpFulfillRequestQoas(
				QoaMappingUtil.getRpComparison(stateData),
				QoaMappingUtil.getRpContextClasses(stateData),
				rpQoaConfig, claimsParty.getQoaConfig());
		var disabled = cpDisabled(mapping.getId(), globalDisabledAppNames, cpCanFulfillQoa);
		return Pair.of(mapping, disabled);
	}

	static List<Pair<ClaimsProvider, UiDisableReason>> filterDisplayedClaimsProviders(String requestId,
			List<Pair<ClaimsProvider, UiDisableReason>> claimsProviders) {
		var displayedClaimsProviders = claimsProviders
				.stream()
				.filter(claimsProvider -> claimsProvider.getLeft().isDisplayed())
				.toList();
		if (!displayedClaimsProviders.isEmpty()) {
			return displayedClaimsProviders;
		}
		var cpIds = claimsProviders
				.stream()
				.map(claimsProvider -> claimsProvider.getLeft().getId())
				.toList();
		var maxOrderCp = claimsProviders
				.stream()
				.filter(claimsProvider -> claimsProvider.getRight() == null)
				// not displayed => orders not null:
				.max(Comparator.comparing(claimsProvider -> claimsProvider.getLeft().getOrder()));
		if (maxOrderCp.isEmpty()) {
			log.info("All CPs are hidden and disabled - returning cpIssuerIds={}", cpIds);
			return claimsProviders;
		}
		log.info("All cpIssuerIds={} are hidden, picked cpIssuerId={} with maximum negative order={} for authnRequestId={}",
				cpIds, maxOrderCp.get().getLeft().getId(), maxOrderCp.get().getLeft().getOrder(), requestId);
		return List.of(maxOrderCp.get());
	}

	// sort by order and restrict
	static List<UiBanner> orderAndLimitBanners(List<UiBanner> banners, Integer bannerLimit) {
		if (bannerLimit == null) {
			bannerLimit = Integer.MAX_VALUE;
		}
		return banners.stream()
				.sorted(Comparator.comparing(AssertionConsumerService::orderBanners))
				.limit(bannerLimit)
				.toList();
	}

	static List<UiObject> orderUiObjects(List<UiObject> uiObjects) {
		return uiObjects.stream()
				.sorted(Comparator.comparingInt(UiObject::getOrderWithDefault))
				.toList();
	}

	private static Integer orderBanners(UiBanner banner) {
		var order = banner.getOrder();
		return order != null ? order : Integer.MAX_VALUE;
	}

	private ArrayList<String> getGlobalDisabledAppNames(RelyingParty relyingParty, HttpServletRequest httpRequest,
			RpRequest rpRequest) {
		var skipUserFeatures = OperationalUtil.skipUserFeatures(rpRequest, httpRequest, trustBrokerProperties); // skip
		// disabling
		var globalAnnouncements = new ArrayList<String>();
		if (announcementService.showAnnouncements(relyingParty.getAnnouncement(), rpRequest.getApplicationName(), rpRequest.featureConditionSet()) && !skipUserFeatures) {
			for (Announcement announcement : announcementService.getGlobalAnnouncements()) {
				if (announcement.getApplicationAccessible() != null && !announcement.getApplicationAccessible()) {
					globalAnnouncements.add(getGlobalAppName(announcement.getApplicationName()));
				}
			}
		}
		return globalAnnouncements;
	}

	private static String getGlobalAppName(String applicationName) {
		if (applicationName == null) {
			return "None";
		}
		String[] appNameElements = applicationName.split("-");
		int length = appNameElements.length;
		return appNameElements[length - 1];
	}

	private static String getTileDescription(ClaimsProvider claimsProvider) {
		var desc = claimsProvider.getDescription();
		if (desc == null) {
			desc = claimsProvider.getName();
		}
		if (desc == null) {
			desc = claimsProvider.getId();
		}
		return desc;
	}

	private static String getTileTitle(ClaimsProvider claimsProvider) {
		var title = claimsProvider.getTitle();
		if (title != null) {
			title = claimsProvider.getName();
		}
		if (title == null) {
			title = claimsProvider.getId();
		}
		return title;
	}

	// UI data for the frontend
	private static UiObject createUiElement(ClaimsProvider claimsProvider, UiDisableReason disableReason, boolean hrdBanners) {
		var uiObject = new UiObject();
		uiObject.setUrn(claimsProvider.getId());

		// banner signals HRDv2
		if (hrdBanners) {
			uiObject.setOrder(claimsProvider.getOrder());
		}

		// key into translation service or fallback for titles
		uiObject.setName(claimsProvider.getName());

		// tile
		uiObject.setImage(claimsProvider.getImg());
		uiObject.setTitle(getTileTitle(claimsProvider));
		uiObject.setDescription(getTileDescription(claimsProvider));
		uiObject.setDisabled(disableReason);

		// small screen
		uiObject.setShortcut(claimsProvider.getShortcut());
		uiObject.setColor(claimsProvider.getColor());

		return uiObject;
	}

	// Banner for the frontend
	private UiBanner createBanner(ClaimsProvider claimsProvider, boolean hrdBanners) {
		if (!hrdBanners) {
			return null;
		}
		var bannerOpt = trustBrokerProperties.getGui().getBanner(claimsProvider.getBanner());
		return bannerOpt
				.map(banner -> createBannerFromConfig(banner, claimsProvider.getOrder()))
				.orElse(null);
	}

	static UiBanner createBannerFromConfig(Banner banner, Integer order) {
		return UiBanner.builder()
					   .name(banner.getName())
					   .mainImage(banner.getMainImage())
					   .secondaryImages(banner.getSecondaryImages())
					   .collapseParagraphs(banner.collapseParagraphs())
					   .order(order != null ? order : banner.getOrder())
					   .build();
	}

	private static UiDisableReason cpDisabled(String id, ArrayList<String> globalDisabledAppNames, boolean cpCanFulfillQoa) {
		if (!cpCanFulfillQoa) {
			return UiDisableReason.INSUFFICIENT;
		}
		if (globalDisabledAppNames.isEmpty()) {
			return null;
		}
		for (String announcementId : globalDisabledAppNames) {
			if (removeIdSpecChar(id).contains(announcementId.toUpperCase())) {
				return UiDisableReason.UNAVAILABLE;
			}
		}
		return null;
	}

	private static String removeIdSpecChar(String id) {
		return id.replace("-", "").toUpperCase();
	}

	public AssertionValidator.MessageValidationResult validateAuthnRequest(AuthnRequest authnRequest, HttpServletRequest request,
			SignatureContext signatureContext, SecurityPolicies securityPolicies) {
		// pre conditions
		if (authnRequest == null) {
			throw new RequestDeniedException("RP AuthnRequest is missing!");
		}

		// validation
		if (trustBrokerProperties.getSecurity().isValidateAuthnRequest()) {
			var issuer = OpenSamlUtil.getMessageIssuerId(authnRequest);
			var referer = WebUtil.getReferer(request);
			var origin = WebUtil.getOrigin(request);
			var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(issuer, referer);
			validateRefererAndOrigin(authnRequest, relyingParty, referer, origin);
			var trustCredentials = relyingParty.getRpTrustCredentials();
			var acWhiteList = relyingParty.getAcWhitelist();
			var providerName = authnRequest.getProviderName();
			var rpQoa = qoaMappingService.getQoaConfiguration(providerName, referer, relyingParty);
			return AssertionValidator.validateAuthnRequest(authnRequest, trustCredentials, acWhiteList, trustBrokerProperties,
					securityPolicies, signatureContext, rpQoa);
		}
		else {
			log.error("trustbroker.config.security.validateAuthnRequest=false: Security on AuthnRequest disabled!!!");
			return AssertionValidator.MessageValidationResult.unvalidated();
		}
	}

	private void validateRefererAndOrigin(AuthnRequest authnRequest, RelyingParty relyingParty, String referer, String origin) {
		if (!relyingParty.validateHttpHeaders(trustBrokerProperties.getSecurity().isValidateHttpHeaders())) {
			log.debug("Skipping validation of referer={} and origin={} for rpIssuerId={} for authnRequestId={}",
					StringUtil.clean(referer), StringUtil.clean(origin), relyingParty.getId(), authnRequest.getID());
			return;
		}
		var perimeterUrls = WebSupport.getOwnOrigins(trustBrokerProperties);
		List<Collection<String>> allowedUrls = List.of(perimeterUrls, relyingParty.getAcWhitelist().getAcUrls());
		if (referer != null && !WebUtil.isAllowedReferer(allowedUrls, referer)) {
			throw new RequestDeniedException(String.format(
					"referer=%s not accepted for rpIssuerId=%s not matching AcWhitelist or XTB perimeter URLs",
					referer, relyingParty.getId()));
		}
		if (origin != null && !WebUtil.isNullOrigin(origin) && !WebUtil.isAllowedOrigin(allowedUrls, origin)) {
			throw new RequestDeniedException(String.format(
					"origin=%s not accepted for rpIssuerId=%s not matching AcWhitelist or XTB perimeter URLs",
					origin, relyingParty.getId()));
		}
		log.debug("referer='{}' / origin='{}' accepted", referer, origin);
	}

	public StateData requestEnterpriseIdp(ResponseData<Response> responseData) {
		OpenSamlUtil.checkResponsePresent(responseData.getResponse(), "CP failed response processing");

		var idpStateData = retrieveValidStateDataForResponse(responseData);
		log.debug("User requested context switch to Enterprise. IdpIssuer={}, responseId={}", idpStateData.getIssuer(),
				responseData.getResponse().getID());

		validateAndGetCpResponse(responseData, idpStateData);

		return idpStateData;
	}

	private CpResponse validateAndGetCpResponse(ResponseData<Response> responseData, StateData idpStateData) {
		var responseIssuer = OpenSamlUtil.getMessageIssuerId(responseData.getResponse());
		var referrer = idpStateData.getReferer();
		var claimsParty = getClaimsPartyForResponseIssuer(responseIssuer, referrer, idpStateData.getIssuer());
		var decryptionCredentials = claimsParty.getCpDecryptionCredentials();
		boolean requireEncryptedAssertion = claimsParty.requireEncryptedAssertion();
		List<Assertion> responseAssertions = SamlUtil.getResponseAssertions(responseData.getResponse(), decryptionCredentials, requireEncryptedAssertion);
		validateResponse(false, responseData, idpStateData, claimsParty, responseAssertions);

		// internal processing context
		var definitions = claimsParty.getAttributesDefinitions();
		var cpResponse = extractCpResponseDto(responseData.getResponse(), responseAssertions, definitions);
		cpResponse.setRpContext(idpStateData.getRpContext());

		// session for SSO
		idpStateData.setCpResponse(cpResponse);
		return cpResponse;
	}

	ClaimsParty getClaimsPartyForResponseIssuer(String responseIssuer, String referrer, String expectedIssuer) {
		// 1) pick single CP.ID or CP.responseIssuer match
		var claimsParties = relyingPartySetupService.getClaimsProviderSetupByResponseIssuerId(responseIssuer);
		if (claimsParties.size() == 1) {
			return claimsParties.get(0);
		}
		// 2) if multiple match CP.ID or CP.responseIssuer pick the one matching the expected session issuer
		var claimsPartyOpt = claimsParties
				.stream()
				.filter(claimsParty -> claimsParty.getId().equalsIgnoreCase(expectedIssuer))
				.findFirst();
		if (claimsPartyOpt.isPresent()) {
			return claimsPartyOpt.get();
		}
		// 3) referrer only match or none of claimsParties matches expected session issuer (usually an error case)
		return relyingPartySetupService.getClaimsProviderSetupByIssuerId(responseIssuer, referrer);
	}

}
