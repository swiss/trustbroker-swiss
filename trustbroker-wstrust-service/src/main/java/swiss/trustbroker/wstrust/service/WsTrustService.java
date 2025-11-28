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

package swiss.trustbroker.wstrust.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.namespace.QName;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponse;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.RequestedSecurityToken;
import org.opensaml.soap.wstrust.TokenType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.opensaml.soap.wstrust.WSTrustObject;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.util.AttributeFilterUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;
import swiss.trustbroker.wstrust.util.WsTrustUtil;
import swiss.trustbroker.wstrust.validator.WsTrustValidator;

@Service
@AllArgsConstructor
@Slf4j
public class WsTrustService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final List<IdmQueryService> idmQueryServices;

	private final RelyingPartySetupService relyingPartySetupService;

	private final ScriptService scriptService;

	private final RelyingPartyService relyingPartyService;

	private final AuditService auditService;

	private final ClaimsMapperService claimsMapperService;

	private final List<WsTrustValidator> wsTrustValidators;

	private WSTrustObject createResponse(List<Attribute> cpAttributes, CpResponse cpResponse,
			WsTrustValidationResult validationResult) {

		var response = createSecurityTokenResponse(cpAttributes, cpResponse, validationResult);

		if (!validationResult.isCreateResponseCollection()) {
			return response;
		}

		RequestSecurityTokenResponseCollection responseCollection = (RequestSecurityTokenResponseCollection) XMLObjectSupport
				.buildXMLObject(RequestSecurityTokenResponseCollection.ELEMENT_NAME);

		responseCollection.getRequestSecurityTokenResponses().add(response);

		return responseCollection;
	}

	private RequestSecurityTokenResponse createSecurityTokenResponse(List<Attribute> cpAttributes,
			CpResponse cpResponse, WsTrustValidationResult validationResult) {
		var requestSecurityTokenResponse =
				(RequestSecurityTokenResponse) XMLObjectSupport.buildXMLObject(RequestSecurityTokenResponse.ELEMENT_NAME);

		var assertionId = OpenSamlUtil.generateSecureRandomId();
		var assertion = createAssertion(cpAttributes, cpResponse, assertionId, validationResult);

		// Current implementation SAML Token Lifetime 8h (configurable)
		// or what the validator determined
		boolean useAssertionLifetime = validationResult.isUseAssertionLifetime();
		var createdTime = useAssertionLifetime ? assertion.getConditions().getNotBefore()
				: Instant.now();
		var expiresTime = useAssertionLifetime ? assertion.getConditions().getNotOnOrAfter()
				: createdTime.plus(trustBrokerProperties.getWstrust().getLifetimeMin(), ChronoUnit.MINUTES);
		var lifetime = WsTrustUtil.createLifeTime(createdTime, expiresTime);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(lifetime);

		var appliesTo = WsTrustUtil.createResponseAppliesTo(validationResult.getIssuerId());
		requestSecurityTokenResponse.getUnknownXMLObjects().add(appliesTo);

		var requestedSecurityToken = createRequestedSecurityToken(assertion, validationResult);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedSecurityToken);

		var requestedAttachedReference = WsTrustUtil.createRequestedAttachedRef(assertionId);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedAttachedReference);

		var requestedUnattachedReference = WsTrustUtil.createRequestUnattachedRef(assertionId);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedUnattachedReference);

		var tokenType = WsTrustUtil.createTokenType();
		requestSecurityTokenResponse.getUnknownXMLObjects().add(tokenType);

		var requestType = WsTrustUtil.createRequestType(validationResult.getRequestType());
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestType);

		var keyType = WsTrustUtil.createKeyType(KeyType.BEARER);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(keyType);

		return requestSecurityTokenResponse;
	}

	private RequestedSecurityToken createRequestedSecurityToken(Assertion assertion, WsTrustValidationResult validationResult) {
		var requestedSecurityToken =
				(RequestedSecurityToken) XMLObjectSupport.buildXMLObject(RequestedSecurityToken.ELEMENT_NAME);

		requestedSecurityToken.setUnknownXMLObject(assertion);

		// trace
		SamlTracer.logSamlObject("<<<<< Outgoing RSTR assertion", assertion);

		// audit
		auditRstResponseToClient(assertion, validationResult.getIssuerId());

		return requestedSecurityToken;
	}

	Assertion createAssertion(List<Attribute> cpAttributes, CpResponse cpResponse, String assertionId,
			WsTrustValidationResult validationResult) {

		var params = buildResponseParams(assertionId, validationResult);

		var rp = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(params.getIssuerId(), null);
		var constAttr = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(validationResult.getIssuerId(), null)
												.getConstAttributes();
		List<String> contextClasses = getAuthnContextClasses(validationResult.getValidatedAssertion());

		var userDetails = AttributeFilterUtil.filteredUserDetails(cpResponse.getUserDetails(), cpResponse.getIdmLookup(),
				rp.getClaimsSelection());

		cpResponse.setUserDetails(claimsMapperService.deduplicatedRpAttributes(userDetails, cpResponse.getProperties(),
				constAttr));
		cpAttributes = SamlFactory.filterDuplicatedAttributes(cpAttributes);

		var assertion = ResponseFactory.createSamlAssertion(cpResponse, constAttr, contextClasses, params, cpAttributes);

		var signatureParameters = rp.getSignatureParametersBuilder()
									.skinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces())
									.build();
		SamlFactory.signSignableObject(assertion, signatureParameters);

		return assertion;
	}

	private ResponseParameters buildResponseParams(String assertionId, WsTrustValidationResult validationResult) {
		var requestNameId = getNameID(validationResult.getValidatedAssertion());
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(validationResult.getIssuerId(), null);
		var tokenLifetime = relyingPartySetupService.getTokenLifetime(relyingParty);
		var audienceLifetime = relyingPartySetupService.getAudienceRestrictionLifetime(relyingParty);
		var sessionIndex = validationResult.getSessionIndex();
		var now = Instant.now();
		return ResponseParameters.builder()
								 .conversationId(assertionId)
								 .issuerId(validationResult.getIssuerId())
								 .federationServiceIssuerId(trustBrokerProperties.getIssuer())
								 .nameId(requestNameId.getValue())
								 .nameIdFormat(requestNameId.getFormat())
								 .nameIdQualifier(requestNameId.getNameQualifier())
								 .rpAuthnRequestId(null)
								 .recipientId(validationResult.getRecipientId())
								 .issuerInstant(now)
								 .authnStatementInstant(now)
								 .subjectValiditySeconds(tokenLifetime)
								 .audienceValiditySeconds(audienceLifetime)
								 .cpAttrOriginIssuer(null)
								 .setSessionIndex(sessionIndex != null)
								 .sessionIndex(sessionIndex)
								 .rpClientName(relyingPartySetupService.getRpClientName(relyingParty))
								 .skinnyAssertionStyle(trustBrokerProperties.getSkinnyAssertionNamespaces())
								 .build();
	}

	private static NameID getNameID(Assertion assertion) {
		Subject subject = assertion.getSubject();
		if (subject == null) {
			throw new TechnicalException(String.format("Missing Assertion.Subject from RST with id=%s", assertion.getID()));
		}
		return subject.getNameID();
	}

	private static List<String> getAuthnContextClasses(Assertion requestHeaderAssertion) {
		List<String> contextClasses = Collections.emptyList();
		if (requestHeaderAssertion == null || requestHeaderAssertion.getAuthnStatements().isEmpty()) {
			return contextClasses;
		}
		var authnContext = requestHeaderAssertion.getAuthnStatements().get(0).getAuthnContext();
		if (authnContext != null && authnContext.getAuthnContextClassRef() != null &&
				authnContext.getAuthnContextClassRef().getURI() != null) {
			var authnContextClassRef = authnContext.getAuthnContextClassRef().getURI();
			contextClasses = List.of(authnContextClassRef);
		}
		return contextClasses;
	}

	public WSTrustObject processSecurityTokenRequest(
			RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader) {
		// trace
		if (requestHeader == null) {
			throw new RequestDeniedException("SOAP request header missing");
		}
		var headerAssertion = requestHeader.getAssertion();
		if (headerAssertion != null) {
			SamlTracer.logSamlObject(">>>>> Incoming RST header assertion", headerAssertion);
		}

		// accept request
		var validationResult = processSecurityToken(requestSecurityToken, requestHeader);
		var requestAssertion = validationResult.getValidatedAssertion();

		// trace assertion extracted from body
		if (headerAssertion != requestAssertion) {
			SamlTracer.logSamlObject(">>>>> Incoming RST assertion", requestAssertion);
		}

		log.debug("Incoming RST accepted -> send RSTR");

		// audit
		auditRstRequestFromClient(requestAssertion, validationResult.getIssuerId());

		// processing
		var cpResponse = createCpResponseDto(validationResult);

		List<AttributeStatement> requestAttributeStatements = requestAssertion.getAttributeStatements();
		List<Attribute> cpAttributes;
		if (!validationResult.isRecomputeAttributes()) {
			cpAttributes = createCpAttributes(cpResponse.getAttributes(), null, requestAttributeStatements, requestAssertion);
		}
		else {
			scriptService.processCpBeforeIdm(cpResponse, null, cpResponse.getIssuer(), "");

			// Filter by CP config AttributeSelection
			filterCpAttributes(cpResponse);

			scriptService.processRpBeforeIdm(cpResponse, null, validationResult.getIssuerId(), "");

			getResponseQueryElements(requestAssertion, validationResult.getIssuerId(), cpResponse);

			// Filter by RP config AttributeSelection
			List<Definition> rpConfigAttributesDefinition =
					relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(validationResult.getIssuerId(), null)
											.getAttributesDefinitions();
			filterCpAttributesByRpConfig(rpConfigAttributesDefinition, cpResponse);

			relyingPartyService.setProperties(cpResponse);

			scriptService.processCpAfterIdm(cpResponse, null, cpResponse.getIssuer(), "");
			scriptService.processRpAfterIdm(cpResponse, null, validationResult.getIssuerId(), "");

			relyingPartyService.filterPropertiesSelection(cpResponse, validationResult.getIssuerId(), "");

			cpAttributes = createCpAttributes(cpResponse.getAttributes(), rpConfigAttributesDefinition,
					requestAttributeStatements, requestAssertion);
		}
		cpResponse.setAttributes(null);

		var response = createResponse(cpAttributes, cpResponse, validationResult);

		scriptService.processWsTrustOnResponse(cpResponse, response, validationResult.getIssuerId(), "");

		return response;
	}

	private void filterCpAttributesByRpConfig(List<Definition> rpConfigAttributesDefinition, CpResponse cpResponse) {
		ResponseFactory.filterCpAttributes(cpResponse, rpConfigAttributesDefinition, trustBrokerProperties.getSaml());
	}

	private void filterCpAttributes(CpResponse cpResponse) {
		List<Definition> cpAttributeDefinitions = relyingPartySetupService
				.getClaimsProviderSetupByIssuerId(cpResponse.getIssuer(), "")
				.getAttributesDefinitions();
		ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions, trustBrokerProperties.getSaml());
	}

	WsTrustValidationResult processSecurityToken(RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader) {
		var headerAssertion = requestHeader.getAssertion();
		var assertionId = headerAssertion != null ? headerAssertion.getID() : null;
		if (requestSecurityToken == null) {
			throw new RequestDeniedException(String.format(
					"Missing WS-Trust RequestSecurityToken RSTR with assertionID='%s'", assertionId));
		}
		var childObjects = requestSecurityToken.getUnknownXMLObjects();

		var requestTypeQname = new QName(WSTrustConstants.WST_NS, RequestType.ELEMENT_LOCAL_NAME);
		RequestType requestType = OpenSamlUtil.findChildObjectByQname(childObjects, requestTypeQname);
		if (requestType == null) {
			throw new RequestDeniedException(String.format(
					"Missing RequestType in RSTR with assertionID='%s'", assertionId));
		}
		var validator = selectValidator(requestType, assertionId);
		var validationResult = validator.validate(requestSecurityToken, requestHeader);

		var tokenTypeQname = new QName(WSTrustConstants.WST_NS, TokenType.ELEMENT_LOCAL_NAME);
		TokenType tokenType = OpenSamlUtil.findChildObjectByQname(childObjects, tokenTypeQname);
		isRequired(tokenType, false, requestSecurityToken);

		if (tokenType == null) {
			throw new RequestDeniedException(String.format(
					"Missing TokenType in RSTR with AssertionID='%s'", assertionId));
		}
		if (!WSSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType.getURI())) {
			throw new RequestDeniedException(String.format(
					"Wrong TokenType in RSTR with assertionID='%s' tokenType='%s' but expectedTokenType='%s'",
					assertionId, tokenType.getURI(), WSSConstants.WSS_SAML2_TOKEN_TYPE));
		}
		return validationResult;
	}

	private WsTrustValidator selectValidator(RequestType requestType, String assertionId) {
		for (var validator : wsTrustValidators) {
			if (validator.applies(requestType)) {
				return validator;
			}
		}
		throw new RequestDeniedException(String.format(
				"Wrong RequestType in RSTR with assertionID='%s' requestType='%s' but no validator for this type available",
				assertionId, requestType.getURI()));
	}

	private static void isRequired(XMLObject elementValue, boolean required, XMLObject requestSecurityToken) {
		if (elementValue == null && required) {
			throw new RequestDeniedException(String.format(
					"One of the security elements is missing from message: %s",
					OpenSamlUtil.samlObjectToString(requestSecurityToken)));
		}
	}

	@SuppressWarnings("java:S2629")
	private static List<Attribute> createCpAttributes(
			Map<Definition, List<String>> cpAttributes, List<Definition> rpConfigAttributesDefinition,
			List<AttributeStatement> requestAttributeStatements, Assertion assertion) {

		List<Attribute> attributes = new ArrayList<>();
		// attribute statements
		// NOTE: Some send no attribute statements, so we make this debug
		if (cpAttributes == null || cpAttributes.isEmpty()) {
			log.debug("There are no CP attributes : {}", OpenSamlUtil.samlObjectToString(assertion));
		}
		else if (rpConfigAttributesDefinition == null) {
			log.debug("Reproduce attributes from request assertion");
			for (var cpAttribute : cpAttributes.entrySet()) {
				var definition = cpAttribute.getKey();
				var namespaceUri = definition.getNamespaceUri() != null ? definition.getNamespaceUri() : definition.getName();
				var values = cpAttribute.getValue();
				attributes.add(SamlFactory.createAttribute(namespaceUri, values,
						getOriginalIssuerFromInput(requestAttributeStatements, namespaceUri)));
			}
		}
		else {
			for (Definition definition : rpConfigAttributesDefinition) {
				var name = definition.getNamespaceUri();
				var values = DefinitionUtil.findListByNameOrNamespace(name, null, cpAttributes);
				if (!values.isEmpty()) {
					attributes.add(SamlFactory.createAttribute(definition.getNamespaceUri(), values,
							getOriginalIssuerFromInput(requestAttributeStatements, definition.getNamespaceUri())));
				}
			}
		}

		return new ArrayList<>(attributes);
	}

	// Request can have attributes with different OriginalIssuer
	private static String getOriginalIssuerFromInput(List<AttributeStatement> requestAttributeStatements,
			String definitionNamespaceUri) {
		if (requestAttributeStatements != null && !requestAttributeStatements.isEmpty()
				&& requestAttributeStatements.get(0) != null) {
			var assertionAttributes = requestAttributeStatements.get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				if (namespaceUri != null && namespaceUri.equals(definitionNamespaceUri)) {
					return SamlUtil.getOriginalIssuerFromAttribute(attribute);
				}
			}
		}
		return null;
	}

	private void getResponseQueryElements(Assertion requestAssertion, String recipientIssuerId,
			CpResponse cpResponse) {

		Subject subject = requestAssertion.getSubject();
		if (subject == null || subject.getNameID() == null || subject.getNameID().getValue() == null) {
			throw new TechnicalException(String.format("Missing NameId from Assertion with id=%s for recipientIssuerId=%s",
					requestAssertion.getID(), recipientIssuerId));
		}

		if (requestAssertion.getIssuer() == null) {
			throw new TechnicalException(String.format("Missing Issuer from Assertion with id=%s ", requestAssertion.getID()));
		}

		var relyingPartyConfig = RelyingParty.builder().id(recipientIssuerId).build();
		var callback = new DefaultIdmStatusPolicyCallback(cpResponse);

		for (var idmService : idmQueryServices) {
			var queryResponse = idmService.getAttributes(relyingPartyConfig, cpResponse, cpResponse.getIdmLookup(), callback);
			if (queryResponse.isPresent()) {
				DefinitionUtil.mapAttributeList(queryResponse.get().getUserDetails(), cpResponse.getUserDetails());
			}
		}
	}

	private CpResponse createCpResponseDto(WsTrustValidationResult validationResult) {
		var requestAssertion = validationResult.getValidatedAssertion();
		var issuer = requestAssertion.getIssuer();
		if (issuer == null) {
			throw new TechnicalException("Assertion issuer is null for Assertion with ID=" + requestAssertion.getID());
		}
		var cpIssuer = issuer.getValue();
		Map<Definition, List<String>> cpAttributes = new HashMap<>();

		// minimal processing context (WSTrust does not need state)
		var cpResponse = new CpResponse();
		if (requestAssertion.getSubject() != null && requestAssertion.getSubject().getNameID() != null) {
			cpResponse.setAttribute(CoreAttributeName.NAME_ID.getNamespaceUri(), requestAssertion.getSubject().getNameID().getValue());
			cpResponse.setNameId(requestAssertion.getSubject().getNameID().getValue());
		}
		cpResponse.setIssuer(cpIssuer);
		cpResponse.setAttributes(cpAttributes);

		// AttributeStatements
		if (requestAssertion.getAttributeStatements() != null && !requestAssertion.getAttributeStatements().isEmpty()) {
			var assertionAttributes = requestAssertion.getAttributeStatements().get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				var values = SamlUtil.getValuesFromAttribute(attribute);
				if (namespaceUri != null && values != null && !values.isEmpty()) {
					cpResponse.setAttributes(namespaceUri, values); // free to be processed afterward
				}
			}
		}

		if (validationResult.isRecomputeAttributes()) {
			var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuer, "");
			var homeName = relyingPartySetupService.getHomeName(claimsParty, List.of(requestAssertion), cpResponse);
			cpResponse.setHomeName(homeName);
		}

		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(validationResult.getIssuerId(), "");
		var idmLookUp = relyingPartySetupService.getIdmLookUp(relyingParty);
		if (idmLookUp.isPresent()) {
			cpResponse.setIdmLookup(idmLookUp.get().shallowClone());
		}

		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(relyingParty));
		cpResponse.setClientName(relyingPartySetupService.getRpClientName(relyingParty));

		var authLevelAttribute = cpResponse.getAttribute(CoreAttributeName.AUTH_LEVEL.getNamespaceUri());
		if (authLevelAttribute != null) {
			cpResponse.setAuthLevel(authLevelAttribute);
		}

		cpResponse.setRpIssuer(validationResult.getIssuerId());

		Map<Definition, List<String>> originalAttributes = new HashMap<>(cpResponse.getAttributes());
		cpResponse.setOriginalAttributes(originalAttributes);

		return cpResponse;
	}


	private void auditRstRequestFromClient(Assertion assertion, String recipientIssuerId) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(recipientIssuerId, null);
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFromRstRequestAssertion(assertion)
				.mapFromThreadContext() // conversation switch done by assertion
				.mapFrom(relyingParty)
				.build();
		auditService.logOutboundFlow(auditDto);
	}

	private void auditRstResponseToClient(Assertion assertion, String recipientIssuerId) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(recipientIssuerId, null);
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFromThreadContext()
				.mapFromRstResponseAssertion(assertion)
				.mapFrom(relyingParty)
				.build();
		auditService.logOutboundFlow(auditDto);
	}

}
