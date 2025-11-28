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

package swiss.trustbroker.saml.util;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.sessioncache.dto.StateData;

@Component
@AllArgsConstructor
@Slf4j
public class ResponseFactory {

	private final RelyingPartySetupService relyingPartySetupService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final QoaMappingService qoaMappingService;

	// high level factory method
	public Assertion createAssertion(StateData idpStateData, CpResponse cpResponse, ResponseParameters params) {
		// federated parties
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				params.getRpIssuerId(), params.getRpReferer());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(
				cpResponse.getIssuer(), idpStateData.getReferer());

		// apply missing required parameters
		applyContextAndDefaults(idpStateData, cpResponse, relyingParty, claimsParty, params);

		// assemble assertion
		params.setNameIdFormat(cpResponse.getNameIdFormat());
		var constAttr = relyingParty.getConstAttributes();
		var rpQoaConfig = qoaMappingService.getQoaConfiguration(idpStateData.getSpStateData(), relyingParty);
		rpQoaConfig = rpQoaConfig != null ?  rpQoaConfig : new QoaConfig(null, null);

		// map CP Qoa model to RP Qoa model (the relevant comparison type is what the RP requested)
		var rpContextClasses = QoaMappingUtil.getRpContextClasses(idpStateData, rpQoaConfig.config());
		var contextClasses = qoaMappingService.mapResponseQoasToOutbound(
				cpResponse.getContextClasses(), claimsParty.getQoaConfig(),
				params.getRpComparison(), rpContextClasses, rpQoaConfig);
		var assertion = createSamlAssertion(cpResponse, constAttr, contextClasses, params, null);

		// disable setting OriginalIssuer on Attribute
		var removeOriginalIssuer = !relyingParty.isDelegateOrigin();
		var homeNameOriginalIssuer = mapHomeNameIssuer(params.getHomeNameIssuerMapping(), claimsParty.getId());
		updateOriginalIssuer(assertion, params.getRequireOriginalIssuerClaims(), params.getCpAttrOriginIssuer(),
				removeOriginalIssuer, homeNameOriginalIssuer);

		// we use the ID as session index - store for validation
		idpStateData.setSessionIndex(assertion.getID());

		// sign assertion
		if (trustBrokerProperties.getSecurity().isDoSignAssertions()) {
			var signatureParams = relyingParty.getSignatureParametersBuilder()
											  .credential(params.getCredential())
											  .skinnyAssertionNamespaces(params.getSkinnyAssertionStyle())
											  .build();
			SamlFactory.signAssertion(assertion, signatureParams);
		}
		return assertion;
	}


	// low level factory method, assembling everything according to RP input, CP response, configuration and state
	public static Assertion createSamlAssertion(CpResponse cpResponse, ConstAttributes constAttr,
		 List<String> contextClasses, ResponseParameters params, List<Attribute> additionalAttributes) {
		var assertion = OpenSamlUtil.buildAssertionObject(params.getSkinnyAssertionStyle());
		var assertionId = OpenSamlUtil.generateSecureRandomId();
		if (params.getConversationId() != null) {
			assertionId = params.getConversationId() + assertionId; // conversation extended
		}
		assertion.setID(assertionId);
		assertion.setIssueInstant(params.getIssuerInstant());
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssuer(SamlFactory.createIssuer(params.getFederationServiceIssuerId()));

		// Note that audience condition and subject confirmation use the same tolerance (default 8min)
		var nameId = SamlFactory.createNameId(params.getNameId(), params.getNameIdFormat(), params.getNameIdQualifier());
		var rpAuthRequestId = params.getRpAuthnRequestId();
		var now = Instant.now();
		assertion.setSubject(SamlFactory.createSubject(nameId, rpAuthRequestId, params.getRecipientId(),
				params.getSubjectValiditySeconds(), now));
		assertion.setConditions(SamlFactory.createConditions(params.getIssuerId(), params.getAudienceValiditySeconds(), now));

		var attributes = createAttributes(params.getCpAttrOriginIssuer(), constAttr, cpResponse.getAttributes(),
				params.getRpClientName(), cpResponse.getProperties(), cpResponse.getUserDetails());
		var samlAttributes = attributes.stream()
				.map(Pair::getRight)
				.collect(Collectors.toList());

		if (additionalAttributes != null && !additionalAttributes.isEmpty()) {
			samlAttributes.addAll(additionalAttributes);
		}

		// AttributeStatement
		var attributeStatement = SamlFactory.createAttributeStatement(samlAttributes);
		assertion.getAttributeStatements().add(attributeStatement);
		if (contextClasses != null) {
			var sessionIndexToUse = params.getSessionIndex() != null ? params.getSessionIndex() : assertionId;
			var sessionIndex = params.isSetSessionIndex() ? sessionIndexToUse : null;
			assertion.getAuthnStatements().addAll(SamlFactory.createAuthnStatements(contextClasses, sessionIndex,
					params.getSessionNotOnOrAfter(), params.getAuthnStatementInstant()));
		}

		// audit input
		addAttributesToDtoResults(cpResponse, attributes);
		return assertion;
	}

	private void applyContextAndDefaults(StateData idpStateData, CpResponse cpResponse,
			RelyingParty relyingParty, ClaimsParty claimsParty,
			ResponseParameters params) {
		applyRpSideDefaults(idpStateData, cpResponse, relyingParty, params);

		applyFederationDefaults(cpResponse, relyingParty, claimsParty, params);

		applyValidityParameterDefaults(relyingParty, params);
	}

	private static void applyRpSideDefaults(StateData idpStateData, CpResponse cpResponse, RelyingParty relyingParty,
			ResponseParameters params) {
		params.setRpAuthnRequestId(idpStateData.getSpStateData().getId());
		if (params.getIssuerId() == null) {
			params.setIssuerId(idpStateData.getRpIssuer());
		}
		if (params.getRecipientId() == null) {
			params.setRecipientId(getRpRecipient(idpStateData, cpResponse));
		}
		if (params.getCredential() == null) {
			params.setCredential(relyingParty.getRpSigner());
		}
		if (params.getRpComparison() == null) {
			params.setRpComparison(idpStateData.getSpStateData().getComparisonType());
		}
		if (params.getRpContextClasses() == null) {
			params.setRpContextClasses(idpStateData.getSpStateData().getContextClasses());
		}
	}

	private void applyFederationDefaults(CpResponse cpResponse, RelyingParty relyingParty, ClaimsParty claimsParty,
			ResponseParameters params) {
		if (params.getFederationServiceIssuerId() == null) {
			var federationServiceIssuer = cpResponse.getCustomIssuer() != null ? cpResponse.getCustomIssuer() :
					trustBrokerProperties.getIssuer();
			params.setFederationServiceIssuerId(federationServiceIssuer);
		}
		if (params.getNameId() == null) {
			var nameId = cpResponse.getNameId();
			if (params.isAccessRequest()) {
				nameId = cpResponse.getMappedNameId() != null ?  cpResponse.getMappedNameId() : cpResponse.getOriginalNameId();
				log.debug("AccessRequest - using nameId={} from mappedNameId={} with fallback to originalNameId={}",
						nameId,  cpResponse.getMappedNameId(), cpResponse.getOriginalNameId());
			}
			params.setNameId(nameId);
			if (params.getNameId() == null) {
				log.error("Missing nameId for authnRequestId={} rpIssuerId={} cpIssuerId={}",
						cpResponse.getInResponseTo(), relyingParty.getId(), claimsParty.getId());
			}
		}
		if (params.getCpAttrOriginIssuer() == null) {
			var cpOriginalIssuer = claimsParty.getOriginalIssuer();
			params.setCpAttrOriginIssuer(cpOriginalIssuer);
		}
		if (params.getRpClientName() == null) {
			var rpClientName = relyingPartySetupService.getRpClientName(relyingParty);
			params.setRpClientName(rpClientName);
		}
		if (params.getSkinnyAssertionStyle() == null) {
			params.setSkinnyAssertionStyle(trustBrokerProperties.getSkinnyAssertionNamespaces());
		}
	}

	private void applyValidityParameterDefaults(RelyingParty relyingParty, ResponseParameters params) {
		var now = Instant.now();
		if (params.getSubjectValiditySeconds() <= 0) {
			params.setSubjectValiditySeconds(relyingPartySetupService.getTokenLifetime(relyingParty));
		}
		if (params.getAudienceValiditySeconds() <= 0) {
			params.setAudienceValiditySeconds(relyingPartySetupService.getAudienceRestrictionLifetime(relyingParty));
		}
		if (params.getIssuerInstant() == null) {
			params.setIssuerInstant(now);
		}
		if (params.getAuthnStatementInstant() == null) {
			params.setAuthnStatementInstant(now);
		}
	}

	private static String mapHomeNameIssuer(List<RegexNameValue> homeNameIssuerMappings, String cpId) {
		if (cpId == null || CollectionUtils.isEmpty(homeNameIssuerMappings)) {
			return null;
		}
		for (var mapping : homeNameIssuerMappings) {
			if (mapping.getPattern()
					   .matcher(cpId)
					   .matches()) {
				return mapping.getValue();
			}
		}
		return null;
	}

	private static void updateOriginalIssuer(
			Assertion assertion, List<String>requireOriginalIssuerClaims, String claimOriginalIssuer,
			boolean removeOriginalIssuer, String homeNameOriginalIssuer) {
		for (var as : assertion.getAttributeStatements()) {
			for (var att : as.getAttributes()) {
				if (homeNameOriginalIssuer != null && CoreAttributeName.HOME_NAME.equalsByNameOrNamespace(att.getName())) {
					SamlUtil.setOriginalIssuer(att, homeNameOriginalIssuer);
					log.debug("Using originalIssuer={} for attributeName={}", homeNameOriginalIssuer, att.getName());
				}
				else if (removeOriginalIssuer) {
					SamlUtil.removeOriginalIssuer(att);
				}
				else if (claimOriginalIssuer != null && requireOriginalIssuerClaims != null &&
						requireOriginalIssuerClaims.contains(att.getName())) {
					SamlUtil.setOriginalIssuerIfMissing(att, claimOriginalIssuer);
				}
			}
		}
	}

	private static String getRpRecipient(StateData idpStateData, CpResponse cpResponse) {
		// script has prio 1 to define the recipient
		if (cpResponse.getRpRecipient() != null) {
			return cpResponse.getRpRecipient();
		}
		// if subject recipient is not defined use response destination
		return getRpDestination(idpStateData, cpResponse);
	}


	public static String getRpDestination(StateData idpStateData, CpResponse cpResponse) {
		// script has prio 1 to define the destination
		if (cpResponse != null && cpResponse.getRpDestination() != null) {
			return cpResponse.getRpDestination();
		}
		// note that the RP AuthnRequest AssertionConsumerServiceUrl must have been accepted by the ACWhitelist
		return idpStateData.getSpStateData().getAssertionConsumerServiceUrl();
	}

	public static void filterCpAttributes(CpResponse cpResponse, List<Definition> cpAttributeDefinitions, SamlProperties samlProperties) {
		var dropAttrSelectionIfNoFilter = samlProperties != null && samlProperties.isDropAttrSelectionIfNoFilter();
		// Keep attributes when there is no AttributeSelection defined
		if ((cpAttributeDefinitions == null || cpAttributeDefinitions.isEmpty()) && !dropAttrSelectionIfNoFilter) {
			return;
		}
		cpResponse.getAttributes()
				.entrySet()
				.removeIf(att -> attributeHasNoDefinition(att.getKey(), cpAttributeDefinitions));
	}

	private static boolean attributeHasNoDefinition(Definition key, List<Definition> cpAttributeDefinitions) {
		for (Definition definition : cpAttributeDefinitions) {
			if (key.equalsByNameOrNamespace(definition)) {
				key.setCid(definition.getCid()); // use flag from configuration
				return false;
			}
		}
		return true;
	}

	public static List<Pair<Definition, Attribute>> createCpResponseAttributes(String attrOriginIssuer,
			Map<Definition, List<String>> attributesForCp, String clientName) {
		List<Pair<Definition, Attribute>> attributeList = new ArrayList<>();
		if (attributesForCp == null) {
			return attributeList;
		}
		for (Map.Entry<Definition, List<String>>  cpAttribute : attributesForCp.entrySet()) {
			Definition definition = cpAttribute.getKey();
			String nameURI = definition.getNamespaceUri();
			List<String> multiValues = definition.getMultiValues();
			var values = multiValues != null && !multiValues.isEmpty() ? multiValues : cpAttribute.getValue();
			if (nameURI != null) {
				nameURI = SamlFactory.replaceClientNameInUri(nameURI, clientName);
				attributeList.add(Pair.of(definition, SamlFactory.createAttribute(nameURI, values, attrOriginIssuer)));
			}
		}
		return attributeList;
	}

	public static List<Pair<Definition, Attribute>> createUserDetailsAttributes(Map<Definition, List<String>> userDetails,
			String clientName) {
		List<Pair<Definition, Attribute>> attributeList = new ArrayList<>();
		if (userDetails == null) {
			return attributeList;
		}
		for (Map.Entry<Definition, List<String>> entry : userDetails.entrySet()) {
			Definition key = entry.getKey();
			String namespaceUri = key.getNamespaceUri();
			String name = key.getName();
			List<String> entryValue = entry.getValue();
			List<String> value = entryValue != null && !entryValue.isEmpty() ? entryValue : key.getMultiValues();
			if (namespaceUri != null) {
				namespaceUri = SamlFactory.replaceClientNameInUri(namespaceUri, clientName);
				attributeList.add(Pair.of(key, SamlFactory.createResponseAttribute(namespaceUri, value)));
			}
			else if (name != null) {
				attributeList.add(Pair.of(key, SamlFactory.createResponseAttribute(name, value)));
			}
		}

		return attributeList;
	}

	public static List<Pair<Definition, Attribute>> createAttributes(
			String attrOriginIssuer, ConstAttributes constAttr, Map<Definition, List<String>> idpAttributes, String clientName,
			Map<Definition, List<String>> properties, Map<Definition, List<String>> idmAttributes) {

		// assemble all output SAML attributes in the order of 'last-one-wins' in a multiValued=false handling
		List<Pair<Definition, Attribute>> attributeList = new ArrayList<>();
		if (idpAttributes != null) {
			attributeList.addAll(createCpResponseAttributes(attrOriginIssuer, idpAttributes, clientName));
		}
		attributeList.addAll(createUserDetailsAttributes(idmAttributes, clientName));
		attributeList.addAll(createUserDetailsAttributes(properties, clientName));
		// deprecated: Use ClaimsSelection with fixed value instead generated into properties
		attributeList.addAll(createConstAttributes(constAttr, clientName, properties));
		return attributeList;
	}

	private static List<Pair<Definition, Attribute>> createConstAttributes(ConstAttributes constAttr, String clientName,
			Map<Definition, List<String>> properties) {
		List<Pair<Definition, Attribute>> attributeList = new ArrayList<>();
		if (constAttr == null || constAttr.getAttributeDefinitions() == null) {
			return attributeList;
		}
		// If set by ClaimsMapperService.applyConfigFilter, make sure it's not duplicated here
		for (Definition definition : constAttr.getAttributeDefinitions()) {
			var nameURI = definition.getNamespaceUri();
			var values = definition.getMultiValues();
			if (nameURI != null && values != null && !values.isEmpty() &&
					!DefinitionUtil.mapContainsDefinitionWithValue(properties, definition, values)) {
				nameURI = SamlFactory.replaceClientNameInUri(nameURI, clientName);
				attributeList.add(Pair.of(definition, SamlFactory.createAttribute(nameURI, values, null)));
			}
		}
		return attributeList;
	}

	private static void addAttributesToDtoResults(CpResponse cpResponse, List<Pair<Definition, Attribute>> attributes) {
		if (cpResponse == null) {
			return;
		}
		attributes.forEach(attribute -> cpResponse.setResult(attribute.getLeft().toBuilder().build(),
				SamlFactory.attributeValueToStrings(attribute.getRight().getAttributeValues())));
	}

	public static NameID createNameId(CpResponse cpResponse) {
		if (cpResponse != null && cpResponse.getNameId() != null && cpResponse.getNameIdFormat() != null) {
			return SamlFactory.createNameId(cpResponse.getNameId(), cpResponse.getNameIdFormat(), null);
		}
		return null;
	}

}
