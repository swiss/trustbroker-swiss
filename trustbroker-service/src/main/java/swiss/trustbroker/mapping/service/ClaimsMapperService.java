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

package swiss.trustbroker.mapping.service;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsMapper;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.MultiResultPolicy;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.mapping.util.AttributeFilterUtil;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.util.HrdSupport;

/**
 * Service for mapping claims (attributes, user details, properties).
 */
@Service
@AllArgsConstructor
@Slf4j
public class ClaimsMapperService {

	private final RelyingPartySetupService relyingPartySetupService;

	private final ScriptService scriptService;

	private final TrustBrokerProperties trustBrokerProperties;

	/**
	 * Perform mapping of collected attributes before outputting them to the caller:
	 * - apply filter by config
	 * - apply Definition mappers
	 * - apply deduplication
	 */
	public void applyFinalAttributeMapping(CpResponse cpResponse, ResponseParameters responseParameters,
			String destination, RelyingParty relyingParty) {
		applyConfigFilter(cpResponse, responseParameters, relyingParty);
		applyMappers(cpResponse);
		applyOidcDeduplication(cpResponse, destination, relyingParty);
	}

	private void applyConfigFilter(CpResponse cpResponse, ResponseParameters params, RelyingParty relyingParty) {
		// filter CP claims on RP side (CP side already done)
		var claimsSelection = relyingParty.getClaimsSelection();
		var cpAttributesDefs = relyingPartySetupService
				.getRelyingPartyByIssuerIdOrReferrer(params.getRpIssuerId(), params.getRpReferer()).getAttributesDefinitions();
		var cpAttributes = filterAndCreateCpDefinitions(cpResponse.getAttributes(), cpAttributesDefs, claimsSelection, cpResponse.getIssuer());

		// filter IDM claims on RP side
		var userQueries = relyingParty.getIdmLookup();
		var userDetails = AttributeFilterUtil.filteredUserDetails(cpResponse.getUserDetails(), userQueries, claimsSelection);

		// filter internally computed claims on RP side (internally meaning code or SCRIPT source)
		var propertiesDefs = relyingParty.getPropertiesSelection();
		var properties = AttributeFilterUtil.filterProperties(cpResponse.getProperties(), propertiesDefs, claimsSelection);

		// apply values from config
		var constants = ClaimsMapperService.applyConstantDefinitionValues(relyingParty);
		properties.putAll(constants);

		// apply multiSourcePolicy (discards multiple values from unwanted sources)
		applyMultiSourcePolicy(claimsSelection, cpAttributes, userDetails, properties);
		cpResponse.setAttributes(cpAttributes);
		cpResponse.setUserDetails(userDetails);
		cpResponse.setProperties(properties);
	}

	// replacement for ConstAttributes (configured Definition having a value)
	public static  Map<Definition, List<String>> applyConstantDefinitionValues(RelyingParty relyingParty) {
		var allDefs = relyingParty.getAllDefinitions();
		var ret = new HashMap<Definition, List<String>>();
		if (!allDefs.isEmpty()) {
			allDefs.forEach(d -> {
				if (d.getValue() != null) {
					var constDef = Definition.ofNameAndSource(d.getName(), ClaimSource.CONFIG.name());
					constDef.setNamespaceUri(d.getNamespaceUri());
					ret.put(constDef, d.getMultiValues());
				}
			});
		}
		return ret;
	}

	private static void applyMultiSourcePolicy(AttributesSelection claimsSelection, Map<Definition, List<String>> cpAttributes,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties) {
		if (claimsSelection != null && claimsSelection.getMultiSourcePolicy() != null) {
			if (MultiResultPolicy.OVERWRITE.equals(claimsSelection.getMultiSourcePolicy())) {
				AttributeFilterUtil.applyOverwritePolicy(cpAttributes, userDetails, properties);
			}
			else if (MultiResultPolicy.MERGE.equals(claimsSelection.getMultiSourcePolicy())) {
				AttributeFilterUtil.applyMergePolicy(cpAttributes, userDetails, properties);
			}
		}
	}

	static Map<Definition, List<String>> filterAndCreateCpDefinitions(
			Map<Definition, List<String>> attributes, Collection<Definition> confAttributes, AttributesSelection claimsSelection, String issuer) {
		if (attributes == null) {
			throw new TechnicalException(String.format("Missing IDP response attributes for cpIssuer=%s", issuer));
		}

		List<Definition> claimsForSource = AttributeFilterUtil.getClaimsForSource(claimsSelection, ClaimSource.CP.name());
		List<Definition> joinedAttributes = AttributeFilterUtil.joinConfAttributes(confAttributes, claimsForSource);
		Map<Definition, List<String>> respCpAttributes = new HashMap<>();
		if (joinedAttributes.isEmpty()) {
			log.debug("No Cp AttributeSelection for={}", claimsForSource);
			return respCpAttributes;
		}
		for (var definition : joinedAttributes) {
			var attributeValues = getAttributeValues(attributes, definition);
			if (!attributeValues.isEmpty()) {
				respCpAttributes.put(definition, attributeValues);
			}
		}
		return respCpAttributes;
	}

	private static List<String> getAttributeValues(Map<Definition, List<String>> userDetails, Definition definition) {
		return userDetails.entrySet()
				.stream()
				.filter(userAttribute -> userAttribute.getKey().equalsByNameOrNamespace(definition))
				.map(Map.Entry::getValue)
				.findFirst() // CP attributes are unique within CP source
				.orElse(Collections.emptyList());
	}

	private void applyMappers(CpResponse cpResponse) {
		cpResponse.setAttributes(applyMappers(cpResponse.getAttributes(), "attributes"));
		cpResponse.setUserDetails(applyMappers(cpResponse.getUserDetails(), "user details"));
		cpResponse.setProperties(applyMappers(cpResponse.getProperties(), "properties"));
	}

	Map<Definition, List<String>> applyMappers(
			Map<Definition, List<String>> attributes, String typeDescription) {
		Map<Definition, List<String>> result = new HashMap<>();
		for (var entry : attributes.entrySet()) {
			if (entry.getKey().getClaimsMappers().isEmpty()) {
				// no mapping
				result.put(entry.getKey(), entry.getValue());
			}
			else {
				var mappedValues = applyMappers(entry.getKey(), entry.getValue(), typeDescription);
				if (mappedValues != null && !mappedValues.isEmpty()) {
					// we need List<String> here
					result.put(entry.getKey(), CollectionUtil.toStringList(mappedValues, Object::toString));
				}
			}
		}
		return result;
	}

	/**
	 * Apply the mappers of a Definition.
	 */
	public <T> List<Object> applyMappers(Definition definition, List<T> values, String typeDescription) {
		var mappers = definition.getClaimsMappers();
		@SuppressWarnings("unchecked")
		List<Object> mappedValues = (List<Object>) values;
		for (var mapper : mappers) {
			mappedValues = mapper.map(mappedValues);
			if (mapper.equals(ClaimsMapper.SCRIPT)) {
				mappedValues = scriptService.processValueConversion(definition.getName(), mappedValues);
			}
		}
		log.debug("Mapped {} name={} namespaceUri={} from values={} to mappedValues={}",
				typeDescription, definition.getName(), definition.getNamespaceUri(), values, mappedValues);
		return mappedValues;
	}

	private void applyOidcDeduplication(CpResponse cpResponse, String destination, RelyingParty relyingParty) {
		List<String> dropDuplicatedAttributes = Collections.emptyList();
		var dropDuplicatedAttributesConfig = trustBrokerProperties.getOidc() != null ?
				trustBrokerProperties.getOidc().getDropDuplicatedAttributeFromOriginalIssuer() : null;
		if (CollectionUtils.isNotEmpty(dropDuplicatedAttributesConfig) &&
				HrdSupport.isXtbDestination(trustBrokerProperties, destination)) {
			dropDuplicatedAttributes = dropDuplicatedAttributesConfig;
			log.debug("OIDC: Dropping original issuer version if duplicated for attributes={}", dropDuplicatedAttributes);
		}

		cpResponse.setUserDetails(deduplicatedRpAttributes(cpResponse.getUserDetails(), cpResponse.getProperties(),
				relyingParty.getConstAttributes()));
		cpResponse.setAttributes(deduplicatedCpAttributes(cpResponse, dropDuplicatedAttributes, relyingParty.getConstAttributes()));
	}

	/**
	 * Drop duplicate attributes coming from CP and IDM having the same value with a CP preference.
	 * This is needed to pass-through data to AccessRequestService with a preference for the IDP.
	 */
	public void applyIdmDeduplication(CpResponse cpResponse) {
		cpResponse.getAttributes().forEach((key, value) -> {
			var idmValue = cpResponse.getUserDetail(key.getNamespaceUri());
			if (value.contains(idmValue)) {
				cpResponse.removeUserDetails(key.getNamespaceUri());
				log.debug("Dropping idmClaim='{}' in favor of cpIssuer={}",
						key.getNamespaceUri(), cpResponse.getIssuerId());
			}
		});
	}

	/**
	 * Apply profile selection result.
	 */
	public void applyProfileSelection(CpResponse cpResponse, ProfileSelectionResult psResult) {
		if (psResult != null) {
			var filteredAttributes = psResult.getFilteredAttributes();
			if (!filteredAttributes.isEmpty()) {
				Map<Definition, List<String>> responseAttrs = new HashMap<>();
				for (Map.Entry<AttributeName, List<String>> entry : filteredAttributes.entrySet()) {
					responseAttrs.put(new Definition(entry.getKey()), entry.getValue());
				}
				cpResponse.setUserDetails(responseAttrs);
			}
		}
	}

	public Map<Definition, List<String>> deduplicatedRpAttributes(Map<Definition, List<String>> userDetailMap,
			Map<Definition, List<String>> properties, ConstAttributes constAttributes) {
		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			Definition key = entry.getKey();
			List<String> value = entry.getValue();
			// Result does not contain the Definition and Properties does not contain it
			if (!definitionInRpMaps(key, value, responseAttrs, properties, constAttributes)) {
				responseAttrs.put(key, value);
			}
		}
		return responseAttrs;
	}

	// should be private, still used by a test
	public static Map<Definition, List<String>> deduplicatedCpAttributes(CpResponse cpResponse,
			List<String> dropDuplicatedAttributes, ConstAttributes constAttributes) {

		Map<Definition, List<String>> attributes = cpResponse.getAttributes();
		Map<Definition, List<String>> userDetails = cpResponse.getUserDetails();
		Map<Definition, List<String>> properties = cpResponse.getProperties();

		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()) {
			Definition key = entry.getKey();
			List<String> value = entry.getValue();
			if (DefinitionUtil.mapContainsDefinitionWithValue(responseAttrs, key, value)
					|| attributeToDrop(key, dropDuplicatedAttributes, userDetails, properties, constAttributes)) {
				log.debug("Dropping duplicated attribute={} from original issuer in list={}", key, dropDuplicatedAttributes);
			}
			else {
				responseAttrs.put(key, value);
			}
		}

		return responseAttrs;
	}

	static boolean attributeToDrop(Definition definition, List<String> attributesToBeDropped,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		if (CollectionUtils.isEmpty(attributesToBeDropped)) {
			return false;
		}
		var attributeToDrop = definition.getNamespaceUri() != null ? definition.getNamespaceUri() : definition.getName();
		// Check if attribute should be dropped
		if (attributeToDrop != null && attributesToBeDropped.contains(attributeToDrop)) {
			// Drop if the Definition is in userDetails, properties or constants
			return definitionInRpMaps(definition, userDetails, properties, constAttributes);
		}
		return false;
	}

	private static boolean definitionInRpMaps(Definition definition,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		return DefinitionUtil.mapContainsDefinitionWithValue(userDetails, definition)
				|| DefinitionUtil.mapContainsDefinitionWithValue(properties, definition)
				|| DefinitionUtil.constContainsDefinition(constAttributes, definition);
	}

	private static boolean definitionInRpMaps(Definition definition, List<String> values,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		return DefinitionUtil.mapContainsDefinitionWithValue(userDetails, definition, values)
				|| DefinitionUtil.mapContainsDefinitionWithValue(properties, definition, values)
				|| DefinitionUtil.constContainsDefinition(constAttributes, definition, values);
	}

}
