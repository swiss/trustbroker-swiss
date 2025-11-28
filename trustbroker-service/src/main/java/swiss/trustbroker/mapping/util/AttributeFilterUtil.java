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

package swiss.trustbroker.mapping.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.MultiResultPolicy;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;

@Slf4j
public class AttributeFilterUtil {

	private AttributeFilterUtil(){}

	public static Definition getDefinitionFromMap(Map<Definition, List<String>> map, Definition definition) {
		for (Map.Entry<Definition, List<String>> entry : map.entrySet()) {
			var key = entry.getKey();
			var namespaceUri = key.getNamespaceUri();
			if (definition.getNamespaceUri() != null && namespaceUri != null) {
				if (definition.equalsByNamespace(namespaceUri)) {
					return key;
				}
			}
			else if (key.equalsByNameOrNamespace(definition)) {
				return key;
			}
		}
		return null;
	}

	public static Map<Definition, List<String>> filteredUserDetails(Map<Definition, List<String>> userDetailMap,
			IdmLookup idmLookup, AttributesSelection claimsSelection) {
		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		if (userDetailMap == null) {
			return responseAttrs;
		}

		// source is SCRIPT if the attributes was created in a groovy,
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			var attributeDefinition = entry.getKey();
			var values = new ArrayList<>(entry.getValue());
			var source = attributeDefinition.getSource();

			// Groovy scripts should not manipulate user details, but we did not prevent that by design, accept it here
			// NOTE: Such claims leak into further processing aan can even be exposed to relying parties
			if (source == null || source.endsWith(AuditDto.AttributeSource.SCRIPT.name())) {
				if (source == null) {
					// All claims need a source of origin so precise picking with Definition.source="PRECISE:SOURCE" is possible
					log.info("Missing source leads to outbound claim leaks for attributeDefinition='{}'", attributeDefinition);
				}
				responseAttrs.put(new Definition(attributeDefinition.getName(), attributeDefinition.getNamespaceUri()), values);
			}
		}

		// merge multiple queries according to policy
		if (idmLookup != null && idmLookup.getQueries() != null) {
			applyMultiQueryPolicies(userDetailMap, idmLookup, responseAttrs, claimsSelection);
		}

		return responseAttrs;
	}

	// Pick attributes for queries to make sure MultiQueryPolicy applied correctly
	private static void applyMultiQueryPolicies(Map<Definition, List<String>> userDetailMap, IdmLookup idmLookup,
			Map<Definition, List<String>> responseAttrs, AttributesSelection claimsSelection) {
		var multiQueryPolicy = idmLookup.getMultiQueryPolicy();
		if (claimsSelection != null && claimsSelection.getMultiSourcePolicy() != null) {
			multiQueryPolicy = claimsSelection.getMultiSourcePolicy();
		}
		List<IdmQuery> queries = idmLookup.getQueries();
		for (IdmQuery idmQuery : queries) {
			var userDetailsSelection = idmQuery.getAttributeSelection();
			List<Definition> claimsForSource = AttributeFilterUtil.getClaimsForSource(claimsSelection,
					ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, idmQuery.getName()));
			var joinConfAttributes = joinConfAttributes(userDetailsSelection, claimsForSource);

			for (var configDefinition : joinConfAttributes) {
				// Create the attribute if the Definition is in the config
				var attributeValue = getAttributeValueIfRequiredForOutput(userDetailMap, configDefinition,
						ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, idmQuery.getName()));
				if (attributeValue.isPresent()) {
					var definition = Definition.ofNames(configDefinition);
					var source = attributeValue.get().getKey().getSource();
					var mappers = attributeValue.get().getKey().getMappers();
					var value = new ArrayList<>(attributeValue.get().getValue());
					definition.setSource(source);
					definition.setMappers(mappers);
					applyMultiQueryPolicy(multiQueryPolicy, responseAttrs, definition, value);
				}
			}
		}
	}

	static Optional<Map.Entry<Definition, List<String>>> getAttributeValueIfRequiredForOutput(
			Map<Definition, List<String>> userDetailMap, AttributeName configDefinition, String queryName) {
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			var attributeDefinition = entry.getKey();
			// Attribute definition does not have NamespaceUri yet
			boolean defInConfig = configDefinition.getName().equals(attributeDefinition.getName())
					&& (queryName != null && attributeDefinition.getSource() != null
					&& queryName.startsWith(attributeDefinition.getSource()));

			if (attributeDefinition.getSource() != null && defInConfig) {
				return Optional.of(entry);
			}
		}
		return Optional.empty();
	}

	// Apply MultiQueryResultPolicy
	static void applyMultiQueryPolicy(MultiResultPolicy multiQueryPolicy, Map<Definition, List<String>> respCpAttributes,
			Definition definition, List<String> value) {
		var foundDef = getDefinitionFromMap(respCpAttributes, definition);
		// Definition is already there from prev query
		if (foundDef != null) {
			if (multiQueryPolicy == null || multiQueryPolicy == MultiResultPolicy.OVERWRITE) {
				respCpAttributes.remove(foundDef);
				respCpAttributes.put(definition, value);
			}
			else {
				respCpAttributes.get(foundDef).addAll(value);
			}
		}
		else {
			respCpAttributes.put(definition, value);
		}
	}

	public static Map<Definition, List<String>> filterProperties(Map<Definition, List<String>> properties,
			AttributesSelection attributesSelection, AttributesSelection claimsSelection) {
		var claimsForSource = getClaimsForSource(claimsSelection, ClaimSource.PROPS.name());
		return properties.entrySet().stream()
				.filter(map -> attributeMustBeInResponse(map.getKey(), attributesSelection) ||
						claimMustBeInResponse(map.getKey(), claimsForSource))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	public static List<Definition> getClaimsForSource(AttributesSelection claimsSelection, String attrSource) {
		return claimsSelection != null && claimsSelection.getDefinitions() != null ?
				claimsSelection.getDefinitions()
						.stream()
						.filter(def -> def.getSource() != null && attrSource != null && attrSource.startsWith(def.getSource()))
						.toList() : Collections.emptyList();
	}

	public static boolean claimMustBeInResponse(Definition definition, List<Definition> claimsSelection) {
		if (claimsSelection.isEmpty()) {
			return false;
		}
		for (Definition def : claimsSelection) {
			if (definition.equalsByNameAndNamespace(def)) {
				return true;
			}
		}
		return false;
	}

	static boolean attributeMustBeInResponse(Definition attributeDefinition, AttributesSelection attributesSelection) {
		if (attributesSelection == null || attributesSelection.getDefinitions() == null) {
			return false;
		}
		List<Definition> definitions = attributesSelection.getDefinitions();
		for (Definition definition : definitions) {
			if (attributeDefinition.equalsByNameAndNamespace(definition)) {
				return true;
			}
		}
		return false;
	}

	// confAttributes can be unmodifiable, adds claimsForSource as required and returns a modifiable list
	public static <T extends AttributeName> List<T> joinConfAttributes(Collection<T> confAttributes, List<T> claimsForSource) {
		List<T> modifiableList = new ArrayList<>();
		if (confAttributes != null) {
			modifiableList.addAll(confAttributes);
		}

		if (CollectionUtils.isEmpty(claimsForSource)) {
			return modifiableList;
		}
		for (T def : claimsForSource) {
			if (addDefToCollection(def, confAttributes)) {
				modifiableList.add(def);
			}
		}
		return modifiableList;
	}

	static <T extends AttributeName> boolean addDefToCollection(T def, Collection<T> confAttributes) {
		if (confAttributes == null) {
			return true;
		}
		for (T confDef : confAttributes) {
			if (confDef.equalsByNameAndNamespace(def)) {
				return false;
			}
		}
		return true;
	}

	// confAttributes can be unmodifiable, adds claimsForSource as required and returns a modifiable list
	public static List<AttributeName> joinConfAttributes(List<AttributeName> confAttributes, List<Definition> claimsSelection) {
		List<AttributeName> modifiableList = new ArrayList<>();
		if (confAttributes != null) {
			modifiableList.addAll(confAttributes);
		}
		if (CollectionUtils.isEmpty(claimsSelection)) {
			return modifiableList;
		}
		for (Definition def : claimsSelection) {
			if (addDefToCollection(def, confAttributes)) {
				modifiableList.add(def);
			}
		}
		return modifiableList;
	}

	public static void applyMergePolicy(Map<Definition, List<String>> cpAttributes, Map<Definition, List<String>> userDetails,
			Map<Definition, List<String>> properties) {
		for (Map.Entry<Definition, List<String>> entry : userDetails.entrySet()) {
			mergeValues(cpAttributes, entry);
			mergeValues(properties, entry);
		}
	}

	static void mergeValues(Map<Definition, List<String>> cpAttributes, Map.Entry<Definition, List<String>> entry) {
		var def = AttributeFilterUtil.getDefinitionFromMap(cpAttributes, entry.getKey());
		if (def != null) {
			var values = new ArrayList<>(cpAttributes.get(def));
			cpAttributes.remove(def);
			values.addAll(entry.getValue());
			entry.setValue(values.stream().distinct().toList());
		}
	}

	public static void applyOverwritePolicy(Map<Definition, List<String>> cpAttributes,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties) {
		removeSameDef(cpAttributes, userDetails);
		removeSameDef(userDetails, properties);
	}

	static void removeSameDef(Map<Definition, List<String>> targetMap, Map<Definition, List<String>> map) {
		if (MapUtils.isEmpty(targetMap) || MapUtils.isEmpty(map)){
			return;
		}
		for (Map.Entry<Definition, List<String>> entry : map.entrySet()) {
			var defFromMap = AttributeFilterUtil.getDefinitionFromMap(targetMap, entry.getKey());
			if (defFromMap != null) {
				targetMap.remove(defFromMap);
			}
		}
	}
}
