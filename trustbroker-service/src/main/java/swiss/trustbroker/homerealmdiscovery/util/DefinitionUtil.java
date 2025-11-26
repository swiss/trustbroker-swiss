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

package swiss.trustbroker.homerealmdiscovery.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;

@Slf4j
public class DefinitionUtil {

	static final String VALUE_TO_LIST_NULL = "XTB.DefinitionUtil.valueToList(null)";

	private DefinitionUtil() {
	}

	public static <K extends AttributeName, T> Optional<Map.Entry<K, T>> findByNameOrNamespace(AttributeName name, String source,
			Map<K, T> definitions) {
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name.getName() + "/" + name.getNamespaceUri(), source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	public static <K extends AttributeName, T> Optional<Map.Entry<K, T>> findByNameOrNamespace(String name, String source,
			Map<K, T> definitions) {
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name, source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	public static Map<AttributeName, List<String>> findAllByNameOrNamespace(String name, String source,
			Map<? extends AttributeName, List<String>> attributes) {
		return attributes.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	public static Map<AttributeName, List<String>> findAllByNameOrNamespace(AttributeName name, String source,
			Map<? extends AttributeName, List<String>> attributes) {
		return attributes.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	public static <K extends AttributeName, T> List<T> findListByNameOrNamespace(AttributeName name, String source,
			Map<K, List<T>> definitions) {
		var entry = findByNameOrNamespace(name, source, definitions);
		return CollectionUtil.getList(entry);
	}

	public static <K extends AttributeName, T> List<T> findListByNameOrNamespace(String name, String source,
			Map<K, List<T>> definitions) {
		var entry = findByNameOrNamespace(name, source, definitions);
		return CollectionUtil.getList(entry);
	}

	public static <T> T findSingleValueByNameOrNamespace(AttributeName name, String source,
			Map<? extends AttributeName, List<T>> definitions) {
		var list = findListByNameOrNamespace(name, source, definitions);
		return CollectionUtil.getSingleValue(list, name);
	}

	public static <T> T findSingleValueByNameOrNamespace(String name, String source,
			Map<? extends AttributeName, List<T>> definitions) {
		var list = findListByNameOrNamespace(name, source, definitions);
		return CollectionUtil.getSingleValue(list, name);
	}

	public static <K extends AttributeName> Optional<K> findSingleValueByNameOrNamespace(
			AttributeName name, String source, List<K> definitions) {
		return CollectionUtil.findSingleValueByPredicate(definitions, attr -> attr.equalsByNameOrNamespace(name, source));
	}

	public static <K extends AttributeName> Optional<K> findSingleValueByNameOrNamespace(
			String name, String source, List<K> definitions) {
		return CollectionUtil.findSingleValueByPredicate(definitions, attr -> attr.equalsByNameOrNamespace(name, source));
	}

	public static <T> List<T> findCpAttributeListByNameOrNamespace(String name, Map<AttributeName, List<T>> definitions) {
		var entry = findByNameOrNamespace(name, null, definitions);
		return CollectionUtil.getList(entry);
	}

	public static <K extends AttributeName, T> Optional<Map.Entry<K, T>> findByNameAndNamespace(
			String name, String namespaceUri, String source, Map<K, T> definitions) {
		if (namespaceUri == null) {
			return findByNameOrNamespace(name, null, definitions);
		}
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByName(name) && e.getKey().equalsByNamespace(namespaceUri))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name, source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	// get namespace part after last slash or null if there is no slash
	public static String truncateNamespace(String namespaceUri) {
		var name = StringUtils.substringAfterLast(namespaceUri, '/');
		if (StringUtils.isNotEmpty(name)) {
			return name;
		}
		// StringUtils returns an empty string, that is less convenient for conditions
		return null;
	}

	public static void mapAttributeList(Map<AttributeName, List<String>> attributes,
										Map<Definition, List<String>> definitions) {
		mapAttributeList(attributes, definitions, false);
	}

	public static void mapAttributeListIgnoringSource(Map<AttributeName, List<String>> attributes,
													  Map<Definition, List<String>> definitions) {
		mapAttributeList(attributes, definitions, true);
	}

	private static void mapAttributeList(Map<AttributeName, List<String>> attributes, Map<Definition, List<String>> definitions,
										boolean ignoreSource) {
		if (attributes == null) {
			return;
		}
		for (var attribute : attributes.entrySet()) {
			var attributeDefinition = attribute.getKey();
			var mappers = attributeDefinition instanceof Definition definition ? definition.getMappers() : null;
			var source = ignoreSource ? null : attributeDefinition.getSource();
			var key = mapCpAttributeName(attributeDefinition.getName(), attributeDefinition.getNamespaceUri(), source, mappers);
			if (key != null) {
				definitions.put(key, attribute.getValue());
			}
		}
	}

	private static Definition mapCpAttributeName(String name, String fqName, String source, String mappers) {
		if (name == null && fqName == null) {
			return null;
		}
		return Definition.builder()
						 .name(name)
						 .namespaceUri(fqName)
						 .source(source)
				         .mappers(mappers)
						 .build();
	}

	// Restricted by design: Use to set sessionProfileExtId only
	public static void putAttributeDefinitionValue(Map<AttributeName, List<String>> attributes,
			String name, String fqName, String source, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(source)
							.build();
		checkSource(key);
		attributes.put(key, newValue);
	}

	// Restricted by design: Used by AfterIdm groovy scripting only
	public static void putDefinitionValue(Map<Definition, List<String>> attributes,
			String name, String fqName, String source, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(source)
							.build();
		checkSource(key);
		attributes.put(key, newValue);
	}

	public static void putAttributeValue(Map<AttributeName, List<String>> attributes, AttributeName attribute,
										 String source, String value) {
		var newValue = valueToList(value);
		var key = new Definition(attribute);
		if (source != null) {
			key.setSource(source);
		}
		checkSource(key);
		attributes.put(key, newValue);
	}

	private static void checkSource(Definition key) {
		if (key.getSource() == null) {
			log.debug("Missing source on key='{}'", key);
		}
	}

	private static ArrayList<String> valueToList(String value) {
		var newValue = new ArrayList<String>(); // mutable, as addAttribute extends
		newValue.add(value != null ? value : VALUE_TO_LIST_NULL); // signal invalid null usage
		return newValue;
	}

	public static void putOrRemoveCpAttributeValues(Map<AttributeName, List<String>> attributes,
			String name, String fqName, String source, List<String> values) {
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(source)
							.build();
		if (values == null) {
			attributes.remove(key);
		}
		else {
			attributes.put(key, values);
		}
	}

	public static void replaceAttributeValuesFromSource(Map<AttributeName, List<String>> attributes,
			String name, String fqName, List<String> values, String source) {
		// can have more values if we get IDM data from multiple source (multiple queries or profiles)
		var ret = findAllByNameOrNamespace(name, source, attributes);
		// should not happen
		if (ret.isEmpty()) {
			putOrRemoveCpAttributeValues(attributes, name, fqName, source, values);
			return;
		}
		if (values == null) {
			values = valueToList(null);
		}
		for (Map.Entry<AttributeName, List<String>> entry : ret.entrySet()) {
			// Replace only in the same source
			if (Objects.equals(entry.getKey().getSource(), source)) {
				attributes.remove(entry.getKey());
				putOrRemoveCpAttributeValues(attributes, name, fqName, entry.getKey().getSource(), values);
			}
		}
	}

	public static boolean constContainsDefinition(ConstAttributes constAttributes, Definition key, List<String> value) {
		if (constAttributes == null || constAttributes.getAttributeDefinitions() == null
				|| constAttributes.getAttributeDefinitions().isEmpty()) {
			return false;
		}
		for (Definition constDef : constAttributes.getAttributeDefinitions()) {
			if (DefinitionUtil.definitionAndValueEquals(key, value, constDef, constDef.getMultiValues())) {
				return true;
			}
		}
		return false;
	}

	public static boolean constContainsDefinition(ConstAttributes constAttributes, Definition key) {
		if (constAttributes == null || constAttributes.getAttributeDefinitions() == null
				|| constAttributes.getAttributeDefinitions().isEmpty()) {
			return false;
		}
		for (Definition constDef : constAttributes.getAttributeDefinitions()) {
			if (DefinitionUtil.definitionEqualsNamespaceUriOrName(key, constDef)) {
				return true;
			}
		}
		return false;
	}

	public static boolean mapContainsDefinitionWithValue(Map<Definition, List<String>> attributes, Definition definition,
			List<String> values) {
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()){
			Definition attrDef = entry.getKey();
			List<String> attrValue = entry.getValue();
			if (definitionAndValueEquals(definition, values, attrDef, attrValue)) {
				return true;
			}
		}
		return false;
	}

	public static boolean mapContainsDefinitionWithValue(Map<Definition, List<String>> attributes, Definition definition) {
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()) {
			Definition attrDef = entry.getKey();
			if (definitionEqualsNamespaceUriOrName(definition, attrDef)) {
				return true;
			}
		}
		return false;
	}

	static boolean definitionEqualsNamespaceUriOrName(Definition def1, Definition def2) {
		if (def1.getNamespaceUri() != null && def2.getNamespaceUri() != null) {
			return def1.getNamespaceUri().equals(def2.getNamespaceUri());
		}
		else if (def1.getName() != null && def2.getName() != null) {
			return def1.getName().equals(def2.getName());
		}
		return false;
	}

	static boolean definitionAndValueEquals(Definition def1, List<String> values1, Definition def2,
			List<String> values2) {
		return definitionEqualsNamespaceUriOrName(def1, def2) && listMatch(values1, values2);
	}

	static boolean listMatch(List<String> values, List<String> resultValues) {
		if (values == null || resultValues == null) {
			return resultValues == values;
		}

		return CollectionUtils.isEqualCollection(values, resultValues);
	}

	/**
	 * First value matching namespace or as fallback, matching name and has a namespace
	 * (i.e. attribute with a same name but differing namespace).
	 */
	public static List<String> findValueByNamespaceUriOrName(Map<? extends AttributeName, List<String>> attributes,
			AttributeName attributeName) {
		for (var entry : attributes.entrySet()) {
			var attrDef = entry.getKey();
			if (attributeName.equalsByNamespace(attrDef)) {
				return entry.getValue();
			}
		}
		// fallback
		for (var entry : attributes.entrySet()) {
			var attrDef = entry.getKey();
			if (attrDef.getNamespaceUri() != null && attributeName.equalsByName(attrDef)) {
				return entry.getValue();
			}
		}
		return Collections.emptyList();
	}

	private static void checkAmbiguities(Map<? extends AttributeName, ?> result, String name, String source) {
		if (result.size() > 1) {
			var availableSources = result.keySet().stream()
					.filter(k -> source == null || k.getSource().equals(source))
					.map(k -> k.getSource())
					.toList();
			log.warn("Ambiguous access to attributeName={} source={} (HINT: Add one of availableSources='{}' to clarify)",
					name, source, availableSources);
		}
	}

	public static Definition getOrCreateDefinition(String name, String namespaceUri, String source, Map<Definition, List<String>> attributes) {
		var ret = findByNameAndNamespace(name, namespaceUri, null, attributes);

		if (ret.isPresent()) {
			var definition = ret.get().getKey();
			return definition.toBuilder().source(source).build();
		}
		return Definition.ofNamesAndSource(name, namespaceUri, source);
	}
}
