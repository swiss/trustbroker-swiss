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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@ExtendWith(MockitoExtension.class)
class DefinitionUtilTest {

	@Mock
	private ScriptService scriptService;

	@BeforeAll
	static void setUp() {
		// for findSingleValueByNameOrNamespace
		new CoreAttributeInitializer().init();
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_NAME);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.CLAIMS_NAME);
	}

	@ParameterizedTest
	@MethodSource
	void truncateNamespace(String input, String result) {
		assertThat(DefinitionUtil.truncateNamespace(input), is(result));
	}

	static String[][] truncateNamespace() {
		return new String[][] {
				{ null, null },
				{ "", null },
				{ "https://domain/path/name/", null },
				{ "simpleName", null },
				{ "https://domain/path/name", "name" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void findByNameOrNamespace(String inputName, String definitionName, String definitionNamespace, String expected) {
		var definition = new Definition(definitionName, definitionNamespace);
		Map<Definition, String> input = Map.of(Definition.ofName(CoreAttributeName.NAME), "other", definition, expected);
		Map<AttributeName, String> inputCp = new HashMap<>(input);
		var result = DefinitionUtil.findByNameOrNamespace(inputName, null, input);
		validateAttributes(expected, result, definition);

		var resultDefinition = DefinitionUtil.findByNameOrNamespace(new Definition(inputName), null, input);
		validateAttributes(expected, resultDefinition, definition);

		var resultCp = DefinitionUtil.findByNameOrNamespace(inputName, null, inputCp);
		validateAttributes(expected, resultCp, definition);
	}

	static String[][] findByNameOrNamespace() {
		return new String[][] {
				{ "attribute1", "attribute1", "https://domain/path/name", "value1" },
				{ "https://domain/path/name", "attribute1", "https://domain/path/name", "value1" },
				{ "other", "attribute1", "https://domain/path/name", "" },
		};
	}

	private static <T extends AttributeName, V> void validateAttributes(String expected, Optional<Map.Entry<T, String>> result,
			Definition definition) {
		if (expected.isEmpty()) {
			assertThat(result.isPresent(), is(false));
		}
		else {
			assertThat(result.isPresent(), is(true));
			assertThat(result.get().getKey(), is(definition));
			assertThat(result.get().getValue(), is(expected));
		}
	}

	@ParameterizedTest
	@MethodSource
	void findListByNameOrNamespace(String inputName, String definitionName, String definitionNamespace, List<String> expected) {
		var source = "source1";
		var definition = new Definition(definitionName, definitionNamespace);
		definition.setSource(source);
		// empty expected indicate not found, put a dummy value in the map to distinguish it from found empty list
		var values = expected.isEmpty() ? List.of("dummy") : expected;
		Map<Definition, List<String>> input =
				Map.of(Definition.ofName(CoreAttributeName.NAME), List.of("other"), definition, values);
		var result = DefinitionUtil.findListByNameOrNamespace(inputName, null, input);
		assertThat(result, is(expected));

		var resultDefinition = DefinitionUtil.findListByNameOrNamespace(new Definition(inputName), null, input);
		assertThat(result, is(resultDefinition));

		var resultOtherSource = DefinitionUtil.findListByNameOrNamespace(definition, "source2", input);
		assertThat(resultOtherSource, is(Collections.emptyList()));

		var resultSource = DefinitionUtil.findListByNameOrNamespace(definition, source, input);
		assertThat(resultSource, is(values));

		var expectedValue = expected.isEmpty() ? null : expected.get(0);
		var singleValue = DefinitionUtil.findSingleValueByNameOrNamespace(inputName, null, input);
		assertThat(singleValue, is(expectedValue));

		var singleValueDefinition = DefinitionUtil.findSingleValueByNameOrNamespace(new Definition(inputName), null, input);
		assertThat(singleValueDefinition, is(expectedValue));

		var singleValueOtherSource = DefinitionUtil.findSingleValueByNameOrNamespace(definition, "source2", input);
		assertThat(singleValueOtherSource, is(nullValue()));

		var singleValueSource = DefinitionUtil.findSingleValueByNameOrNamespace(definition, source, input);
		assertThat(singleValueSource, is(values.get(0)));

		Map<AttributeName, List<String>> inputCp =
				Map.of(Definition.ofName(CoreAttributeName.NAME), List.of("other"), definition, values);
		result = DefinitionUtil.findCpAttributeListByNameOrNamespace(inputName, inputCp);
		assertThat(result, is(expected));
	}

	static Object[][] findListByNameOrNamespace() {
		return new Object[][] {
				{ "attribute1", "attribute1", "https://domain/path/name", List.of("value1") },
				{ "https://domain/path/name", "attribute1", "https://domain/path/name", List.of("value1") },
				{ "other", "attribute1", "https://domain/path/name", Collections.emptyList() },
		};
	}

	@ParameterizedTest
	@MethodSource
	void findAllByNameOrNamespace(String inputName, Map<AttributeName, List<String>>  inputAttributes,
			Map<AttributeName, List<String>> expectedAttributes) {
		var result = DefinitionUtil.findAllByNameOrNamespace(inputName, null, inputAttributes);
		assertThat(result, is(expectedAttributes));
	}

	static Object[][] findAllByNameOrNamespace() {
		return new Object[][] {
				{
						CoreAttributeName.FIRST_NAME.getNamespaceUri(),
						givenAttributeMap(),
						givenAttributeMapFilteredByFirstNameNamespaceUri()
				},
				{
						CoreAttributeName.EMAIL.getName(),
						Map.of(CoreAttributeName.FIRST_NAME, List.of("name4"),
								CoreAttributeName.AUTH_LEVEL, List.of("name5")),
						Collections.emptyMap()
				},
		};
	}

	@ParameterizedTest
	@MethodSource
	void findAllAttributesByAttributeNameOrNamespace(AttributeName inputName, Map<AttributeName, List<String>>  inputAttributes,
			Map<AttributeName, List<String>> expectedAttributes) {
		var result = DefinitionUtil.findAllByNameOrNamespace(inputName, null, inputAttributes);
		assertThat(result, is(expectedAttributes));
	}

	static Object[][] findAllAttributesByAttributeNameOrNamespace() {
		return new Object[][] {
				{
						CoreAttributeName.FIRST_NAME,
						givenAttributeMap(),
						givenAttributeMapFilteredByFirstNameNamespaceUri()
				},
				{
						CoreAttributeName.EMAIL,
						Map.of(CoreAttributeName.FIRST_NAME, List.of("name4"),
								CoreAttributeName.AUTH_LEVEL, List.of("name5")),
						Collections.emptyMap()
				},
		};
	}

	private static Map<AttributeName, List<String>> givenAttributeMap() {
		return Map.of(CoreAttributeName.FIRST_NAME, List.of("name1"),
				Definition.ofNames(CoreAttributeName.FIRST_NAME), List.of("name2"),
				CoreAttributeName.CLAIMS_NAME, List.of("wrong"),
				new Definition(null, CoreAttributeName.FIRST_NAME.getNamespaceUri()), List.of("name3"));
	}

	private static Map<AttributeName, List<String>> givenAttributeMapFilteredByFirstNameNamespaceUri() {
		return Map.of(CoreAttributeName.FIRST_NAME, List.of("name1"),
				Definition.ofNames(CoreAttributeName.FIRST_NAME), List.of("name2"),
				new Definition(null, CoreAttributeName.FIRST_NAME.getNamespaceUri()), List.of("name3"));
	}

	@Test
	void mapAttributeList() {
		var firstName = List.of("first1");
		var lastName = List.of("last1");
		Map<AttributeName, List<String>> attributes = Map.of(
				Definition.ofName(CoreAttributeName.NAME), lastName,
				// test Definition implementation that is not Definition
				Definition.ofName(
						SamlTestBase.TestAttributeName.of(CoreAttributeName.FIRST_NAME)), firstName);
		Map<Definition, List<String>> expected = Map.of(
				Definition.builder().name(CoreAttributeName.NAME.getName()).build(), lastName,
				Definition.builder().name(CoreAttributeName.FIRST_NAME.getName()).build(), firstName);

		HashMap<Definition, List<String>> result = new HashMap<>();
		DefinitionUtil.mapAttributeList(attributes, result);
		assertThat(result, is(expected));

		Map<Definition, List<String>> definitions = new HashMap<>();
		DefinitionUtil.mapAttributeList(attributes, definitions);
		assertThat(definitions, is(expected));
	}

	@ParameterizedTest
	@MethodSource
	void putAttributeValue(AttributeName attribute, String value, List<String> expected) {
		var attributeDefinition = Definition.builder()
											   .name(attribute.getName())
											   .namespaceUri(attribute.getNamespaceUri())
											   .build();
		Map<AttributeName, List<String>> cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(cpAttributes, attribute.getName(), attribute.getNamespaceUri(), null, value);
		assertThat(cpAttributes.get(attributeDefinition), is(expected));

		Map<AttributeName, List<String>> attrs = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(attrs, attribute.getName(), attribute.getNamespaceUri(), null, value);
		assertThat(attrs.get(attributeDefinition), is(expected));

		cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(cpAttributes, attribute.getName(), attribute.getNamespaceUri(), null, value);
		assertThat(cpAttributes.get(attributeDefinition), is(expected));

		Map<Definition, List<String>> attributes = new HashMap<>();
		DefinitionUtil.putDefinitionValue(attributes, attribute.getName(), attribute.getNamespaceUri(), null, value);
		assertThat(attributes.get(new Definition(attribute)), is(expected));
	}

	static Object[][] putAttributeValue() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, List.of(DefinitionUtil.VALUE_TO_LIST_NULL) },
				{ CoreAttributeName.NAME, "lastName1", List.of("lastName1") },
		};
	}

	@Test
	void definitionAndValueEqualsTest() {
		var def1 = Definition.builder()
									.name(CoreAttributeName.FIRST_NAME.getName())
									.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
									.build();
		var def2 = Definition.builder()
									.name(CoreAttributeName.EMAIL.getName())
									.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
									.build();

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		def2.setNamespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		assertTrue(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, List.of("any"), def2, null));

		def2.setNamespaceUri(null);
		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		def2.setName(CoreAttributeName.FIRST_NAME.getName());
		assertTrue(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, List.of("any"), def2, null));
	}

	@Test
	void listMatchTest(){
		assertTrue(DefinitionUtil.listMatch(null, null));

		assertTrue(DefinitionUtil.listMatch(List.of("name1", "name2"), List.of("name2", "name1")));

		assertFalse(DefinitionUtil.listMatch(List.of("name1", "name4"), List.of("name2", "name1")));
	}

	@Test
	void mapContainsDefinitionWithValueTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Definition definition = new Definition("attr1");
		List<String> value = List.of("value1");

		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition, value),
				"Result should be false when the attributes map is empty.");

		Definition matchingDefinition = new Definition("attr1");
		attributes.put(matchingDefinition, value);
		assertTrue(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition, value));
		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition,  List.of("othervalue")));

		Definition notMatchingDefinition = new Definition("otherName");
		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, notMatchingDefinition, value));
	}

	@ParameterizedTest
	@MethodSource
	void equalsByName(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByName(second), is(expectedResult));
		assertThat(first.equalsByName(second != null ? second.getName() : null), is(expectedResult));
	}

	static Object[][] equalsByName() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, Definition.ofName(CoreAttributeName.FIRST_NAME), true },
				{ CoreAttributeName.FIRST_NAME, Definition.ofName(CoreAttributeName.NAME), false },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri()), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNamespace(AttributeName first, String namespace, boolean expectedResult) {
		assertThat(first.equalsByNamespace(namespace), is(expectedResult));
	}

	static Object[][] equalsByNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME.getNamespaceUri(), true },
				{ CoreAttributeName.FIRST_NAME, Definition.ofNames(CoreAttributeName.FIRST_NAME).getNamespaceUri(), true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL.getNamespaceUri(), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNameAndNamespace(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByNameAndNamespace(second), is(expectedResult));
	}

	static Object[][] equalsByNameAndNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, Definition.ofNames(CoreAttributeName.FIRST_NAME), true },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getName(),
						CoreAttributeName.NAME_ID.getNamespaceUri()), false },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.HOME_NAME.getName(),
						CoreAttributeName.FIRST_NAME.getNamespaceUri()), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNameOrNamespace(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByNameOrNamespace(second), is(expectedResult));
	}

	static Object[][] equalsByNameOrNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getName(),
						CoreAttributeName.NAME_ID.getNamespaceUri()), true },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.HOME_NAME.getName(),
						CoreAttributeName.FIRST_NAME.getNamespaceUri()), true },
				// AttributeName compares the same type
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(),
						CoreAttributeName.FIRST_NAME.getName()), false },
				// Definition compares cross-wise
				{ new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(), CoreAttributeName.FIRST_NAME.getName()),
						CoreAttributeName.FIRST_NAME, true },
				{ new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(), null),
						CoreAttributeName.FIRST_NAME, true },
				{ new Definition(null, CoreAttributeName.FIRST_NAME.getName()),
						CoreAttributeName.FIRST_NAME, true }
		};
	}

	@ParameterizedTest
	@MethodSource
	<K extends AttributeName> void findSingleValueByNameOrNamespace(List<K> definitions, K key, String source,
			Optional<K> expected) {
		var singleByNameAttribute = DefinitionUtil.findSingleValueByNameOrNamespace(key, source, definitions);
		assertThat(singleByNameAttribute, is(expected));
		var name = key != null ? key.getName() : null;
		var singleByName = DefinitionUtil.findSingleValueByNameOrNamespace(name, source, definitions);
		assertThat(singleByName, is(expected));
		var namespace = key != null ? key.getNamespaceUri() : null;
		var singleByNamespace = DefinitionUtil.findSingleValueByNameOrNamespace(namespace, source, definitions);
		assertThat(singleByNamespace, is(expected));
	}

	static Object[][] findSingleValueByNameOrNamespace() {
		var source1 = "cp";
		var source2 = "idm.tenant";
		List<AttributeName> attributes =
				List.of(CoreAttributeName.CONVERSATION_ID, CoreAttributeName.NAME, CoreAttributeName.FIRST_NAME,
						CoreAttributeName.HOME_NAME);
		var homeName = Definition.builder()
								 .name(CoreAttributeName.HOME_NAME.getName())
								 .namespaceUri(CoreAttributeName.HOME_NAME.getNamespaceUri())
								 .build();
		var claimsName = Definition.builder()
								   .name(CoreAttributeName.CLAIMS_NAME.getName())
								   .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
								   .build();
		List<Definition> definitions = List.of(homeName, claimsName);
		var homeNameSource = Definition.builder()
								 .name(CoreAttributeName.HOME_NAME.getName())
								 .namespaceUri(CoreAttributeName.HOME_NAME.getNamespaceUri())
								 .source(source1)
								 .build();
		var claimsNameSource = Definition.builder()
								 .name(CoreAttributeName.CLAIMS_NAME.getName())
								 .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
								 .source(source2)
								 .build();
		List<Definition> definitionsWithSource = List.of(homeNameSource, claimsNameSource);

		return new Object[][] {
				{ null, null, null, Optional.empty() },
				// AttributeName (no source)
				{ attributes, null, null, Optional.empty() },
				{ attributes, CoreAttributeName.NAME, null, Optional.of(CoreAttributeName.NAME) },
				{ attributes, CoreAttributeName.NAME, source1, Optional.of(CoreAttributeName.NAME) },
				// Definitions without source
				{ definitions, null, null, Optional.empty() },
				{ definitions, CoreAttributeName.FIRST_NAME, null, Optional.empty() },
				{ definitions, CoreAttributeName.HOME_NAME, null, Optional.of(homeName) },
				{ definitions, CoreAttributeName.CLAIMS_NAME, source1, Optional.of(claimsName) },
				{ definitions, CoreAttributeName.CLAIMS_NAME, source2, Optional.of(claimsName) },
				// Definitions with source
				{ definitionsWithSource, null, null, Optional.empty() },
				{ definitionsWithSource, CoreAttributeName.FIRST_NAME, source1, Optional.empty() },
				{ definitionsWithSource, CoreAttributeName.CLAIMS_NAME, source1, Optional.empty() },
				{ definitionsWithSource, CoreAttributeName.HOME_NAME, null, Optional.of(homeNameSource) },
				{ definitionsWithSource, CoreAttributeName.CLAIMS_NAME, source2, Optional.of(claimsNameSource) },
				{ definitionsWithSource, CoreAttributeName.CLAIMS_NAME, "idm", Optional.of(claimsNameSource) } // source prefix
		};
	}


	@ParameterizedTest
	@MethodSource
	void getOrCreateDefinitionTest(String name, String namespace, String source, Map<Definition, List<String>> inputAttributes, String expectedName) {
		var result = DefinitionUtil.getOrCreateDefinition(name, namespace, source, inputAttributes);
		assertThat(expectedName, is(result.getName()));
		assertNotNull(result.getSource());
		if (namespace != null) {
			assertThat(namespace, is(result.getNamespaceUri()));
		}
	}

	static Object[][] getOrCreateDefinitionTest() {

		var attributes = Map.of(
				Definition.ofName(CoreAttributeName.FIRST_NAME), List.of("name1"),
				Definition.ofNamesAndSource(CoreAttributeName.HOME_NAME.getName(), CoreAttributeName.HOME_NAME.getNamespaceUri(), "CP"), List.of("name2"),
				Definition.ofNamesAndSource(CoreAttributeName.CLAIMS_NAME.getName(), CoreAttributeName.CLAIMS_NAME.getNamespaceUri(), "CP"), List.of("name3"));
		return new Object[][]{
				{CoreAttributeName.NAME.getName(), null, "CP", attributes, CoreAttributeName.NAME.getName()},
				{CoreAttributeName.HOME_NAME.getName(), null, "CP", attributes, CoreAttributeName.HOME_NAME.getName()},
				{CoreAttributeName.CLAIMS_NAME.getName(), CoreAttributeName.CLAIMS_NAME.getNamespaceUri(),
						"CP", attributes, CoreAttributeName.CLAIMS_NAME.getName()},
		};
	}

}
