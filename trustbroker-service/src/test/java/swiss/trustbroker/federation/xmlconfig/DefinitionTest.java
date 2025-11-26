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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalToObject;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;

class DefinitionTest {

	@BeforeAll
	static void setup() {
		new CoreAttributeInitializer().init();
	}

	@Test
	void testKeyConstructors() {
		// via AttributeName
		var nameAttr = CoreAttributeName.NAME;
		var nameShort = new Definition(nameAttr.getName());
		var nameShortSrc = new Definition(nameAttr.getName());
		nameShortSrc.setSource("nameSource1");
		var nameLong = new Definition(nameAttr.getName(), nameAttr.getNamespaceUri());
		var nameFull = new Definition(nameAttr.getName(), nameAttr.getNamespaceUri());
		nameFull.setSource("nameSource2");
		assertThat(Definition.ofName(nameAttr), is(nameShort));
		assertThat(Definition.ofNameAndSource(nameAttr, "nameSource1"), is(nameShortSrc));
		assertThat(Definition.ofNames(nameAttr), is(nameLong));
		assertThat(Definition.ofNamesAndSource(nameAttr, "nameSource2"), is(nameFull));

		// via string API
		nameFull.setSource("nameSource");
		var short1 = new Definition("shortname1");
		var short2 = new Definition("shortname2");
		short2.setSource("source2");
		var long3 = new Definition("shortname3", "longname3");
		var full4 = new Definition("shortname4", "longname4");
		full4.setSource("source4");

		assertThat(Definition.ofName("shortname1"), is(short1));
		assertThat(Definition.ofNameAndSource("shortname2", "source2"), is(short2));
		assertThat(Definition.ofNames("shortname3", "longname3"), is(long3));
		assertThat(Definition.ofNamesAndSource("shortname4", "longname4", "source4"), is(full4));
	}

	@Test
	void testUniqueKey() {
		var o1 = Definition.builder().name("N1").namespaceUri("FQN1").value("V1").build();
		var o2 = Definition.builder().name("N1").namespaceUri("FQN1").value("V2").build();
		var o3 = Definition.builder().name("N1").namespaceUri("FQN1").build();
		var o4 = Definition.builder().name("N1").namespaceUri("FQN2").build();
		var o5 = Definition.builder().name("N2").namespaceUri("FQN1").build();
		assertThat(o1, equalToObject(o2));
		assertThat(o1, equalToObject(o3));
		assertThat(o1, not(equalToObject(o4)));
		assertThat(o1, not(equalToObject(o5)));
	}

	@Test
	void testFindAttributeName() {
		var definition = new Definition(CoreAttributeName.NAME.getNamespaceUri());
		assertThat(definition.getName(), is(CoreAttributeName.NAME.getNamespaceUri()));
		assertThat(definition.getNamespaceUri(), is(nullValue()));
		assertThat(definition.findAttributeName(), is(CoreAttributeName.NAME));

		definition = Definition.ofName(CoreAttributeName.HOME_NAME);
		assertThat(definition.getName(), is(CoreAttributeName.HOME_NAME.getName()));
		assertThat(definition.getNamespaceUri(), is(nullValue()));
		assertThat(definition.findAttributeName(), is(CoreAttributeName.HOME_NAME));

		definition = new Definition(CoreAttributeName.CLAIMS_NAME);
		assertThat(definition.getName(), is(CoreAttributeName.CLAIMS_NAME.getName()));
		assertThat(definition.getNamespaceUri(), is(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()));
		assertThat(definition.findAttributeName(), is(CoreAttributeName.CLAIMS_NAME));
	}

	@ParameterizedTest
	@MethodSource
	void testEqualsByNameOrNamespace(Definition definition1, Definition definition2, boolean equals) {
		assertThat(definition1.equalsByNameOrNamespace(definition2), is(equals));
		if (definition2 != null) {
			assertThat(definition2.equalsByNameOrNamespace(definition1), is(equals));
		}
	}

	static Object[][] testEqualsByNameOrNamespace() {
		return new Object[][] {
				{ new Definition(CoreAttributeName.NAME.getName()), null, false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(null, null), false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME_ID), false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME), true },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME.getName()), true },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(null, CoreAttributeName.NAME.getName()), true },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()), new Definition(CoreAttributeName.NAME), true },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()),
						new Definition(null, CoreAttributeName.NAME.getNamespaceUri()), true },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()), new Definition(CoreAttributeName.NAME), true },
				{ new Definition(CoreAttributeName.NAME), new Definition(CoreAttributeName.NAME), true }
		};
	}

	@ParameterizedTest
	@MethodSource
	void testEqualsByNameAndNamespace(Definition definition1, Definition definition2, boolean equals) {
		assertThat(definition1.equalsByNameAndNamespace(definition2), is(equals));
		if (definition2 != null) {
			assertThat(definition2.equalsByNameAndNamespace(definition1), is(equals));
		}
	}

	static Object[][] testEqualsByNameAndNamespace() {
		return new Object[][] {
				{ new Definition(CoreAttributeName.NAME.getName()), null, false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(null, null), false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME_ID), false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME), false },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(CoreAttributeName.NAME.getName()), true },
				{ new Definition(CoreAttributeName.NAME.getName()), new Definition(null, CoreAttributeName.NAME.getName()), false },
				{ new Definition(null, CoreAttributeName.NAME.getNamespaceUri()),
						new Definition(null, CoreAttributeName.NAME.getNamespaceUri()), true },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()), new Definition(CoreAttributeName.NAME), false },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()),
						new Definition(null, CoreAttributeName.NAME.getNamespaceUri()), false },
				{ new Definition(CoreAttributeName.NAME.getNamespaceUri()), new Definition(CoreAttributeName.NAME), false },
				{ new Definition(CoreAttributeName.NAME), new Definition(CoreAttributeName.NAME), true }
		};
	}

	@ParameterizedTest
	@MethodSource
	void testEqualsByNameOrNamespaceString(Definition definition, String name, boolean equals) {
		assertThat(definition.equalsByNameOrNamespace(name), is(equals));
	}

	static Object[][] testEqualsByNameOrNamespaceString() {
		return new Object[][] {
				{ new Definition(CoreAttributeName.NAME.getName()), null, false },
				{ new Definition(CoreAttributeName.NAME.getName()), CoreAttributeName.NAME_ID.getName(), false },
				{ new Definition(CoreAttributeName.NAME.getName()), CoreAttributeName.NAME.getName(), true },
				{ new Definition(null, CoreAttributeName.NAME.getNamespaceUri()),
						CoreAttributeName.NAME.getNamespaceUri(), true },
				{ new Definition(CoreAttributeName.NAME), CoreAttributeName.NAME.getName(), true },
				{ new Definition(CoreAttributeName.NAME), CoreAttributeName.NAME.getNamespaceUri(), true },
		};
	}

	@ParameterizedTest
	@MethodSource
	@SuppressWarnings("deprecation")
	void testGetMappers(String mappers, ClaimsMapper oidcMapper, List<ClaimsMapper> expectedMappers) {
		var definition = Definition.builder()
				.mappers(mappers)
				.oidcMapper(oidcMapper) // oidcMapper fallback
				.build();
		assertThat(definition.getClaimsMappers(), is(expectedMappers));
	}

	static Object[][] testGetMappers() {
		return new Object[][] {
				{ null, null, Collections.emptyList() },
				{ "", ClaimsMapper.EMAIL, List.of(ClaimsMapper.EMAIL) },
				{ StringUtils.joinWith(Definition.LIST_ATTRIBUTE_DELIMITER,
						ClaimsMapper.EMAIL.name(), ClaimsMapper.TIME_EPOCH.name()),
						ClaimsMapper.BOOLEAN, // oidcMapper ignored
						List.of(ClaimsMapper.EMAIL, ClaimsMapper.TIME_EPOCH) }
		};
	}

	@Test
	void putOrRemoveCpAttributeValuesTest() {
		Map<AttributeName, List<String>> attributes = givenAttributeMap();
		var initialSize = attributes.size();
		DefinitionUtil.putOrRemoveCpAttributeValues(attributes, CoreAttributeName.FIRST_NAME.getName(),
				CoreAttributeName.FIRST_NAME.getNamespaceUri(), null, null);
		assertTrue(attributes.size() < initialSize);

		DefinitionUtil.putOrRemoveCpAttributeValues(attributes,  CoreAttributeName.FIRST_NAME.getName(),
				CoreAttributeName.FIRST_NAME.getNamespaceUri(), "anySource", List.of("values"));
		assertEquals(attributes.size(), initialSize);
	}


	private static Map<AttributeName, List<String>> givenAttributeMap() {
		Map<AttributeName, List<String>> map = new HashMap<>();
		map.put(Definition.builder()
						  .name(CoreAttributeName.FIRST_NAME.getName())
						  .namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
						  .build(),
				List.of("name1"));
		map.put(CoreAttributeName.CLAIMS_NAME, List.of("wrong"));
		return map;
	}
}
