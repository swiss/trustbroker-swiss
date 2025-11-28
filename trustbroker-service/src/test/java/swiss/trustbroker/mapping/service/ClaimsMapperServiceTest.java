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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsMapper;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.MultiResultPolicy;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = ClaimsMapperService.class)
class ClaimsMapperServiceTest {

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@Autowired
	private ClaimsMapperService claimsMapperService;

	@Test
	void filterAndCreateCpDefinitionsExceptionTest() {
		var confAttributes = Collections.singletonList(new Definition("attr1"));
		assertThrows(TechnicalException.class, () ->
				ClaimsMapperService.filterAndCreateCpDefinitions(null, confAttributes, null, "cpIssuer"));
	}

	@Test
	void filterAndCreateCpDefinitionsIsEmptyTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Collection<Definition> confAttributes = Collections.emptyList();

		Map<Definition, List<String>> result = ClaimsMapperService.filterAndCreateCpDefinitions(attributes, confAttributes,
				null, "cpIssuer");

		assertTrue(result.isEmpty(), "Result should be an empty map when confAttributes is empty.");
	}

	@Test
	void filterAndCreateCpDefinitionsTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Definition definition1 = new Definition("attr1");
		Definition definition2 = new Definition("attr2");

		List<String> values1 = Arrays.asList("value1", "value2");
		List<String> values2 = Arrays.asList("value3", "value4");

		attributes.put(definition1, values1);
		attributes.put(definition2, values2);

		Collection<Definition> confAttributes = List.of(definition1);

		Map<Definition, List<String>> result = ClaimsMapperService.filterAndCreateCpDefinitions(attributes, confAttributes,
				null, "cpIssuer");

		assertEquals(1, result.size());
		assertTrue(result.containsKey(definition1));
	}

	@Test
	void filterAndCreateCpDefinitionsNoConfTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Definition definition1 = new Definition("attr1");
		Definition definition2 = new Definition("attr2");

		List<String> values1 = Arrays.asList("value1", "value2");
		List<String> values2 = Arrays.asList("value3", "value4");

		attributes.put(definition1, values1);
		attributes.put(definition2, values2);

		Collection<Definition> confAttributes = Collections.emptyList();

		Map<Definition, List<String>> result = ClaimsMapperService.filterAndCreateCpDefinitions(attributes, confAttributes,
				null, "cpIssuer");

		assertEquals(0, result.size());
	}

	@Test
	void applyMappers() {
		var timeBoolean = Definition.builder()
									.name("time-boolean")
									.mappers(StringUtils.joinWith(",",
											ClaimsMapper.TIME_EPOCH.name(), ClaimsMapper.BOOLEAN.name()))
									.build();
		var inputs = Map.of(timeBoolean, List.of(Instant.ofEpochSecond(1234)
														.toString(), "TRUE"));
		var result = claimsMapperService.applyMappers(inputs, "test");

		// TIME_EPOCH converts first, BOOLEAN second element
		assertThat(result, is(Map.of(timeBoolean, List.of("1234", "true"))));
		verifyNoInteractions(scriptService);
	}

	@Test
	void applyMapperScript() {
		List<Object> scriptResult = List.of(Instant.ofEpochSecond(100_000));
		var script = "TimeBoolean.groovy";
		var scriptTime = Definition.builder()
								   .name(script)
								   .mappers(StringUtils.joinWith(",",
										   ClaimsMapper.SCRIPT.name(), ClaimsMapper.TIME_EPOCH.name()))
								   .build();
		doReturn(scriptResult).when(scriptService)
							  .processValueConversion(script, List.of("test"));

		var result = claimsMapperService.applyMappers(Map.of(scriptTime, List.of("test")), "unit-test");

		// scriptResult run through TIME_EPOCH mapper
		assertThat(result, is(Map.of(scriptTime, List.of("100000"))));
	}

	@Test
	void applyMapperIgnore() {
		var attrWithIgnore = Definition.builder()
				.name("attribute")
				.mappers(ClaimsMapper.IGNORE.name())
				.build();
		var inputs = Map.of(attrWithIgnore, List.of("anyData"));
		var result = claimsMapperService.applyMappers(inputs, "test");

		assertEquals(0 , result.size());
		verifyNoInteractions(scriptService);
	}

	@Test
	void applyMapperString() {
		var attr = Definition.builder()
				.name("attribute")
				.mappers(ClaimsMapper.STRING.name())
				.build();

		var stringInput = "anything";
		var result = claimsMapperService.applyMappers(attr, List.of(stringInput), "test");
		assertEquals(1 , result.size());
		assertThat(result.get(0) instanceof String, is(true));
		assertEquals(stringInput, result.get(0));

		var now = LocalDate.now();
		result = claimsMapperService.applyMappers(attr, List.of(now), "test");
		assertEquals(1 , result.size());
		assertThat(result.get(0) instanceof String, is(true));
		assertEquals(now.toString(), result.get(0));

		var longInput = 123L;
		result = claimsMapperService.applyMappers(attr, List.of(longInput), "test");
		assertEquals(1 , result.size());
		assertThat(result.get(0) instanceof String, is(true));
		assertEquals(String.valueOf(longInput), result.get(0));

		var booleanInput = true;
		result = claimsMapperService.applyMappers(attr, List.of(booleanInput), "test");
		assertEquals(1 , result.size());
		assertThat(result.get(0) instanceof String, is(true));
		assertEquals(String.valueOf(booleanInput), result.get(0));
	}

	@Test
	void applyMapperEpochString() {
		var attr = Definition.builder()
				.name("timeAttr")
				.mappers(StringUtils.joinWith(",",
						ClaimsMapper.TIME_EPOCH.name(), ClaimsMapper.STRING.name()))
				.build();
		var now = LocalDate.now();
		var inputs = Map.of(attr, List.of(now.toString()));
		var result = claimsMapperService.applyMappers(inputs, "test");

		assertEquals(1 , result.size());
		assertEquals(String.valueOf(TimeUnit.DAYS.toSeconds(now.toEpochDay())), result.get(attr).get(0));
	}

	@Test
	void applyProfileSelectionTest() {
		var cpResponse = givenCpResponse();
		var userDetails = cpResponse.getUserDetails();

		claimsMapperService.applyProfileSelection(cpResponse, null);
		assertEquals(userDetails, cpResponse.getUserDetails());

		Map<AttributeName, List<String>> psUserDetails = givenPSResultUserDetails();
		var psResult = ProfileSelectionResult.builder()
											 .filteredAttributes(psUserDetails)
											 .build();
		claimsMapperService.applyProfileSelection(cpResponse, psResult);
		assertNotEquals(userDetails, cpResponse.getUserDetails());
		assertTrue(cpResponse.getUserDetails()
							 .entrySet()
				.stream()
				.anyMatch(map -> map.getKey()
									.getName()
									.equals(CoreAttributeName.CLAIMS_NAME.getName())));
	}

	@Test
	void deduplicatedRpAttributesTest() {
		Map<Definition, List<String>> userDetailMap = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		var result = claimsMapperService.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);

		assertTrue(result.isEmpty(), "Result should be an empty map when the userDetailMap is empty.");

		Definition definition1 = new Definition("attr1", CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		List<String> values1 = List.of("value1");
		Definition definition2 = new Definition("attr2");
		List<String> values2 = List.of("value2");
		Definition definition3 = new Definition("attr3", CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		userDetailMap.put(definition1, values1);
		userDetailMap.put(definition2, values2);
		userDetailMap.put(definition3, values1);

		result = claimsMapperService.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);
		assertFalse(result.isEmpty());
		assertTrue(result.size() < userDetailMap.size());

		properties.put(definition3, values1);
		result = claimsMapperService.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);
		assertFalse(result.isEmpty());
		assertTrue(result.size() < userDetailMap.size());
	}

	@Test
	void attributeToDropEmptyTest() {
		var definition = new Definition("attr1");
		List<String> attributesToBeDropped = Collections.emptyList();
		Map<Definition, List<String>> userDetails = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		var constAttributes = mock(ConstAttributes.class);

		boolean result =
				ClaimsMapperService.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertFalse(result, "Result should be false when attributesToBeDropped is empty.");
	}

	@Test
	void attributeToDropNoInListTest() {
		Definition definition = Definition.ofNames(CoreAttributeName.FIRST_NAME);
		List<String> attributesToBeDropped = List.of("otherAttr");
		Map<Definition, List<String>> userDetails = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		boolean result =
				ClaimsMapperService.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertFalse(result, "Result should be false when the attribute is not in the list of attributes to be dropped.");
	}

	@Test
	void attributeToDropInListTest() {
		Definition definition = Definition.ofNames(CoreAttributeName.FIRST_NAME);
		List<String> attributesToBeDropped = Collections.singletonList(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		Map<Definition, List<String>> userDetails = new HashMap<>();
		userDetails.put(definition, List.of("someValue"));
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		boolean result =
				ClaimsMapperService.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertTrue(result, "Result should be true when the attribute is in the list and is present in userDetails.");
	}

	@ParameterizedTest
	@CsvSource(value = {
			"CP | null | cp-value",
			"IDM | null | idm-value-q1,idm-value-q2",
			"IDM:Q1 | null | idm-value-q1",
			"IDM:Q2 | null | idm-value-q2",
			"SCRIPT | null | idm-value-groovy",
			"PROPS | null | props-value-props",
			"CONFIG | const | const"
	}, nullValues = "null", delimiterString = " | ")
	void applyFinalAttributeMapping(String source, String defValue, String expectedValues) {
		var claim = "a1";
		var fqClaim = "fq-a1";
		var selection = AttributesSelection
				.builder()
				.definitions(List.of(Definition.ofNamesAndSource(claim, fqClaim, null)))
				.build();
		var relyingParty = RelyingParty
				.builder()
				.id("testRp")
				.claimsSelection(selection)
				.build();
		var params = ResponseParameters
				.builder()
				.rpIssuerId(relyingParty.getId())
				.build();
		var claimsParty = ClaimsParty.builder()
									 .id("testCp")
									 .build();

		// data
		var cpResponse = CpResponse
				.builder()
				// CP attributes
				.issuer(claimsParty.getId())
				.attributes(Map.of(
						Definition.ofNamesAndSource(claim, fqClaim, "CP"), List.of("cp-value")
				))
				// IDM user details (source null until applied through query and claims selections)
				.userDetails(new HashMap<>(Map.of(
						Definition.ofNamesAndSource(claim, null, "IDM:Q0"), List.of("idm-value-q0"),
						Definition.ofNamesAndSource(claim, fqClaim, "IDM:Q1"), List.of("idm-value-q1"),
						Definition.ofNamesAndSource(claim, fqClaim, "IDM:Q2"), List.of("idm-value-q2")
				)))
				// computed properties
				.properties(Map.of(
						Definition.ofNamesAndSource(claim, fqClaim, "PROPS"), List.of("props-value-props")
				))
				// OIDC claims
				.claims(Map.of(claim, List.of("claims-value")))
				.build();

		// selection
		var querySourceToks = source.split(":");
		var claimSource = ClaimSource.valueOf(querySourceToks[0]);
		switch (claimSource) {
			case CP:
				relyingParty.setAttributesSelection(selection);
				break;
			case IDM:
				var queries = new ArrayList<IdmQuery>();
				if (querySourceToks.length > 1) {
					queries.add(IdmQuery.builder().name(querySourceToks[1]).userDetailsSelection(selection).build());
				}
				else {
					queries.add(IdmQuery.builder().name("Q1").userDetailsSelection(selection).build());
					queries.add(IdmQuery.builder().name("Q2").userDetailsSelection(selection).build());
				}
				relyingParty.setIdmLookup(IdmLookup
						.builder()
						.queries(queries)
						.multiQueryPolicy(MultiResultPolicy.MERGE)
						.build());
				break;
			case CONFIG:
				selection.getDefinitions()
						 .get(0)
						 .setValue(defValue);
				relyingParty.setPropertiesSelection(selection);
				break;
			case SCRIPT:
				cpResponse.setUserDetail(claim, fqClaim, "idm-value-groovy");
				relyingParty.setClaimsSelection(selection);
				break;
			case PROPS:
				relyingParty.setPropertiesSelection(selection);
				break;
			default:
				throw new TechnicalException("Unexpected source " + source);
		}

		// pick
		doReturn(relyingParty)
				.when(relyingPartySetupService)
				.getRelyingPartyByIssuerIdOrReferrer(params.getRpIssuerId(), params.getRpReferer());
		doReturn(claimsParty)
				.when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(claimsParty.getId(), null);
		claimsMapperService.applyFinalAttributeMapping(cpResponse, params, "dest", relyingParty);

		// assert
		var expectedList = List.of(expectedValues.split(","));
		var expectedFirst = expectedValues.split(",")[0];
		switch (claimSource) {
			case CP:
				assertThat(cpResponse.getAttributes(claim), is(expectedList));
				assertThat(cpResponse.getAttribute(claim), is(expectedFirst));
				break;
			case IDM, SCRIPT:
				assertThat(cpResponse.getUserDetails(claim), is(expectedList));
				assertThat(cpResponse.getUserDetail(claim), is(expectedFirst));
				break;
			case PROPS, CONFIG:
				assertThat(cpResponse.getProperties(claim, source), is(expectedList));
				assertThat(cpResponse.getProperty(claim, source), is(expectedFirst));
				break;
		}
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(new Definition(CoreAttributeName.EMAIL), List.of("email"));
		return CpResponse.builder()
						 .attributes(attributeValueMap)
						 .userDetails(givenUserDetails())
						 .build();
	}

	private static Map<Definition, List<String>> givenUserDetails() {
		return Map.of(
				Definition.ofNames(CoreAttributeName.FIRST_NAME), List.of(
						"first_name_1"),
				Definition.ofNames(CoreAttributeName.NAME), List.of(
						"family_name_1"));
	}

	private static Map<AttributeName, List<String>> givenPSResultUserDetails() {
		return Map.of(
				SamlTestBase.TestAttributeName.of(CoreAttributeName.CLAIMS_NAME), List.of(
						"first_name_1"),
				SamlTestBase.TestAttributeName.of(CoreAttributeName.NAME), List.of(
						"family_name_1"));
	}

}
