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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.MultiResultPolicy;
import swiss.trustbroker.saml.dto.ClaimSource;

@SpringBootTest
@ContextConfiguration(classes = AttributeFilterUtil.class)
class AttributeFilterUtilTest {

	@ParameterizedTest
	@CsvSource(value = {
			"FirstName,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,null",
			"FirstName,null,null",
			"null,null,null",
			"EMail,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,EMail",
			"ClaimsName,null,ClaimsName",
	}, nullValues = "null")
	void getDefinitionFromMapTest(String name, String namespaceUri, String result) {
		var map = givenUserDetails();
		var definition = Definition.builder()
										  .name(name)
										  .namespaceUri(namespaceUri)
										  .build();

		var definitionFromMap = AttributeFilterUtil.getDefinitionFromMap(map, definition);
		if (result == null) {
			assertNull(definitionFromMap);
		}
		else {
			assertEquals(result, definitionFromMap.getName());
		}
	}

	@Test
	void getAttributeValueIfRequiredForOutputTest() {
		var claimsName = new Definition(CoreAttributeName.EMAIL);
		assertFalse(AttributeFilterUtil
				.getAttributeValueIfRequiredForOutput(Collections.emptyMap(), claimsName, "ANU").isPresent());

		assertFalse(AttributeFilterUtil
				.getAttributeValueIfRequiredForOutput(givenUserDetails(), claimsName, ClaimSource.IDM.name() +":NAMEID").isPresent());

		assertTrue(AttributeFilterUtil
				.getAttributeValueIfRequiredForOutput(givenUserDetails(), claimsName, ClaimSource.IDM.name() +":TENANT").isPresent());

	}

	private static Map<Definition, List<String>> givenUserDetails() {
		Map<Definition, List<String>> userDetails = new LinkedHashMap<>();
		var email = Definition.builder()
							  .name(CoreAttributeName.EMAIL.getName())
							  .namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
							  .source("IDM:TENANT")
							  .build();
		var userExtId = Definition.builder()
								  .name(CoreAttributeName.CLAIMS_NAME.getName())
								  .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
								  .source("IDM:IDENTITY")
								  .build();
		var convId = Definition.builder()
							   .name(CoreAttributeName.CONVERSATION_ID.getName())
							   .namespaceUri(CoreAttributeName.CONVERSATION_ID.getNamespaceUri())
							   .build();
		userDetails.put(email, new ArrayList<>(Arrays.asList("user@trustbroker.swiss")));
		userDetails.put(userExtId, new ArrayList<>(Arrays.asList("idm98765")));
		userDetails.put(convId, new ArrayList<>(Arrays.asList("tmp-2324")));

		return userDetails;
	}

	@Test
	void filterPropertiesTest() {
		var attributesSelection = givenAttributesSelection();
		var claimsSelection = givenClaimsSelection();

		assertEquals(2, AttributeFilterUtil.filterProperties(givenUserDataMap(), attributesSelection, claimsSelection).size());

		var claimsName = new Definition(CoreAttributeName.CLAIMS_NAME);
		claimsName.setSource(ClaimSource.PROPS.name());
		claimsSelection.getDefinitions().add(claimsName);
	}

	private static Map<Definition, List<String>> givenUserDataMap() {
		Map<Definition, List<String>> userDetails = new LinkedHashMap<>();
		var email = Definition.builder()
							  .name(CoreAttributeName.EMAIL.getName())
							  .namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
							  .build();
		var userExtId = Definition.builder()
								  .name(CoreAttributeName.CLAIMS_NAME.getName())
								  .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
								  .build();
		var convId = Definition.builder()
								  .name(CoreAttributeName.CONVERSATION_ID.getName())
								  .namespaceUri(CoreAttributeName.CONVERSATION_ID.getNamespaceUri())
								  .build();
		userDetails.put(email, List.of("user@trustbroker.swiss"));
		userDetails.put(userExtId, List.of("idm98765"));
		userDetails.put(convId, List.of("tmp-2324"));

		return userDetails;
	}

	private AttributesSelection givenClaimsSelection() {
		List<Definition> definitions = new ArrayList<>();
		var authLevel = new Definition(CoreAttributeName.AUTH_LEVEL);
		authLevel.setSource(ClaimSource.CP.name());
		definitions.add(authLevel);

		var email = new Definition(CoreAttributeName.EMAIL);
		email.setSource(ClaimSource.PROPS.name());
		definitions.add(email);

		var convId = new Definition(CoreAttributeName.CONVERSATION_ID);
		convId.setSource(ClaimSource.PROPS.name());
		definitions.add(convId);

		AttributesSelection attributesSelection = new AttributesSelection();
		attributesSelection.setDefinitions(definitions);

		return attributesSelection;
	}

	@Test
	void getClaimsForSourceTest() {
		assertEquals(0, AttributeFilterUtil.getClaimsForSource(givenAttributesSelection(), "IDM").size());
		assertEquals(0, AttributeFilterUtil.getClaimsForSource(null, "CP").size());
		assertEquals(1, AttributeFilterUtil.getClaimsForSource(givenAttributesSelection(), "CP").size());
	}

	@Test
	void claimMustBeInResponseTest() {
		assertFalse(AttributeFilterUtil.claimMustBeInResponse(
				new Definition(CoreAttributeName.HOME_REALM), Collections.emptyList()));
		assertTrue(AttributeFilterUtil.claimMustBeInResponse(
				new Definition(CoreAttributeName.EMAIL), givenDefinitionList()));
		assertFalse(AttributeFilterUtil.claimMustBeInResponse(
				new Definition(CoreAttributeName.HOME_REALM), givenDefinitionList()));
	}

	@Test
	void attributeMustBeInResponseTest() {
		assertFalse(AttributeFilterUtil.attributeMustBeInResponse(
				new Definition(CoreAttributeName.FIRST_NAME), null));
		assertTrue(AttributeFilterUtil.attributeMustBeInResponse(
				new Definition(CoreAttributeName.HOME_REALM), givenAttributesSelection()));
		assertFalse(AttributeFilterUtil.attributeMustBeInResponse(
				new Definition(CoreAttributeName.FIRST_NAME), givenAttributesSelection()));
	}

	private AttributesSelection givenAttributesSelection() {
		List<Definition> definitions = new ArrayList<>();
		definitions.add(new Definition(CoreAttributeName.EMAIL));
		definitions.add(new Definition(CoreAttributeName.HOME_REALM));

		var authLevel = new Definition(CoreAttributeName.AUTH_LEVEL);
		authLevel.setSource("CP");
		definitions.add(authLevel);

		AttributesSelection attributesSelection = new AttributesSelection();
		attributesSelection.setDefinitions(definitions);

		return attributesSelection;
	}

	@Test
	void addDefToCollectionTest() {
		List<Definition> confAttributes = givenDefinitionList();

		assertTrue(AttributeFilterUtil.addDefToCollection(new Definition(CoreAttributeName.CLAIMS_NAME), confAttributes));
		assertFalse(AttributeFilterUtil.addDefToCollection(new Definition(CoreAttributeName.NAME), confAttributes));
	}

	private List<Definition> givenDefinitionList() {
		List<Definition> definitions = new ArrayList<>();
		definitions.add(Definition.builder()
								  .name(CoreAttributeName.NAME.getName())
								  .namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
								  .build());
		definitions.add(Definition.builder()
								  .name(CoreAttributeName.EMAIL.getName())
								  .namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
								  .oidcNames("email")
								  .build());
		return definitions;
	}

	@Test
	void mergeValuesTest() {
		Map<Definition, List<String>> userDetails = givenUserDetails();
		Map.Entry<Definition, List<String>> entry = givenEntryToFilterAttributes(CoreAttributeName.COUNTRY);

		AttributeFilterUtil.mergeValues(userDetails, entry);
		assertEquals(2, entry.getValue().size());

		entry = givenEntryToFilterAttributes(CoreAttributeName.EMAIL);
		AttributeFilterUtil.mergeValues(userDetails, entry);
		assertEquals(3, entry.getValue().size());
		assertTrue(entry.getValue().contains(entry.getValue().get(0)));

		// add only deduplicated value
		AttributeFilterUtil.mergeValues(userDetails, entry);
		assertEquals(3, entry.getValue().size());
		assertTrue(entry.getValue().contains(entry.getValue().get(0)));
	}

	static Map.Entry<Definition, List<String>> givenEntryToFilterAttributes(CoreAttributeName attribute) {
		var key = Definition.builder()
							.name(attribute.getName())
							.namespaceUri(attribute.getNamespaceUri())
							.source("source")
							.build();
		List<String> values = new ArrayList<>();
		values.add("value1");
		values.add("value2");
		return new AbstractMap.SimpleEntry<>(key, values);
	}

	@Test
	void removeSameDefTest() {
		Map<Definition, List<String>> targetMap = givenUserDetails();
		Map<Definition, List<String>> map = givenUserDetails();
		AttributeFilterUtil.removeSameDef(targetMap, map);
		assertTrue(targetMap.isEmpty());

		targetMap = givenUserDetails();
		targetMap.put(Definition.builder()
								.name(CoreAttributeName.COUNTRY.getName())
								.namespaceUri(CoreAttributeName.COUNTRY.getNamespaceUri())
								.build(), List.of("anydata"));
		AttributeFilterUtil.removeSameDef(targetMap, map);
		assertEquals(1, targetMap.size());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"MERGE,FirstName,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,newValue",
			"MERGE,EMail,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,newEmail",
			"OVERWRITE,FirstName,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,newValue",
			"OVERWRITE,EMail,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,newEmail",
			"null,FirstName,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,newValue",
			"null,EMail,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,newEmail"
	}, nullValues = "null")
	void applyMultiQueryPolicyTest(String policy, String name, String namespaceUri, String value) {
		var map = givenUserDetails();
		var def = Definition.builder()
								   .name(name)
								   .namespaceUri(namespaceUri)
								   .build();
		var values = new ArrayList<String>();
		values.add(value);
		MultiResultPolicy multiQueryPolicy = policy != null ? MultiResultPolicy.valueOf(policy) : null;
		AttributeFilterUtil.applyMultiQueryPolicy(multiQueryPolicy, map, def, values);
		Optional<Map.Entry<Definition, List<String>>> mapEntry = map.entrySet()
				.stream()
				.filter(entry -> entry.getKey().getNamespaceUri() != null && entry.getKey().getNamespaceUri().equals(namespaceUri))
				.findFirst();
		assertTrue(mapEntry.isPresent());
		assertTrue(mapEntry.get().getValue().contains(value));
	}
}
