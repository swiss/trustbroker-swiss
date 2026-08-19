/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.ldap.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.saml.dto.CpResponse;

@SpringBootTest(classes = { LdapService.class })
@TestPropertySource(properties = "trustbroker.config.ldap.enabled=true")
class LdapServiceTest {

	@MockitoBean
	LdapClient ldapClient;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@Autowired
	LdapService ldapService;

	@Test
	void getLdapAttributesTest() {
		Map<String, Object> state = new HashMap<>();

		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var rpConfig = givenRpConfig(null);
		var userQuery = rpConfig.getIdmLookup().getQueryList().getFirst();

		doReturn(givenLdapAttributes()).when(ldapClient).search(eq(rpConfig), eq(cpResponse), eq(userQuery), any(), any());

		var ldapResult = new IdmResult();
		ldapService.getLdapAttributes(rpConfig, cpResponse, userQuery, state, ldapResult);
		Map<AttributeName, List<String>> userDetails = ldapResult.getUserDetails();
		assertEquals(3, userDetails.size());
		assertTrue(userDetails.get(Definition.builder().name("uid").source("IDM:LDAP").build()).getFirst().contains("mail"));
		assertEquals(2, userDetails.get(Definition.builder().name("mail").source("IDM:LDAP").build()).size());
		var orgIds = userDetails.get(Definition.builder().name("orgId").source("IDM:LDAP").build());
		assertEquals(3, orgIds.size());
		assertTrue(orgIds.getFirst().contains("mail"));
	}

	@Test
	void getLdapAttributesOrgSelectionTest() {
		Map<String, Object> state = new HashMap<>();
		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var rpConfig = givenRpConfig("orgId");
		var userQuery = rpConfig.getIdmLookup().getQueryList().getFirst();
		var orgQuery = rpConfig.getIdmLookup().getQueryList().get(1);

		doReturn(givenLdapAttributes()).when(ldapClient).search(eq(rpConfig), eq(cpResponse), eq(userQuery), any(), any());
		doReturn(givenOrgs()).when(ldapClient).search(eq(rpConfig), eq(cpResponse), eq(orgQuery), any(), any());

		var ldapResult = new IdmResult();
		ldapService.getLdapAttributes(rpConfig, cpResponse, userQuery, state, ldapResult);
		Map<AttributeName, List<String>> userDetails = ldapResult.getUserDetails();
		assertEquals(3, userDetails.size());
		assertTrue(userDetails.get(Definition.builder().name("uid").source("IDM:LDAP").build()).getFirst().contains("mail"));
		assertEquals(3, userDetails.get(Definition.builder().name("mail").source("IDM:LDAP").build()).size());
		var orgIds = userDetails.get(Definition.builder().name("orgId").source("IDM:LDAP").build());
		assertEquals(3, orgIds.size());
		assertTrue(orgIds.getFirst().contains("mail"));

		var ldapOrgResult = new IdmResult();
		ldapService.getLdapAttributes(rpConfig, cpResponse, orgQuery, state, ldapOrgResult);
		Map<AttributeName, List<String>> userDetailsWithTranslation = ldapOrgResult.getUserDetails();
		assertEquals(4, userDetailsWithTranslation.size());
		assertEquals(3, userDetailsWithTranslation.get(Definition.builder().name("translation").source("IDM:LDAP").build()).size());
	}

	@Test
	void getLdapAttributesUsesStateFallbackWhenSearchReturnsNoAttrs() {
		Map<String, Object> state = new HashMap<>();
		state.put(LdapService.UNPROCESSED_ATTRIBUTES, givenLdapAttributes());

		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		// No ProfileSelection
		var rpConfig = givenRpConfigWithDisabledProfileSelection();
		var userQuery = rpConfig.getIdmLookup().getQueryList().getFirst();

		// No LDAP result
		doReturn(List.of()).when(ldapClient).search(eq(rpConfig), eq(cpResponse), eq(userQuery), any(), any());

		var ldapResult = new IdmResult();
		ldapService.getLdapAttributes(rpConfig, cpResponse, userQuery, state, ldapResult);

		Map<AttributeName, List<String>> userDetails = ldapResult.getUserDetails();
		var mailKey = Definition.builder().name("mail").source("IDM:LDAP").build();
		assertFalse(userDetails.containsKey(mailKey));
	}

	@Test
	void getLdapAttributesPrefersCurrentSearchAttrsOverStateWhenPresent() {
		Map<String, Object> state = new HashMap<>();
		List<Map<String, List<String>>> staleStateAttrs = new ArrayList<>();
		Map<String, List<String>> staleEntry = new HashMap<>();
		staleEntry.put("uid", List.of("staleUid"));
		staleEntry.put("mail", List.of("staleMail"));
		staleEntry.put("orgId", List.of("999"));
		staleStateAttrs.add(staleEntry);
		state.put(LdapService.UNPROCESSED_ATTRIBUTES, staleStateAttrs);

		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var rpConfig = givenRpConfigWithDisabledProfileSelection();
		var userQuery = rpConfig.getIdmLookup().getQueryList().getFirst();

		doReturn(givenLdapAttributes()).when(ldapClient).search(eq(rpConfig), eq(cpResponse), eq(userQuery), any(), any());

		var ldapResult = new IdmResult();
		ldapService.getLdapAttributes(rpConfig, cpResponse, userQuery, state, ldapResult);

		Map<AttributeName, List<String>> userDetails = ldapResult.getUserDetails();
		var mailKey = Definition.builder().name("mail").source("IDM:LDAP").build();
		assertTrue(userDetails.containsKey(mailKey));
		assertEquals(2, userDetails.get(mailKey).size());
		assertFalse(userDetails.get(mailKey).contains("staleMail"));
	}

	private static RelyingParty givenRpConfig(String orgSelector) {
		String base = "base";
		var idmLookup = givemIdmLookup(base);
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		if (orgSelector != null) {
			profileSelection.setOrganizationSelector(orgSelector);
		}
		return RelyingParty.builder().id("relyingPartyId").idmLookup(idmLookup).profileSelection(profileSelection).build();
	}

	private static RelyingParty givenRpConfigWithDisabledProfileSelection() {
		String base = "base";
		var idmLookup = givemIdmLookup(base);
		var profileSelection = ProfileSelection.builder().enabled(false).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		return RelyingParty.builder().id("relyingPartyId").idmLookup(idmLookup).profileSelection(profileSelection).build();
	}

	private static IdmLookup givemIdmLookup(String base) {
		List<IdmQuery> queries = new ArrayList<>();
		queries.add(IdmQuery.builder().store("LDAP").name("LDAP").appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build());
		queries.add(IdmQuery.builder().store("LDAP").name("ORGANIZATION").appFilter("(&amp;(app=app1)(|(orgId=1)(orgId=2))").subResource(base).build());
		return IdmLookup.builder().queries(queries).build();
	}

	private static List<Map<String, List<String>>> givenLdapAttributes() {
		List<Map<String, List<String>>> ldapAttributes = new ArrayList<>();
		Map<String, List<String>> attribute1 = new HashMap<>();
		attribute1.put("uid", List.of("uid1"));
		attribute1.put("mail", List.of("mail1"));
		attribute1.put("orgId", List.of("10", "101"));
		ldapAttributes.add(attribute1);
		Map<String, List<String>> attribute2 = new HashMap<>();
		attribute2.put("uid", List.of("uid2"));
		attribute2.put("mail", List.of("mail2"));
		attribute2.put("orgId", List.of("101"));
		ldapAttributes.add(attribute2);
		return ldapAttributes;
	}

	private static List<Map<String, List<String>>> givenOrgs() {
		List<Map<String, List<String>>> ldapAttributes = new ArrayList<>();
		Map<String, List<String>> attribute1 = new HashMap<>();
		attribute1.put("orgId", List.of("10"));
		attribute1.put("translation", List.of("translation1"));
		ldapAttributes.add(attribute1);
		Map<String, List<String>> attribute2 = new HashMap<>();
		attribute2.put("orgId", List.of("101"));
		attribute2.put("translation", List.of("translation2"));
		ldapAttributes.add(attribute2);
		return ldapAttributes;
	}

	@Test
	void getProfileSelectorTest() {
		assertNull(ldapService.getProfileSelector(null, "RP_ID"));
		assertEquals("mail", ldapService.getProfileSelector("mail", "RP_ID"));
	}

	@Test
	void prefixValuesWithProfileSelectorTest() {
		Map<String, List<String>> profile = givenLdapAttributes().getFirst();
		ldapService.prefixValuesWithProfileSelector("mail1", null, profile);
		assertTrue(profile.get("uid").contains("mail1:uid1"));
	}

	@Test
	void prefixProfileAttributesTest() {
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		List<Map<String, List<String>>> attrs = givenLdapAttributes();
		Map<String, List<String>> noSelector = new HashMap<>();
		noSelector.put("uid", List.of("uid3"));
		attrs.add(noSelector);

		var ex = assertThrows(TechnicalException.class,
				() -> ldapService.prefixProfileAttributes(rpConfig, profileSelection, attrs));
		assertThat(ex.getInternalMessage(), containsString("attributes not found"));
	}

	@Test
	void userWithMultiProfilesTest() {
		assertFalse(ldapService.userWithMultiProfiles(givenLdapAttributes(), null));
		assertFalse(ldapService.userWithMultiProfiles(givenLdapAttributes(), "unknownSelector"));
		assertTrue(ldapService.userWithMultiProfiles(givenLdapAttributes(), "mail"));
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(new Definition("uid"), List.of("uid"));
		attributeValueMap.put(new Definition("attribute"), List.of("attribute"));
		attributeValueMap.put(new Definition("wildcard"), List.of("*"));
		attributeValueMap.put(new Definition("escape"), List.of("user\\123"));
		attributeValueMap.put(new Definition("injection"), List.of(")(test=*"));
		return CpResponse.builder()
		                 .userDetails(attributeValueMap)
		                 .attributes(attributeValueMap)
		                 .nameId("NAME_ID")
		                 .build();
	}
}
