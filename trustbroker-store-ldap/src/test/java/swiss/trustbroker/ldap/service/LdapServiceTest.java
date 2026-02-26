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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.directory.SearchControls;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.saml.dto.CpResponse;

@SpringBootTest(classes = { LdapService.class })
class LdapServiceTest {

	private static final String SUBJECT_NAME_ID = "subjectNameId";

	@MockitoBean
	LdapTemplate ldapTemplate;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@Autowired
	LdapService ldapService;

	@Test
	void getLdapAttributesTest() {
		var ldapConfig = LdapStoreConfig.builder().undefined("UNDEF").build();
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		var idmRequests = givemIdmLookup(base);

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));

		var ldapResult = ldapService.getLdapAttributes(rpConfig, cpResponse, idmRequests);
		assertEquals(2, ldapResult.getUserDetails().size());
		assertTrue(ldapResult.getUserDetails().get(Definition.builder().name("uid").source("IDM:LDAP").build()).get(0).contains("mail"));

	}

	private static IdmLookup givemIdmLookup(String base) {
		List<IdmQuery> queries = new ArrayList<>();
		queries.add(IdmQuery.builder().store("ANY").build());
		queries.add(IdmQuery.builder().store("LDAP").name("LDAP").appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build());
		return IdmLookup.builder().queries(queries).build();
	}

	private static List<Map<String, List<String>>> givenLdapAttributes() {
		List<Map<String, List<String>>> ldapAttributes = new ArrayList<>();
		Map<String, List<String>> attribute1 = new HashMap<>();
		attribute1.put("uid", List.of("uid1"));
		attribute1.put("mail", List.of("mail1"));
		ldapAttributes.add(attribute1);
		Map<String, List<String>> attribute2 = new HashMap<>();
		attribute2.put("uid", List.of("uid2"));
		attribute2.put("mail", List.of("mail2"));
		ldapAttributes.add(attribute2);
		return ldapAttributes;
	}

	@Test
	void getProfileSelectorTest() {
		var profileSelection = ProfileSelection.builder().build();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapService.getProfileSelector(profileSelection, "RP_ID"));
		assertThat(ex.getInternalMessage(), containsString("LDAP ProfileSelection.profileSelector cannot be null or empty"));
		assertEquals("mail", ldapService.getProfileSelector(ProfileSelection.builder().profileSelector("mail").build(), "RP_ID"));
	}

	@Test
	void prefixValuesWithProfileSelectorTest() {
		Map<String, List<String>> profile = givenLdapAttributes().get(0);
		ldapService.prefixValuesWithProfileSelector("mail1", null, profile);
		assertTrue(profile.get("uid").contains("mail1\\uid1"));
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

	@Test
	void getQueryBaseTest() {
		var rpConfig = RelyingParty.builder().id("relyingPartyId").build();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapService.getQueryBase(null, rpConfig));
		assertThat(ex.getInternalMessage(), containsString("Missing subResource"));

		assertEquals("subresource", ldapService.getQueryBase("subresource", rpConfig));
	}

	@Test
	void queryFilterFormatterTest() {
		var cpResponse = givenCpResponse();
		var ldapConfig = LdapStoreConfig.builder().undefined("UNDEF").build();
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var ex = assertThrows(TechnicalException.class,
				() -> ldapService.queryFilterFormatter(null, cpResponse, "RP_ID"));
		assertThat(ex.getInternalMessage(), containsString("AppFilter is null or empty"));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))",
				ldapService.queryFilterFormatter("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))", cpResponse, "RP_ID"));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))",
				ldapService.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute})))", cpResponse, "RP_ID"));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(id=UNDEF)))",
				ldapService.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:uid})(id=${unknownAttr})))", cpResponse, "RP_ID"));

		assertEquals("(&amp;(app=app1)(|(uid=user\\5c123)(attribute=\\2a)(value=\\29\\28test=\\2a)))",
				ldapService.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:escape})(attribute=${wildcard})"
						+ "(value=${injection})))", cpResponse, "RP_ID"));
	}

	@Test
	void isChainedQueryTest() {
		assertTrue(ldapService.isChainedQuery("IDM:uid"));
		assertFalse(ldapService.isChainedQuery("uid"));
	}

	@Test
	void getPlaceholderValueTest() {
		var cpResponse = givenCpResponse();
		assertEquals("NAME_ID", ldapService.getPlaceholderValue(SUBJECT_NAME_ID, cpResponse));
		assertEquals("uid", ldapService.getPlaceholderValue("IDM:uid", cpResponse));
		assertEquals("attribute", ldapService.getPlaceholderValue("attribute", cpResponse));
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
