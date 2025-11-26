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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.beanutils.BeanUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AccessRequest;
import swiss.trustbroker.federation.xmlconfig.AnnouncementRpConfig;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantTypes;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.ClaimsMapper;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Scopes;

class RelyingPartySetupUtilTest {

	@Test
	void mergeClaimsProviderMappings() {
		var profileClaimsProviderMappings = givenProfileMappings();
		var claimsProviderMappings = givenRelyingPartyMappings();
		var relyingParty = RelyingParty
				.builder()
				.id("TestRP")
				.base("ProfileRP")
				.claimsProviderMappings(claimsProviderMappings)
				.build();

		var claimProviderSetup = givenClaimsProviderSetup(claimsProviderMappings, profileClaimsProviderMappings);
		RelyingPartySetupUtil.mergeClaimsProviderMappings(relyingParty, profileClaimsProviderMappings, claimProviderSetup, false);

		// all enabled CPs from profile and setup were combined with overrides from setup, no disabled ones anymore
		var mappings = relyingParty.getClaimsProviderMappings();
		assertThat(mappings, is(notNullValue()));
		var mappingList = relyingParty.getClaimsProviderMappings().getClaimsProviderList();
		assertThat(mappingList, is(notNullValue()));
		assertThat(mappingList.size(), is(7));
		// SetupRP with alias copied
		assertMapping(mappingList.get(0), "P1enabled", null, null, "alias1", null);
		// ProfileRP merged
		assertMapping(mappingList.get(1), "P3network", true, "N3", null,  300);
		// SetupRP copied
		assertMapping(mappingList.get(2), "R1enabled", true, "N4", null, 1);
		// ProfileRP added
		assertMapping(mappingList.get(5), "P1enabled", true, "N1,N2", null, 100);
		// Alias match
		assertThat(mappingList.get(3).getId(), is("P4network"));
		assertThat(mappingList.get(3).getRelyingPartyAlias(), is("alias"));
		assertThat(mappingList.get(4).getId(), is("P5network"));
		assertThat(mappingList.get(6).getId(), is("P5network"));
	}

	private static ClaimsProviderMappings givenRelyingPartyMappings() {
		return ClaimsProviderMappings
				.builder()
				.claimsProviderList(List.of(
						ClaimsProvider.builder()
									  .id("P1enabled")
									  .relyingPartyAlias("alias1")
									  .build(),
						ClaimsProvider.builder()
									  .id("P2disabled")
									  .enabled(false)
									  .build(),
						ClaimsProvider.builder()
									  .id("P3network")
									  .enabled(true)
									  .clientNetworks("N3")
									  .build(),
						ClaimsProvider.builder()
									  .id("R1enabled")
									  .enabled(true)
									  .order(1)
									  .clientNetworks("N4")
									  .build(),
						ClaimsProvider.builder()
									  .id("R2disabled")
									  .enabled(false)
									  .order(999)
									  .build(),
						ClaimsProvider.builder()
									  .id("P4network")
									  .order(300)
									  .clientNetworks("N1,N2")
									  .relyingPartyAlias("alias")
									  .build(),
						ClaimsProvider.builder()
									  .id("P5network")
									  .order(300)
									  .clientNetworks("N1,N2")
									  .relyingPartyAlias("alias2")
									  .build()
				))
				.build();
	}

	private static ClaimsProviderMappings givenProfileMappings() {
		return ClaimsProviderMappings
				.builder()
				.claimsProviderList(List.of(
						ClaimsProvider.builder()
									  .id("P1enabled")
									  .enabled(true)
									  .order(100)
									  .clientNetworks("N1,N2")
									  .build(),
						ClaimsProvider.builder()
									  .id("P2disabled")
									  .enabled(false)
									  .order(200)
									  .clientNetworks("N1,N2")
									  .build(),
						ClaimsProvider.builder()
									  .id("P3network")
									  .enabled(false)
									  .order(300)
									  .clientNetworks("N1,N2")
									  .build(),
						ClaimsProvider.builder()
									  .id("P4network")
									  .order(300)
									  .clientNetworks("N1,N2")
									  .relyingPartyAlias("alias")
									  .build(),
						ClaimsProvider.builder()
									  .id("P5network")
									  .order(300)
									  .clientNetworks("N1,N2")
									  .relyingPartyAlias("alias1")
									  .build()
				))
				.build();
	}

	private static void assertMapping(ClaimsProvider mapping, String id, Boolean enabled, String networks, String rpAlias,
			Integer order) {
		assertThat(mapping.getId(), is(id));
		assertThat(mapping.getClientNetworks(), is(networks));
		assertThat(mapping.getRelyingPartyAlias(), is(rpAlias));
		assertThat(mapping.getEnabled(), is(enabled)); // null is treated as enabled
		assertThat(mapping.getOrder(), is(order)); // null is treated as not relevant to clients
	}

	private ClaimsProviderSetup givenClaimsProviderSetup(ClaimsProviderMappings claimsProviderMappings, ClaimsProviderMappings profileClaimsProviderMappings) {
		var claimsProviderSetup = new ClaimsProviderSetup();
		List<ClaimsParty> claimParty1 = claimsProviderMappings.getClaimsProviderList().stream()
				.map(claimsProvider -> ClaimsParty.builder().id(claimsProvider.getId()).build())
				.collect(Collectors.toList());
		List<ClaimsParty> claimParty2 = profileClaimsProviderMappings.getClaimsProviderList().stream()
				.map(claimsProvider -> ClaimsParty.builder().id(claimsProvider.getId()).build())
				.collect(Collectors.toList());
		claimParty1.addAll(claimParty2);
		claimsProviderSetup.setClaimsParties(claimParty1);
		return claimsProviderSetup;
	}

	@Test
	void mergeAccessRequestCopy() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = RelyingParty.builder().id("rp1").build();

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest(), sameInstance(profile.getAccessRequest()));
	}

	@Test
	void mergeAccessRequestCopyApplication() {
		var profile = createRelyingPartyWithAccessRequest();
		var templateApp = AuthorizedApplication.builder().name("app1").build();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(templateApp);
		var rp = createRelyingPartyWithAccessRequest();
		rp.getAccessRequest().setEnabled(null);

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().size(), is(1));
		assertThat(rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().get(0),
				sameInstance(templateApp));
		assertThat(rp.getAccessRequest().enabled(), is(profile.getAccessRequest().enabled()));
	}

	@Test
	void mergeAccessRequestDuplicateDefault() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = createRelyingPartyWithAccessRequest();
		var defaultTriggerRole = "defaultApp.role";
		var defaultApp = AuthorizedApplication.builder().triggerRole(defaultTriggerRole).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(defaultApp);
		var otherTriggerRole = "otherApp.role";
		var otherDefaultApp = AuthorizedApplication.builder().triggerRole(otherTriggerRole).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(otherDefaultApp);

		var ex = assertThrows(TechnicalException.class, () -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));

		assertThat(ex.getInternalMessage(), containsString(defaultTriggerRole));
		assertThat(ex.getInternalMessage(), containsString(otherTriggerRole));
	}

	@Test
	void mergeAccessRequest() {
		var profile = createRelyingPartyWithAccessRequest();
		profile.getAccessRequest().setEnabled(false);
		var mode = "SILENT";
		var url = "https://localhost/silent";
		var templateApp = AuthorizedApplication.builder().mode(mode).serviceUrl(url).build();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(templateApp);

		var rp = createRelyingPartyWithAccessRequest();
		// one retained and one merged attribute each to ensure both are updated
		var app1Name = "app1";
		var url1 = "https://localhost/silent2";
		var app1 = AuthorizedApplication.builder().name(app1Name).serviceUrl(url1).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(app1);
		var app2Name = "app2";
		var mode2 = "INTERACTIVE";
		// set URL for second one, there must be only one default
		var app2 = AuthorizedApplication.builder().name(app2Name).url("/url").mode(mode2).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList().add(app2);

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest().getEnabled(), is(Boolean.TRUE)); // not copied

		var apps = rp.getAccessRequest().getAuthorizedApplications();
		assertThat(apps.getAuthorizedApplicationList().size(), is(2));

		var mergedApp1 = apps.getAuthorizedApplicationList().get(0);
		assertThat(mergedApp1.getName(), is(app1Name));
		assertThat(mergedApp1.getMode(), is(mode));
		assertThat(mergedApp1.getServiceUrl(), is(url1));

		var mergedApp2 = apps.getAuthorizedApplicationList().get(1);
		assertThat(mergedApp2.getName(), is(app2Name));
		assertThat(mergedApp2.getMode(), is(mode2));
		assertThat(mergedApp2.getServiceUrl(), is(url));
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" })
	void mergeAccessRequestWrongTemplate(boolean enabled) {
		var profile = createRelyingPartyWithAccessRequest();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList()
				.add(AuthorizedApplication.builder().build());
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList()
				.add(AuthorizedApplication.builder().build());

		var rp = createRelyingPartyWithAccessRequest();
		rp.getAccessRequest().setEnabled(enabled);

		if (enabled) {
			assertThrows(TechnicalException.class, () -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
		}
		else {
			assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
		}
	}

	@Test
	void mergeAccessRequestOidc() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = createRelyingPartyWithAccessRequest();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList()
				.add(AuthorizedApplication.builder().name("test1").build());
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationList()
				.add(AuthorizedApplication.builder().name("test2").build());
		rp.setOidc(Oidc.builder().clients(List.of(OidcClient.builder().build())).build());

		assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
	}

	@Test
	void mergeAnnouncements() {
		var profile = createRelyingPartyWithAnnouncements();
		var urls = List.of("url1");
		profile.getAnnouncement().setAnnouncementUrls(urls);
		var rp = createRelyingPartyWithAnnouncements();
		rp.getAnnouncement().setEnabled(null);

		RelyingPartySetupUtil.mergeAnnouncements(rp, profile);

		assertThat(rp.getAnnouncement().getAnnouncementUrls(), is(profile.getAnnouncement().getAnnouncementUrls()));
		assertThat(rp.getAnnouncement().isAnnouncementEnabled(), is(profile.getAnnouncement().isAnnouncementEnabled()));
	}

	@Test
	void mergeProfileSelection() {
		var profile = createRelyingPartyWithProfileSelection();
		var rp = createRelyingPartyWithProfileSelection();
		rp.getProfileSelection().setOidcOnly(null);

		RelyingPartySetupUtil.mergeProfileSelection(rp, profile.getProfileSelection());

		assertThat(rp.getProfileSelection().getProfileSelectionMode(), is(profile.getProfileSelection().getProfileSelectionMode()));
		assertThat(rp.getProfileSelection().isProfileSelectionEnabled(), is(profile.getProfileSelection().isProfileSelectionEnabled()));
		assertThat(rp.getProfileSelection().isForOidcOnly(), is(profile.getProfileSelection().isForOidcOnly()));
	}

	@Test
	void mergeQoaLevelsTest() {
		// empty
		var relyingParty = new RelyingParty();
		var baseRelyingParty = new RelyingParty();
		assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty));

		// use base profile
		var expectedQoa = givenQoa(null, true, false, SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		var rpOoa = givenQoa(null, null, null, null);
		var mergedQoa = givenQoa(null, true, false, SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		baseRelyingParty.setQoa(expectedQoa);
		RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty);
		assertThat(relyingParty.getQoa(), is(expectedQoa));

		// merge
		relyingParty.setQoa(rpOoa);
		RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty);
		assertThat(relyingParty.getQoa(), is(mergedQoa));

		// preserve
		baseRelyingParty.setQoa(givenQoa(2, false, true, SamlContextClass.SMART_CARD_PKI));
		RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty);
		assertThat(relyingParty.getQoa(), is(mergedQoa));
	}

	@Test
	void notInBaseOrHasOidcConfTest() {
		List<Definition> baseAttributes = givenDefinitionList();
		List<Definition> toRemove;

		// NOT in Base
		Definition definition = Definition.builder()
				.name(CoreAttributeName.FIRST_NAME.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(0, toRemove.size());

		// In Base, no OIDC attribute
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.build();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());

		// In Base, OIDC attribute in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.oidcNames("oidcname")
				.scope("scope")
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());
		assertNotNull(definition.getOidcNames());
		assertNull(definition.getMappers());

		// In Base, only OIDC name attribute in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.mappers("STRING")
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());
		assertNull(definition.getOidcNames());
		assertNotNull(definition.getMappers());

		// In Base, OIDC name attribute in Profile and in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.oidcNames("oidcname")
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());
		assertNotNull(definition.getOidcNames());
		assertEquals("oidcname", definition.getOidcNames());
		assertNull(definition.getMappers());

		// In Base, OIDC name attribute only in Profile
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());

		// In Base, OIDC mapper set in base
		definition = Definition.builder()
				.name(CoreAttributeName.LOCALITY.getName())
				.namespaceUri(CoreAttributeName.LOCALITY.getNamespaceUri())
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());
		assertNull(definition.getOidcNames());
		assertNotNull(definition.getMappers());

		// In Base, OIDC mapper set in base and Rp
		definition = Definition.builder()
				.name(CoreAttributeName.LOCALITY.getName())
				.namespaceUri(CoreAttributeName.LOCALITY.getNamespaceUri())
				.mappers(ClaimsMapper.BOOLEAN.toString())
				.build();
		toRemove = new ArrayList<>();
		RelyingPartySetupUtil.setBaseToRemove(baseAttributes, definition, toRemove);
		assertEquals(1, toRemove.size());
		assertNull(definition.getOidcNames());
		assertNotNull(definition.getMappers());
		assertEquals(ClaimsMapper.BOOLEAN.toString(), definition.getMappers());
	}

	@Test
	void definitionInListTest() {
		List<Definition> definitionList = givenDefinitionList();

		Definition definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.build();
		assertTrue(RelyingPartySetupUtil.definitionInList(definition, definitionList).isPresent());

		// Same attribute but no oidc name => present
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.build();
		assertTrue(RelyingPartySetupUtil.definitionInList(definition, definitionList).isPresent());


		definition = Definition.builder()
				.name(CoreAttributeName.FIRST_NAME.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		assertThat(RelyingPartySetupUtil.definitionInList(definition, definitionList), is(Optional.empty()));

		definition = Definition.builder()
				.name(CoreAttributeName.NAME_ID.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		assertThat(RelyingPartySetupUtil.definitionInList(definition, definitionList), is(Optional.empty()));
	}

	@Test
	void oidcClientMergeTest() throws InvocationTargetException, IllegalAccessException {
		var defsBase = givenDefinitionList();
		var defsExpected = givenDefinitionList();
		var defsClientAddon = Definition.builder().name("ClientAddOnClaim").build();
		defsExpected.add(defsClientAddon);

		var client = OidcClient.builder()
				.id("OidcTestClient")
				.federationId("Saml.IssuerId")
				.clientSecret("per client")
				// aggregate
				.redirectUris(AcWhitelist.builder().acUrls(new ArrayList<>(List.of("url1", "url2"))).build())
				.claimsSelection(AttributesSelection.builder().definitions(new ArrayList<>(List.of(
						Definition.builder().name("ClientAddOnClaim").build()))).build())
				.oidcSecurityPolicies(OidcSecurityPolicies.builder()
						.requireProofKey(true)
						.requireAuthorizationConsent(false)
						.tokenTimeToLiveMin(480) // 28800sec SAML assertion TTL
						.refreshTokenTimeToLiveMin(60) // 3600sec SAML response TTL (see application.yml)
						.build())
				// stuff overwritten
				.scopes(Scopes.builder().scopeList(List.of("openid", "email", "profile", "address", "phone")).build())
				.qoa(Qoa.builder().classes(List.of(AcClass.builder().contextClass("qoa10").build())).build())
				.build();
		var base = OidcClient.builder()
				.redirectUris(AcWhitelist.builder().acUrls(List.of("url3", "url4")).build())
				.claimsSelection(AttributesSelection.builder().definitions(defsBase).build())
				.oidcSecurityPolicies(OidcSecurityPolicies.builder()
						.build())
				.scopes(Scopes.builder()
						.scopeList(List.of("lost")).build())
				.authorizationGrantTypes(AuthorizationGrantTypes.builder()
						.grantTypes(
								List.of(AuthorizationGrantType.AUTHORIZATION_CODE,
										AuthorizationGrantType.REFRESH_TOKEN)
						).build())
				.clientAuthenticationMethods(ClientAuthenticationMethods.builder()
						.methods(
								List.of(ClientAuthenticationMethod.NONE,
										ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
										ClientAuthenticationMethod.CLIENT_SECRET_POST)
						).build())
				.qoa(Qoa.builder().classes(List.of(AcClass.builder().contextClass("lost").build())).build())
				.build();


		RelyingPartySetupUtil.mergeOidcClient(client, base, RelyingParty.builder().build());

		var expected = OidcClient.builder().build();
		BeanUtils.copyProperties(expected, client);
		expected.getRedirectUris().getAcUrls().addAll(base.getRedirectUris().getAcUrls());
		expected.getClaimsSelection().getDefinitions().addAll(base.getClaimsSelection().getDefinitions());

		assertThat(client, is(expected));
		assertThat(client.getRedirectUris().getAcUrls(), containsInAnyOrder("url1", "url2", "url3", "url4"));
		assertThat(client.getClaimsSelection().getDefinitions(), containsInAnyOrder(defsExpected.toArray()));
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
		definitions.add(Definition.builder()
				.name(CoreAttributeName.CLAIMS_NAME.getName())
				.namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
				.oidcNames("claimsname")
				.scope("oidc")
				.build());
		definitions.add(Definition.builder()
				.name(CoreAttributeName.NAME_ID.getName())
				.namespaceUri(CoreAttributeName.NAME_ID.getNamespaceUri())
				.build());
		definitions.add(Definition.builder()
				.name(CoreAttributeName.LOCALITY.getName())
				.namespaceUri(CoreAttributeName.LOCALITY.getNamespaceUri())
				.mappers(ClaimsMapper.EMAIL.name())
				.build());
		return definitions;
	}

	private Qoa givenQoa(Integer order, Boolean enforce, Boolean mapOutbound, String qoaClass) {
		List<AcClass> classes = new ArrayList<>();
		if (qoaClass != null || order != null) {
			classes.add(AcClass.builder()
							   .order(order)
							   .contextClass(qoaClass)
							   .build());
		}
		return Qoa.builder()
				  .classes(classes)
				  .enforce(enforce)
				  .mapOutbound(mapOutbound)
				  .build();
	}

	private static RelyingParty createRelyingPartyWithAccessRequest() {
		var ar = AccessRequest.builder().enabled(true).build();
		return RelyingParty.builder().id("rpId").accessRequest(ar).build();
	}

	private static RelyingParty createRelyingPartyWithAnnouncements() {
		var announcement = AnnouncementRpConfig.builder().enabled(true).build();
		return RelyingParty.builder().id("rpId").announcement(announcement).build();
	}

	private static RelyingParty createRelyingPartyWithProfileSelection() {
		var ps = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).build();
		return RelyingParty.builder().id("rpId").profileSelection(ps).build();
	}

	private ArrayList<ClaimsProvider> givenClaimsProviders() {
		ArrayList<ClaimsProvider> claimsProviders = new ArrayList<>();
		claimsProviders.add(ClaimsProvider.builder().id("id1").clientNetworks("cn1").build());
		claimsProviders.add(ClaimsProvider.builder().id("id2").clientNetworks("cn2").build());
		return claimsProviders;
	}

	private static List<ClaimsProvider> givenClaimsProviderDefinitions() {
		return List.of(
				ClaimsProvider.builder().id("id1").img("img1").build(),
				ClaimsProvider.builder().id("id2").img("img2").build(),
				ClaimsProvider.builder().id(null).img("img2").build()
		);
	}

	@Test
	void getCpDefinitionByIdTest() {
		var claimsProviderDef = givenClaimsProviderDefinitions();
		assertFalse(RelyingPartySetupUtil.getCpDefinitionById("cpId", claimsProviderDef).isPresent());
		assertTrue(RelyingPartySetupUtil.getCpDefinitionById("id1", claimsProviderDef).isPresent());
		assertTrue(RelyingPartySetupUtil.getCpDefinitionById("id2", claimsProviderDef).isPresent());
		assertFalse(RelyingPartySetupUtil.getCpDefinitionById(null, claimsProviderDef).isPresent());
	}

	@Test
	void getRpClaimsMappingTest() {
		var baseClaimsProvider1 = ClaimsProvider.builder().id("id1").img("img1").build();
		List<ClaimsProvider> claimsProviders = givenClaimsProviders();
		assertFalse(RelyingPartySetupUtil.getRpClaimsMapping(baseClaimsProvider1, claimsProviders, false).isEmpty());

		var baseClaimsProvider2 = ClaimsProvider.builder().id("id1").img("img1").relyingPartyAlias("rpAlias").build();
		assertTrue(RelyingPartySetupUtil.getRpClaimsMapping(baseClaimsProvider2, claimsProviders, false).isEmpty());

		var baseClaimsProvider3 = ClaimsProvider.builder().id("id3").img("img1").relyingPartyAlias("rpAlias3").build();
		claimsProviders.add(baseClaimsProvider3);
		assertFalse(RelyingPartySetupUtil.getRpClaimsMapping(baseClaimsProvider3, claimsProviders, false).isEmpty());
	}

	@Test
	void mergeEnabledClaimsProvidersTest() {
		var rpCpMappings = ClaimsProviderMappings.builder()
				.claimsProviderList(
						List.of(ClaimsProvider.builder().id("rpCp1").build(), ClaimsProvider.builder().id("rpCp2").build()))
				.build();
		var relyingParty = RelyingParty.builder().id("rpId")
				.claimsProviderMappings(rpCpMappings)
				.build();

		var baseCpMappingList = List.of(ClaimsProvider.builder().id("baseCp1").build(),
				ClaimsProvider.builder().id("baseCp2").img("imgBase2").build(),
				// Cp with existing Cp definition
				ClaimsProvider.builder().id("id1").build(),
				// Cp with existing Cp definition
				ClaimsProvider.builder().id("id2").img("imgBase").build());

		// profile overrides
		var baseCpMappings = ClaimsProviderMappings.builder()
				.claimsProviderList(baseCpMappingList)
				.build();
		var profileCpSetup = givenClaimsProviderSetup(rpCpMappings, baseCpMappings);
		RelyingPartySetupUtil.mergeEnabledClaimsProviders(relyingParty, baseCpMappingList, profileCpSetup, false);

		// default overrides
		var claimsProviderMappings = ClaimsProviderMappings
				.builder()
				.enabled(true)
				.claimsProviderList(givenClaimsProviderDefinitions())
				.build();
		var defaultCpSetup = givenClaimsProviderSetup(rpCpMappings, claimsProviderMappings);
		RelyingPartySetupUtil.mergeClaimsProviderMappings(relyingParty, claimsProviderMappings, defaultCpSetup, true);

		var resultedMappings = relyingParty.getClaimsProviderMappings();
		assertNotNull(resultedMappings);
		var resultCpList = resultedMappings.getClaimsProviderList();
		assertNotNull(resultCpList);
		assertEquals(6, resultCpList.size());
		// Rp Cp configuration
		assertNotNull(getCpById("rpCp1", resultCpList));
		assertNull(getCpById("rpCp1", resultCpList).getImg());
		// Base Cp configuration
		assertNotNull(getCpById("baseCp1", resultCpList));
		assertNull(getCpById("baseCp1", resultCpList).getImg());
		// Cp with UI configuration
		assertNotNull(getCpById("baseCp2", resultCpList));
		assertNotNull(getCpById("baseCp2", resultCpList).getImg());
		assertNotNull(getCpById("id1", resultCpList));
		assertNotNull(getCpById("id1", resultCpList).getImg());
		// Image from ClaimsProviderDefinitions
		assertEquals("img1", getCpById("id1", resultCpList).getImg());
		assertNotNull(getCpById("id2", resultCpList));
		assertNotNull(getCpById("id2", resultCpList).getImg());
		// Image from Base Cp configuration
		assertEquals("imgBase", getCpById("id2", resultCpList).getImg());
	}

	private ClaimsProvider getCpById(String rpCp1, List<ClaimsProvider> resultCpList) {
		return resultCpList.stream()
				.filter(cp -> cp.getId().equals(rpCp1))
				.findFirst().orElse(null);
	}

	@Test
	void isValidClaimsProviderMappingsTest() {
		var claimsProviders = givenClaimsProviders();
		assertTrue(RelyingPartySetupUtil.isValidClaimsProviderMappings(claimsProviders, "claimsProviderDef"));
		claimsProviders.add(ClaimsProvider.builder().id("id1").build());
		assertFalse(RelyingPartySetupUtil.isValidClaimsProviderMappings(claimsProviders, "claimsProviderDef"));
	}

	@ParameterizedTest
	@MethodSource
	void mergeOidcQoaLevelsTest(Qoa oidcQoa, Qoa samlQoa, Qoa resultedQoa) {
		var oidcClient = OidcClient.builder().qoa(oidcQoa).build();
		RelyingPartySetupUtil.mergeQoaLevels(oidcClient, samlQoa);
		var oidcQoaResult = oidcClient.getQoa();
		if (resultedQoa == null) {
			assertNull(oidcQoaResult);
		}
		else {
			assertEquals(resultedQoa.getEnforce(), oidcQoaResult.getEnforce());
			assertEquals(resultedQoa.getMapOutbound(), oidcQoaResult.getMapOutbound());
			assertEquals(resultedQoa.getComparison(), oidcQoaResult.getComparison());
			assertEquals(resultedQoa.getClasses(), oidcQoaResult.getClasses());
		}
	}

	static Object[][] mergeOidcQoaLevelsTest() {
		var accClasses = List.of(AcClass.builder().contextClass("qoa1").build());
		return new Object[][]{
				{ null, null, null },
				{ null, Qoa.builder().enforce(true).build(), Qoa.builder().enforce(true).build() },
				{ Qoa.builder().enforce(true).build(), null, Qoa.builder().enforce(true).build() },
				{ Qoa.builder().enforce(true).build(), Qoa.builder().enforce(false).build(), Qoa.builder().enforce(true).build() },
				{ Qoa.builder().enforce(true).build(), Qoa.builder().enforce(false).mapOutbound(false).build(), Qoa.builder().enforce(true).mapOutbound(true).build() },
				{ Qoa.builder().enforce(true).comparison(QoaComparison.MINIMUM).build(), Qoa.builder().enforce(true).comparison(QoaComparison.EXACT).build(), Qoa.builder().comparison(QoaComparison.MINIMUM).enforce(true).build() },
				{ Qoa.builder().enforce(true).comparison(QoaComparison.MINIMUM).build(), Qoa.builder().enforce(true).comparison(QoaComparison.EXACT).classes(accClasses).build(), Qoa.builder().comparison(QoaComparison.MINIMUM).classes(accClasses).enforce(true).build() }
		};
	}
}
