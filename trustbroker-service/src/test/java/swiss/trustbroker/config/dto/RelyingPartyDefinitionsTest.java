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

package swiss.trustbroker.config.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AccessRequest;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplications;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

class RelyingPartyDefinitionsTest {

	private static final String CP_PUBLIC = "PUBLIC-LOGIN";

	private static final String CP_ENTERPRISE = "ENTERPRISE-LOGIN";

	private static final String CP_MOBILE = "MOBILE-LOGIN";

	private static final String HRD_HINT = "cp_hint";

	private static final String MOB_GW_IP = "192.168.1.1";

	private static final String AUTOLOGIN_COOKIE = "XTB_autLogin";

	@Test
	void updateAcWhitelistFromOidcClients() {
		var acs1 = "https://localhost:4443/acs";
		var acs2 = "http://localhost:8080/url";
		var acUrls = List.of(acs1, acs2);
		var acWhitelist = AcWhitelist.builder().acUrls(acUrls).build();
		var app1 = "firstApp";
		var app2 = "otherApp";
		var clients = List.of(OidcClient.builder().id(app1).build(), OidcClient.builder().id(app2).build());
		var oidc = Oidc.builder().clients(clients).build();
		var relyingParty = RelyingParty.builder().id("rpIssuerId1").acWhitelist(acWhitelist).oidc(oidc).build();
		var properties = new OidcProperties();
		var perimeterUrl = "http://localhost/internal/";
		properties.setPerimeterUrl(perimeterUrl);
		RelyingPartyDefinitions.updateAcWhitelistFromOidcClients(relyingParty, properties);
		assertThat(relyingParty.getAcWhitelist().getAcUrls(),
				containsInAnyOrder(acs1, acs2, perimeterUrl + app1, perimeterUrl + app2));
	}

	@Test
	void testAmbiguousOidcRouting() {
		var newConfigurations = new HashMap<String, Pair<RelyingParty, OidcClient>>();

		var clientId1 = "OidcClient1";
		var clientId2 = "OidcClient2";
		var clientId3 = "OidcClient3";
		var clientId4 = "OidcClient4";
		var rpMainId = "RP1";
		var rp11Id = "RP1-PRIV";
		var rp12Id = "RP1-FED";
		var rp13Id = "RP1-MDM";
		var rp31Id = "RP3-PRIV";
		var rp32Id = "RP3-FED";
		var rp33Id = "RP3-MDM";
		var rp41Id = "RP4";
		var intranetNetwork = "INTRANET";

		// 1 file with aliases
		var rp11 = givenRelyingParty(rpMainId, null, intranetNetwork, CP_ENTERPRISE, CP_PUBLIC, CP_MOBILE);
		var rp12 = givenRelyingParty(rp11Id, rpMainId, intranetNetwork, CP_ENTERPRISE, CP_PUBLIC, CP_MOBILE);
		var rp13 = givenRelyingParty(rp12Id, rpMainId, intranetNetwork, CP_ENTERPRISE, CP_PUBLIC, CP_MOBILE);
		var rp14 = givenRelyingParty(rp13Id, rpMainId, intranetNetwork, CP_ENTERPRISE, CP_PUBLIC, CP_MOBILE);
		// 2 oidc client duplicate file2 for MDM no alias
		var rp21 = givenRelyingParty(rp13Id, null, intranetNetwork, CP_MOBILE);
		// 3 files without aliases
		var rp31 = givenRelyingParty(rp31Id, rp31Id, "INTERNET", CP_PUBLIC);
		var rp32 = givenRelyingParty(rp32Id, rp32Id, intranetNetwork, CP_ENTERPRISE);
		var rp33 = givenRelyingParty(rp33Id, rp33Id, "ABC", CP_MOBILE);
		// 4 HRD hint alias
		var rp41 = givenRelyingParty(rp41Id, null, intranetNetwork, CP_PUBLIC);
		var hrdAlias = "public";
		var hrdName = "hrdCp";
		rp41.getClaimsProviderMappings().getClaimsProviderList().get(0).setHrdHintAlias(hrdAlias);
		rp41.getClaimsProviderMappings().getClaimsProviderList().get(0).setName(hrdName);

		// copy of clients federated with different SetupRP
		var cl1 = OidcClient.builder().id(clientId1).build();
		var cl1cp = OidcClient.builder().id(clientId1).build();
		var cl2 = OidcClient.builder().id(clientId2).build();
		var cl31 = OidcClient.builder().id(clientId3).federationId(rp31Id).build();
		var cl32 = OidcClient.builder().id(clientId3).federationId(rp32Id).build();
		var cl33 = OidcClient.builder().id(clientId3).federationId(rp33Id).build();
		var cl41 = OidcClient.builder().id(clientId4).federationId(rp41Id).build();

		// setup
		var properties= givenProperties();
		var relyingPartyDefinitions = new RelyingPartyDefinitions();
		relyingPartyDefinitions.setOidcConfigurations(newConfigurations);

		// invalid
		RelyingPartyDefinitions.addOidcClient(newConfigurations, OidcClient.builder().build(), RelyingParty.builder().build());

		// SetupRP-1.xml
		// RP, OIDC1 (main config)
		// RP1, OIDC1>>PRIVATE-LOGIN
		// RP2, OIDC1>>ENTERPRISE-LOGIN
		// RP3, OIDC1>>MOBILE-LOGIN
		// RP, OIDC2 (main config)
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl1, rp11);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl1, rp12);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl1, rp13);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl1, rp14);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl2, rp11);

		// SetupRP-2.xml
		// RP1, OIDC3>>MOBILE-LOGIN
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl1cp, rp21);

		// SetupRP-PRIVATE.xml, SetupRP-ENTERPRISE.xml, SetupRP-MOBILE.xml,  only set to assert the object
		// RP1, OIDC3>>PRIVATE-LOGIN
		// RP2, OIDC3>>ENTERPRISE-LOGIN
		// RP3, OIDC3>>MOBILE-LOGIN
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl31, rp31);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl32, rp32);
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl33, rp33);

		// RP4, OIDC4
		RelyingPartyDefinitions.addOidcClient(newConfigurations, cl41, rp41);

		// verify OIDC mapping table (4 accepted entries + null and one rejected)
		assertThat(newConfigurations.size(), equalTo(11));
		assertThat(newConfigurations.keySet(), containsInAnyOrder(
				clientId1,
				clientId1 + ">>" + CP_MOBILE,
				clientId2,
				clientId3,
				clientId4,
				clientId3 + ">>" + CP_PUBLIC,
				clientId3 + ">>" + CP_ENTERPRISE,
				clientId3 + ">>" + CP_MOBILE,
				clientId4 + ">>" + CP_PUBLIC,
				clientId4 + ">>" + hrdName,
				clientId4 + ">>" + hrdAlias
		));

		// test
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);

		// last one wins (arbitrary)
		var def1 = relyingPartyDefinitions.getOidcClientConfigById(clientId1, properties);
		assertTrue(def1.isPresent());
		assertThat(def1.get(), equalTo(cl1cp));

		// unique one works
		var def2 = relyingPartyDefinitions.getOidcClientConfigById(clientId2, properties);
		assertTrue(def2.isPresent());
		assertThat(def2.get(), equalTo(cl2));

		// LB routing for mobile gateway
		request.addHeader(WebUtil.HTTP_HEADER_X_FORWARDED_FOR, MOB_GW_IP);
		var def3 = relyingPartyDefinitions.getOidcClientConfigById(clientId3, properties);
		assertTrue(def3.isPresent());
		assertThat(def3.get().getFederationId(), equalTo(rp33.getId()));

		// LB for INTRANET
		request.removeHeader(WebUtil.HTTP_HEADER_X_FORWARDED_FOR);
		request.addHeader(properties.getNetwork().getNetworkHeader(), intranetNetwork);
		var def4 = relyingPartyDefinitions.getOidcClientConfigById(clientId3, properties);
		assertTrue(def4.isPresent());
		assertThat(def4.get().getFederationId(), equalTo(rp32.getId()));

		request.addHeader(HRD_HINT, hrdAlias);
		var def5 = relyingPartyDefinitions.getOidcClientConfigById(clientId4, properties);
		assertTrue(def5.isPresent());
		assertThat(def5.get().getFederationId(), equalTo(rp41.getId()));

		request.addHeader(HRD_HINT, hrdName);
		var def6 = relyingPartyDefinitions.getOidcClientConfigById(clientId4, properties);
		assertTrue(def6.isPresent());
		assertThat(def6.get().getFederationId(), equalTo(rp41.getId()));
	}

	@Test
	void loadAccessRequestConfigurations() {
		var applicationName = "app1";
		var application = givenApplication(applicationName, "INTERACTIVE", true);
		var rp1 = givenRelyingParty("rp1", null, null);
		rp1.setAccessRequest(givenAccessRequest(true, application));
		var rp2 = givenRelyingParty("rp2", null, null);
		rp2.setAccessRequest(givenAccessRequest(false, application));
		var rp3 = givenRelyingParty("rp3", null, null);
		var application2 = givenApplication("app2", "INTERACTIVE", false);
		rp3.setAccessRequest(givenAccessRequest(false, application2));
		// alias is not put into map
		var rp4 = givenRelyingParty("rpAlias1", "rp1", null);
		rp4.setAccessRequest(rp1.getAccessRequest());
		// duplicated AR application name
		var rp5 = givenRelyingParty("rp5", null, null);
		rp5.setAccessRequest(rp1.getAccessRequest());
		var relyingPartySetup = RelyingPartySetup.builder().relyingParties(List.of(rp1, rp2, rp4, rp5)).build();
		var relyingPartyDefinitions = new RelyingPartyDefinitions();
		relyingPartyDefinitions.setRelyingPartySetup(relyingPartySetup);

		relyingPartyDefinitions.loadAccessRequestConfigurations();

		var configurations = relyingPartyDefinitions.getAccessRequestConfigurations();
		assertThat(configurations.size(), is(1));
		var pair = configurations.get(applicationName);
		assertThat(pair, is(not(nullValue())));
		assertThat(pair.getKey(), is(rp1));
		assertThat(pair.getValue(), is(application));
	}

	@Test
	void addAuthorizedApplication() {
		Map<String, Pair<RelyingParty, AuthorizedApplication>> map = new HashMap<>();
		var name1 = "app1";
		var name2 = "app2";
		var application1 = givenApplication(name1, "mode1", false);
		var relyingParty = givenRelyingParty("rp1", null, null);
		RelyingPartyDefinitions.addAuthorizedApplication(map, application1, relyingParty);
		assertThat(map.get(name1), is(Pair.of(relyingParty, application1)));
		var application2 = givenApplication(name2, "mode2", true);
		RelyingPartyDefinitions.addAuthorizedApplication(map, application2, relyingParty);
		assertThat(map.get(name2), is(Pair.of(relyingParty, application2)));
		// disabled trigger overwritten
		var application3 = givenApplication(name1, "mode3", true);
		RelyingPartyDefinitions.addAuthorizedApplication(map, application3, relyingParty);
		assertThat(map.get(name1), is(Pair.of(relyingParty, application3)));
		// enabled trigger not overwritten
		var application4 = givenApplication(name2, "mode4", false);
		RelyingPartyDefinitions.addAuthorizedApplication(map, application4, relyingParty);
		assertThat(map.get(name2), is(Pair.of(relyingParty, application2)));
		var application5 = givenApplication(name2, "mode5", true);
		RelyingPartyDefinitions.addAuthorizedApplication(map, application5, relyingParty);
		assertThat(map.get(name2), is(Pair.of(relyingParty, application2)));
	}

	private static AuthorizedApplication givenApplication(String applicationName, String mode, Boolean enableTrigger) {
		return AuthorizedApplication.builder()
				.mode(mode)
				.name(applicationName)
				.enableTrigger(enableTrigger)
				.redirectUrl("https://localhost")
				.build();
	}

	private static AccessRequest givenAccessRequest(boolean enabled, AuthorizedApplication... applications) {
		return AccessRequest.builder()
				.enabled(enabled)
				.authorizedApplications(
						AuthorizedApplications.builder().authorizedApplicationList(Arrays.asList(applications)).build())
				.build();
	}

	private RelyingParty givenRelyingParty(String rpId, String alias, String net, String... cpIds) {
		var cps = new ArrayList<ClaimsProvider>();
		for (var cpId : cpIds) {
			cps.add(ClaimsProvider.builder()
											  .id(cpId)
											  .clientNetworks(net)
											  .build());
		}
		return RelyingParty.builder()
						   .id(rpId)
						   .unaliasedId(alias)
						   .claimsProviderMappings(ClaimsProviderMappings.builder()
																		 .claimsProviderList(cps)
																		 .build())
						   .build();
	}

	private static TrustBrokerProperties givenProperties() {
		var ret = new TrustBrokerProperties();
		ret.setPublicIdpId(CP_PUBLIC);
		ret.setEnterpriseIdpId(CP_ENTERPRISE);
		ret.setMobileIdpId(CP_MOBILE);
		ret.setHrdHintTestParameter(HRD_HINT);
		ret.setPublicAutoLoginCookie(AUTOLOGIN_COOKIE);
		var network = new NetworkConfig();
		ret.setNetwork(network);
		network.setMobileGatewayIpRegex(MOB_GW_IP);
		return ret;
	}

	@Test
	void isRpDisabledTest() {
		var request = new MockHttpServletRequest();
		var relyingPartyDefinitions = new RelyingPartyDefinitions();
		var relyingParty = new RelyingParty();
		var networkConfig = NetworkConfig.builder()
										 .canaryMarkerName("canary")
										 .canaryEnabledValue("always")
										 .build();

		assertFalse(relyingPartyDefinitions.isRpDisabled(null, request, networkConfig));
		assertFalse(relyingPartyDefinitions.isRpDisabled(relyingParty, request, networkConfig));

		relyingParty.setEnabled(FeatureEnum.FALSE);
		assertTrue(relyingPartyDefinitions.isRpDisabled(relyingParty, request, networkConfig));

		request.addHeader(networkConfig.getCanaryMarkerName(), networkConfig.getCanaryEnabledValue());
		assertFalse(relyingPartyDefinitions.isRpDisabled(relyingParty, request, networkConfig));
	}

}
