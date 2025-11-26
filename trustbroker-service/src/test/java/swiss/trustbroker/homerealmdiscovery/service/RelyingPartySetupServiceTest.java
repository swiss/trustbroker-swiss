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

package swiss.trustbroker.homerealmdiscovery.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;

@SpringBootTest
@ContextConfiguration(classes = { RelyingPartySetupService.class })
@TestPropertySource(properties = "trustbroker.config.devmode.enabled=false")
class RelyingPartySetupServiceTest {

	private static final String RP_ID = "rp";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Autowired
	private RelyingPartySetupService relyingPartySetupService;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void getRelyingPartyByIssuerIdOrReferrerUnknown() {
		mockRelyingPartyConfiguration();
		assertThrows(RequestDeniedException.class, () -> {
			relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer("unknown", "https://unknown");
		});
	}

	@Test
	void getRelyingPartyByIssuerIdOrReferrerUnknownTryOnly() {
		mockRelyingPartyConfiguration();
		var result = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer("unknown", "https://unknown", true);
		assertThat(result, is(nullValue()));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"urn:test:TESTRP,,urn:test:TESTRP",
			"urn:test:TESTRP,https://unknown,urn:test:TESTRP",
			"urn:test:MOCKRP-DIRECT,,urn:test:MOCKRP-DIRECT", // by alias
			// odd URL as we need to match out test data:
			",https://urn:test:TESTRP,urn:test:TESTRP",
			",https://urn:test:TESTRP/one/two?query,urn:test:TESTRP"
	})
	void getRelyingPartyByIssuerIdOrReferrer(String issuer, String referer, String expected) {
		mockRelyingPartyConfiguration();
		var result = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(issuer, referer);
		assertThat(result.getId(), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"urn:test:TESTRP,true",
			"urn:test:NOIDM,false"
	})
	void getIdmLookUp(String issuer, boolean expected) {
		mockRelyingPartyConfiguration();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(issuer, null);
		var idmLookup = relyingPartySetupService.getIdmLookUp(relyingParty);
		assertThat(idmLookup.isPresent(), is(expected));
	}

	@Test
	void getAllRelyingPartiesByIssuerIdAndReferrerBothMatchingSame() {
		mockRelyingPartyConfiguration();
		var issuer = "urn:test:TESTRP";
		var referer = "https://urn:test:TESTRP";
		var result = relyingPartySetupService.getOrderedRelyingPartiesForSlo(issuer, referer);
		assertThat(result.size(), is(1));
		assertThat(result.get(0).getId(), is(issuer));
	}

	@Test
	void getAllRelyingPartiesByIssuerIdAndReferrerBothMatchingOther() {
		mockRelyingPartyConfiguration();
		var issuer = "urn:test:TESTRP";
		var referer = "https://referring-party.localdomain";
		var result = relyingPartySetupService.getOrderedRelyingPartiesForSlo(issuer, referer);
		assertThat(result.size(), is(1));
		// the order is specified
		assertThat(result.get(0).getId(), is(issuer));
	}

	@Test
	void getAllRelyingPartiesByIssuerIdAndReferrerMatchingAcs() {
		mockRelyingPartyConfiguration();
		var referer = "https://referring-party-acs.localdomain:43443";
		var result = relyingPartySetupService.getOrderedRelyingPartiesForSlo("unknown", referer);
		// the order is unspecified
		assertThat(result.stream().map(RelyingParty::getId).toList(),
				containsInAnyOrder("https://referring-party.localdomain", "https://idp.referring-party.localdomain"));
	}

	@Test
	void getAllRelyingPartiesByReferrerOnly() {
		mockRelyingPartyConfiguration();
		var referer = "https://referring-party-top.localdomain/"; // port 443 fails as the lookup does not normalize the URL
		var result = relyingPartySetupService.getOrderedRelyingPartiesForSlo(null, referer);
		assertNotNull(result);
		assertEquals(1, result.size());
		assertEquals("https://referring-party.localdomain", result.get(0).getId());
	}

	@Test
	void getAllRelyingPartiesByReferrerMatchingLogout() {
		mockRelyingPartyConfiguration();
		var referer = "https://referring-party-acs.localdomain:43443/"; // Referer of LogoutRequest
		var result = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(null, referer, true);
		assertNotNull(result);
	}

	@Test
	void getAllRelyingPartiesByIssuerIdAndReferrerNearlyMatching() {
		mockRelyingPartyConfiguration();
		when(trustBrokerProperties.getSloPepIssuerIdPrefix()).thenReturn("urn:test:MOCKRP");
		when(trustBrokerProperties.getSloIssuerIdDropPatterns()).thenReturn(new String[] { "-REMOVE", "-DROP" });
		var issuer = "urn:test:MOCKRP-DEVINT";
		when(trustBrokerProperties.isPepIssuerMatchingEnabled(issuer)).thenReturn(true);
		var result = relyingPartySetupService.getOrderedRelyingPartiesForSlo(issuer, null);
		// the order is unspecified
		assertThat(result.stream().map(RelyingParty::getId).toList(),
				containsInAnyOrder("urn:test:MOCKRP-REMOVE-DEVINT", "urn:test:MOCKRP-DROP-DEVINT"));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// Office 365 sharepoint plugin and old MSIE11
			"User-Agent,Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E),/skinnyHRD.html",
			"User-Agent,Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko,/skinnyHRD.html",
			"User-Agent,Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0,null",
			// robots
			"X-Origin-Forwarded-For,192.168.12.111,/skinnyImgHRD.html",
			"X-ORIGIN-FORWARDED-FOR,192.168.12.110,/skinnyImgHRD.html",
			"X-Origin-Forwarded-FOR,192.168.12.113,/skinnyImgHRD.html",
			"X-Origin-Forwarded-For,192.168.12.90,/skinnyImgHRD.html",
			"X-Origin-Forwarded-For,192.168.11.100,null"
	}, nullValues = "null")
	void useSkinnyHrdForLegacyClients(String httpHeaderName, String httpHeaderValue, String expectedResult) {
		mockRelyingPartyConfiguration();
		when(trustBrokerProperties.getSkinnyHrdTriggers()).thenReturn(List.of(
				RegexNameValue.builder().name("User-Agent").regex(".*Trident/7.*").value("/skinnyHRD.html").build(),
				RegexNameValue.builder().name("X-MOS-Agent").regex("Silk-Performer").value("/skinnyImgHRD.html").build(),
				RegexNameValue.builder()
							  .name("X-Origin-Forwarded-For").regex("192\\.168\\.12\\.[0-9]*").value("/skinnyImgHRD.html").build()
		));
		var httpRequest = new MockHttpServletRequest();
		httpRequest.addHeader(httpHeaderName, httpHeaderValue);
		assertThat(OperationalUtil.useSkinnyUiForLegacyClients(null, httpRequest, trustBrokerProperties), equalTo(expectedResult));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"Origin-Forwarded-For,192.168.33.77,false",
			"X-Origin-Forwarded-For,192.168.34.77,false",
			"X-Origin-Forwarded-For,192.168.33.77,true"
	}, nullValues = "null")
	void skipMonitoringUserAgents(String httpHeaderName, String httpHeaderValue, boolean expectedResult) {
		mockRelyingPartyConfiguration();
		when(trustBrokerProperties.getMonitoringHints()).thenReturn(List.of(
				RegexNameValue.builder().name("X-Origin-Forwarded-For").regex("192\\.168\\.33\\.[0-9]*").build()
		));
		var httpRequest = new MockHttpServletRequest();
		httpRequest.addHeader(httpHeaderName, httpHeaderValue);
		assertThat(OperationalUtil.skipUiFeaturesForAdminAndMonitoringClients(httpRequest, trustBrokerProperties), equalTo(expectedResult));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			"invalid,null,null",
			"43c0851b5aff697b87578d957ffa967556be59c0,null,urn:test:TESTRP", // sourceId match
			"invalid,https://referring-party.localdomain,https://referring-party.localdomain", // referrer match
	}, nullValues = "null")
	void getRelyingPartyByArtifactSourceIdOrReferrer(String sourceId, String referrer, String expectedRpId) {
		mockRelyingPartyConfiguration();
		var rp = relyingPartySetupService.getRelyingPartyByArtifactSourceIdOrReferrer(sourceId, referrer);
		assertThat(rp.isPresent(), is(expectedRpId != null));
		if (expectedRpId != null) {
			assertThat(rp.get().getId(), is(expectedRpId));
		}
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			"invalid,null,null",
			"62b27965d5014067653e103e64b876ab79de8d2c,null,urn:test:TESTCP", // sourceId match
			"invalid,https://idp.test.trustbroker.swiss/idp/,https://idp.test.trustbroker.swiss/idp/", // referrer match
	}, nullValues = "null")
	void getClaimsProviderByArtifactSourceIdOrReferrer(String sourceId, String referrer, String expectedCpId) {
		mockClaimsPartyConfiguration();
		var cp = relyingPartySetupService.getClaimsProviderByArtifactSourceIdOrReferrer(sourceId, referrer);
		assertThat(cp.isPresent(), is(expectedCpId != null));
		if (expectedCpId != null) {
			assertThat(cp.get().getId(), is(expectedCpId));
		}
	}

	@Test
	void matchesSourceIdFails() {
		var artifactBinding = ArtifactBinding.builder().sourceIdEncoded("encodedSourceId").sourceId("sourceId").build();
		assertThat(RelyingPartySetupService.matchesSourceId("inputId", "issuerId", artifactBinding), is(false));
		assertThat(RelyingPartySetupService.matchesSourceId("inputId", "issuerId", null), is(false));
	}

	@Test
	void matchesSourceIdByIssuerId() {
		var issuerId = "issuerId";
		var encoded = OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(issuerId);
		var artifactBinding = ArtifactBinding.builder().sourceIdEncoded("encodedSourceId").sourceId("sourceId").build();
		assertThat(RelyingPartySetupService.matchesSourceId(encoded, issuerId, artifactBinding), is(true));
		assertThat(RelyingPartySetupService.matchesSourceId(encoded, issuerId, null), is(true));
	}

	@Test
	void matchesSourceId() {
		var sourceId = "sourceId";
		var encoded = OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(sourceId);
		var artifactBinding = ArtifactBinding.builder().sourceIdEncoded("encodedSourceId").sourceId(sourceId).build();
		assertThat(RelyingPartySetupService.matchesSourceId(encoded, "issuerId", artifactBinding), is(true));
	}

	@Test
	void matchesSourceIdEncoded() {
		var encoded = "encodedSourceId";
		var artifactBinding = ArtifactBinding.builder().sourceIdEncoded(encoded).sourceId("sourceId").build();
		assertThat(RelyingPartySetupService.matchesSourceId(encoded, "issuerId", artifactBinding), is(true));
	}

	@Test
	void getCpSecurityPoliciesTest() {
		mockRelyingPartyConfiguration();
		mockClaimsPartyConfiguration();

		// SAML response from problem CP
		var authnResponseNoValidate = ServiceSamlTestUtil.loadSampleResponse();
		var policies = relyingPartySetupService.getPartySecurityPolicies(authnResponseNoValidate);
		assertThat(policies.getValidateXmlSchema(), is(false));

		// anything else validates
		var authnResponseValidate = ServiceSamlTestUtil.loadAuthnResponse();
		assertThat(relyingPartySetupService.getPartySecurityPolicies(authnResponseValidate), is(nullValue()));
	}

	@ParameterizedTest
	@MethodSource
	void getTokenLifetime(RelyingParty relyingParty, long tokenLifeTime, Long expected) {
		mockTokenLifeTime(tokenLifeTime);
		var result = relyingPartySetupService.getTokenLifetime(relyingParty);
		assertThat(result, is(expected));
	}

	static Object[][] getTokenLifetime() {
		return new Object[][] {
				{ null, 0l, 0l },
				{ RelyingParty.builder().id(RP_ID).build(), 8l, 8l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().build())
						.build(), 4l, 3600l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().notOnOrAfterSeconds(0).build())
						.build(), 7l, 0l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().notOnOrAfterSeconds(4).build())
						.build(), 9l, 4l },
		};
	}

	@ParameterizedTest
	@MethodSource
	void getAudienceRestrictionLifetime(RelyingParty relyingParty, long tokenLifeTime, Long expected) {
		mockTokenLifeTime(tokenLifeTime);
		var result = relyingPartySetupService.getAudienceRestrictionLifetime(relyingParty);
		assertThat(result, is(expected));
	}

	static Object[][] getAudienceRestrictionLifetime() {
		return new Object[][] {
				{ null, 12l, 12l },
				{ RelyingParty.builder().id(RP_ID).build(), -1l, -1l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().build())
						.build(), 4l, 3600l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().notOnOrAfterSeconds(12).build())
						.build(), 4l, 12l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().notOnOrAfterSeconds(-1).build())
						.build(), 4l, -1l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().audienceNotOnOrAfterSeconds(0).build())
						.build(), 7l, 3600l },
				{ RelyingParty.builder().id(RP_ID)
							  .securityPolicies(SecurityPolicies.builder().audienceNotOnOrAfterSeconds(1).build())
						.build(), 9l, 1l },
		};
	}

	@Test
	void getSsoGroupConfig() {
		var ssoGroup1 = SsoGroup.builder().name("SSO1").build();
		var ssoGroup2 = SsoGroup.builder().name("SSO2").build();
		var ssoGroups = List.of(ssoGroup1, ssoGroup2);
		var ssoGroupSetup = SsoGroupSetup.builder().ssoGroups(ssoGroups).build();
		doReturn(ssoGroupSetup).when(relyingPartyDefinitions).getSsoGroupSetup();

		assertThat(relyingPartySetupService.getSsoGroupConfig(ssoGroup1.getName()), is(ssoGroup1));
		assertThat(relyingPartySetupService.getSsoGroupConfig(ssoGroup2.getName(), true), is(Optional.of(ssoGroup2)));
		assertThat(relyingPartySetupService.getSsoGroupConfig("unknown", true), is(Optional.empty()));
		assertThrows(TechnicalException.class,
				() -> relyingPartySetupService.getSsoGroupConfig("invalid", false));
	}

	private void mockTokenLifeTime(long tokenLifeTime) {
		var secChecks = new SecurityChecks();
		secChecks.setTokenLifetimeSec(tokenLifeTime);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();
	}

	private void mockRelyingPartyConfiguration() {
		var relyingPartySetup = ServiceSamlTestUtil.loadRelyingPartySetup();
		when(relyingPartyDefinitions.getRelyingPartySetup())
				.thenReturn(relyingPartySetup);
	}

	private void mockClaimsPartyConfiguration() {
		var claimsPartySetup = ServiceSamlTestUtil.loadClaimsProviderSetup();
		when(relyingPartyDefinitions.getClaimsProviderSetup())
				.thenReturn(claimsPartySetup);
	}

}
