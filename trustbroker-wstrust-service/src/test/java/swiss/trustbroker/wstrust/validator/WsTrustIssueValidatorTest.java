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

package swiss.trustbroker.wstrust.validator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.WsTrust;
import swiss.trustbroker.federation.xmlconfig.WsTrustBinding;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.wstrust.util.WsTrustTestUtil;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration(classes = {
		WsTrustIssueValidator.class
})
class WsTrustIssueValidatorTest {

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private Clock clock;

	@Autowired
	private WsTrustIssueValidator wsTrustIssueValidator;

	private WsTrustConfig wsTrustConfig;

	@BeforeEach
	void setup() {
		wsTrustConfig = new WsTrustConfig();
		when(trustBrokerProperties.getWstrust()).thenReturn(wsTrustConfig);
	}

	@BeforeAll
	static void setupAll() {
		SamlInitializer.initSamlSubSystem();
	}

	@ParameterizedTest
	@MethodSource
	void applies(RequestType requestType, boolean protocolEnabled, boolean bindingEnabled, List<String> bindings,
			boolean expectedResult) {
		wsTrustConfig.setEnabled(protocolEnabled);
		wsTrustConfig.setIssueEnabled(bindingEnabled);
		wsTrustConfig.setBindings(bindings);
		assertThat(wsTrustIssueValidator.applies(requestType), is(expectedResult));
	}

	static Object[][] applies() {
		return new Object[][] {
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), true, true, null, true },
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), true, false, List.of(WsTrustBinding.RENEW.name()), false },
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), true, false,
						List.of(WsTrustBinding.RENEW.name(), WsTrustBinding.ISSUE.name()), true },
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), false, true, List.of(WsTrustBinding.ISSUE.name()), false },
				{ WsTrustUtil.createRequestType(RequestType.RENEW), true, true, Collections.emptyList(), false },
				{ WsTrustUtil.createRequestType(RequestType.RENEW), true, false, List.of(WsTrustBinding.ISSUE.getAction()), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void requireSignedRequests(ClaimsParty cp, RelyingParty rp, WsTrustConfig config,
			Function<WsTrustConfig, Boolean> configGetter, BiFunction<CounterParty, Boolean, Boolean> policyGetter,
			boolean expected) {
		var defaultValue = configGetter.apply(config);
		assertThat(WsTrustIssueValidator.calculateProperty(cp, rp, defaultValue, policyGetter, "requireSignedRequests"),
				is(expected));
	}

	static Object[][] requireSignedRequests() {
		return givenMockData(
				WsTrustConfig::setIssueRequireSignedRequests, WsTrustConfig::isIssueRequireSignedRequests,
				SecurityPolicies::setWsTrustIssueRequireSignedRequest, CounterParty::wsTrustIssueRequireSignedRequest);
	}

	@ParameterizedTest
	@MethodSource
	void requireSignedRequestAssertions(ClaimsParty cp, RelyingParty rp, WsTrustConfig config,
			Function<WsTrustConfig, Boolean> configGetter, BiFunction<CounterParty, Boolean, Boolean> policyGetter,
			boolean expected) {
		var defaultValue = configGetter.apply(config);
		assertThat(WsTrustIssueValidator.calculateProperty(cp, rp, defaultValue, policyGetter, "requireSignedRequestAssertions"),
				is(expected));
	}

	static Object[][] requireSignedRequestAssertions() {
		return givenMockData(
				WsTrustConfig::setIssueRequireSignedAssertions, WsTrustConfig::isIssueRequireSignedAssertions,
				SecurityPolicies::setWsTrustIssueRequireSignedAssertion, CounterParty::wsTrustIssueRequireSignedAssertion);
	}

	private static Object[][] givenMockData(
			BiConsumer<WsTrustConfig, Boolean> configSetter, Function<WsTrustConfig, Boolean> configGetter,
			BiConsumer<SecurityPolicies, Boolean> policySetter, BiFunction<CounterParty, Boolean, Boolean> policyGetter) {
		var defaultPolicies = new SecurityPolicies();
		var defaultConfig = new WsTrustConfig();
		var truePolicy = givenSecurityPolicies(true, policySetter);
		var falsePolicy = givenSecurityPolicies(false, policySetter);
		var trueConfig = givenConfig(true, configSetter);
		var falseConfig = givenConfig(false, configSetter);
		return new Object[][] {
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), defaultConfig, configGetter, policyGetter, true }, // default
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), falseConfig, configGetter, policyGetter, false }, // global
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), trueConfig, configGetter, policyGetter, true }, // global
				{ givenCp(truePolicy), givenRp(defaultPolicies), defaultConfig, configGetter, policyGetter, true }, // CP
				{ givenCp(truePolicy), givenRp(defaultPolicies), falseConfig, configGetter, policyGetter, true }, // CP
				{ givenCp(falsePolicy), givenRp(defaultPolicies), defaultConfig, configGetter, policyGetter, false }, // CP
				{ givenCp(truePolicy), givenRp(falsePolicy), defaultConfig, configGetter, policyGetter, false }, // RP
				{ givenCp(defaultPolicies), givenRp(falsePolicy), defaultConfig, configGetter, policyGetter, false }, // RP
				{ givenCp(defaultPolicies), givenRp(truePolicy), defaultConfig, configGetter, policyGetter, true }, // RP
				{ givenCp(falsePolicy), givenRp(truePolicy), defaultConfig, configGetter, policyGetter, true }, // RP
				{ givenCp(falsePolicy), givenRp(truePolicy), falseConfig, configGetter, policyGetter, true } // RP
		};
	}

	private static RelyingParty givenRp(SecurityPolicies policies) {
		return RelyingParty.builder()
				.id("rp1")
				.securityPolicies(policies)
				.build();
	}

	private static ClaimsParty givenCp(SecurityPolicies policies) {
		return ClaimsParty.builder()
						   .id("cp1")
						   .securityPolicies(policies)
						   .build();
	}

	private static SecurityPolicies givenSecurityPolicies(Boolean value, BiConsumer<SecurityPolicies, Boolean> attribute) {
		var config = new SecurityPolicies();
		if (value != null) {
			attribute.accept(config, value);
		}
		return config;
	}

	private static WsTrustConfig givenConfig(Boolean value, BiConsumer<WsTrustConfig, Boolean> attribute) {
		var config = new WsTrustConfig();
		if (value != null) {
			attribute.accept(config, value);
		}
		return config;
	}

	@ParameterizedTest
	@MethodSource
	void validateInvalidTimestamp(Instant now, Instant created, Instant expires,
			SecurityPolicies rpPolicies, SecurityPolicies cpPolicies, String expected) {
		mockProperties();
		when(clock.instant()).thenReturn(now);
		var assertion = WsTrustTestUtil.givenAssertion();
		var header = WsTrustTestUtil.givenRequestHeader(assertion, created, expires);
		var rst = WsTrustTestUtil.givenIssueRstRequest();
		rst.getUnknownXMLObjects().add(WsTrustTestUtil.givenAddress(WsTrustTestUtil.RP_ISSUER_ID));
		SamlIoUtil.marshalXmlObject(rst); // produce DOM for address resolution
		mockRpIssuer(rpPolicies);
		mockCpIssuer(cpPolicies);
		var result = assertThrows(RequestDeniedException.class, () -> wsTrustIssueValidator.validate(rst, header));
		assertThat(result.getInternalMessage(), containsString(expected));
	}

	static Object[][] validateInvalidTimestamp() {
		var now = WsTrustTestUtil.NOW;
		var timestampOk = "Audience missing"; // timestamp check override: error after timestamp validation due to test data
		// overrides for some cases are just either CP or RP as the code is the same
		return new Object[][] {
				{ now, null, null, null, null, "Timestamp missing" },
				{ now, null, null, SecurityPolicies.builder().wsTrustIssueRequireTimestamp(false).build(), null, timestampOk },
				{ now, null, null, null, SecurityPolicies.builder().wsTrustIssueRequireTimestamp(false).build(), timestampOk },
				{ now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC - 1),
						now.plusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC), null, null, "Timestamp invalid" },
				{ now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC - 1),
						now.plusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC),
						SecurityPolicies.builder().wsTrustIssueRequireTimestamp(false).build(), null, timestampOk },
				{ now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC - 1),
						now.plusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC), null,
						SecurityPolicies.builder()
										.wsTrustIssueNotBeforeToleranceSec(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC - 2)
										.build(),
						timestampOk },
				{ now, now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 1),
						null, null, "Timestamp invalid" },
				{ now, now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 1),
						null, SecurityPolicies.builder().wsTrustIssueRequireTimestamp(false).build(), timestampOk },
				{ now, now, now.minusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 1),
						SecurityPolicies.builder()
										.wsTrustIssueNotOnOrAfterToleranceSec(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 1)
										.build(),
						null, timestampOk }
		};
	}

	@Test
	void validate() {
		mockCpIssuer(null);
		mockRpIssuer(null);
		mockProperties();
		var now = WsTrustTestUtil.NOW;
		when(clock.instant()).thenReturn(now);
		var assertion = WsTrustTestUtil.givenAssertion(WsTrustTestUtil.TEST_TO);
		SamlTestBase.signSamlObject(assertion);
		var header = WsTrustTestUtil.givenRequestHeader(assertion, now, now.plusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC));
		var rst = WsTrustTestUtil.givenIssueRstRequest();
		SamlIoUtil.marshalXmlObject(rst); // produce DOM for address resolution
		var result = wsTrustIssueValidator.validate(rst, header);
		assertThat(result.getValidatedAssertion(), is(assertion));
	}

	private void mockProperties() {
		var wsTrust = WsTrustConfig.builder()
								   .enabled(true)
								   .bindings(List.of(WsTrustBinding.ISSUE.name()))
								   // If true requires a SoapMessage signed with private key for RelyingParty.SignerTrustStore:
								   .issueRequireSignedRequests(false)
								   .build();
		when(trustBrokerProperties.getWstrust()).thenReturn(wsTrust);
		when(trustBrokerProperties.getIssuer()).thenReturn(WsTrustTestUtil.TEST_TO);
		when(trustBrokerProperties.getSecurity()).thenReturn(new SecurityChecks());
	}

	private void mockCpIssuer(SecurityPolicies securityPolicies) {
		var trustCredential = SamlTestBase.dummyCredential();
		var trustCredentials = List.of(trustCredential);
		var cp = ClaimsParty.builder()
							.id(WsTrustTestUtil.XTB_ISSUER_ID)
							.wsTrust(WsTrust.builder().enabled(true).build())
							.securityPolicies(securityPolicies)
							.cpTrustCredential(trustCredentials)
							.build();
		when(relyingPartySetupService.getClaimsProviderSetupByIssuerId(WsTrustTestUtil.XTB_ISSUER_ID, null)).thenReturn(cp);
	}

	private void mockRpIssuer(SecurityPolicies securityPolicies) {
		var rp = RelyingParty.builder()
							 .id(WsTrustTestUtil.RP_ISSUER_ID)
							 .wsTrust(WsTrust.builder().enabled(true).build())
							 .securityPolicies(securityPolicies)
							 .build();
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(WsTrustTestUtil.RP_ISSUER_ID, null)).thenReturn(rp);
	}

}
