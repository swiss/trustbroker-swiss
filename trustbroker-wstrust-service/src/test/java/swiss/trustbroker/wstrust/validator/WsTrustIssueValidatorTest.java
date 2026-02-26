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
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

import java.time.Clock;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.script.service.ScriptService;
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
	void applies(RequestType requestType, boolean enabled, boolean expectedResult) {
		wsTrustConfig.setIssueEnabled(enabled);
		assertThat(wsTrustIssueValidator.applies(requestType), is(expectedResult));
	}

	static Object[][] applies() {
		return new Object[][] {
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), true, true },
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), false, false },
				{ WsTrustUtil.createRequestType(RequestType.RENEW), true, false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void requireSignedRequest(ClaimsParty cp, RelyingParty rp, WsTrustConfig config, boolean expected) {
		assertThat(WsTrustIssueValidator.requireSignedRequest(cp, rp, config), is(expected));
	}

	static Object[][] requireSignedRequest() {
		var defaultPolicies = new SecurityPolicies();
		var defaultConfig = new  WsTrustConfig();
		return new Object[][] {
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), defaultConfig, true }, // default
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), givenConfig(true, null), true }, //  global
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), givenConfig(false, null), false }, //  global
				{ givenCp(givenSecurityPolicies(true, null)), givenRp(defaultPolicies), defaultConfig, true }, // CP
				{ givenCp(givenSecurityPolicies(true, null)), givenRp(defaultPolicies), givenConfig(false, null), true }, // CP
				{ givenCp(givenSecurityPolicies(false, null)), givenRp(defaultPolicies), defaultConfig, false }, // CP
				{ givenCp(givenSecurityPolicies(true, null)), givenRp(givenSecurityPolicies(false, null)),
						defaultConfig, false }, // RP
				{ givenCp(defaultPolicies), givenRp(givenSecurityPolicies(false, null)),
						defaultConfig, false }, // RP
				{ givenCp(givenSecurityPolicies(false, null)), givenRp(givenSecurityPolicies(true, null)),
						defaultConfig, true }, // RP
				{ givenCp(givenSecurityPolicies(false, null)), givenRp(givenSecurityPolicies(true, null)),
						givenConfig(false, null), true } // RP
		};
	}

	@ParameterizedTest
	@MethodSource
	void requireSignedAssertion(ClaimsParty cp, RelyingParty rp, WsTrustConfig config, boolean expected) {
		assertThat(WsTrustIssueValidator.requireSignedAssertion(cp, rp, config), is(expected));
	}

	static Object[][] requireSignedAssertion() {
		var defaultPolicies = new SecurityPolicies();
		var defaultConfig = new  WsTrustConfig();
		return new Object[][] {
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), defaultConfig, true }, // default
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), givenConfig(null, false), false }, // default
				{ givenCp(defaultPolicies), givenRp(defaultPolicies), givenConfig(null, true), true }, // default
				{ givenCp(givenSecurityPolicies(null, true)), givenRp(defaultPolicies), defaultConfig, true }, // CP
				{ givenCp(givenSecurityPolicies(null, true)), givenRp(defaultPolicies), givenConfig(null, false), true }, // CP
				{ givenCp(givenSecurityPolicies(null, false)), givenRp(defaultPolicies), defaultConfig, false }, // CP
				{ givenCp(defaultPolicies), givenRp(givenSecurityPolicies(null, false)), defaultConfig, false }, // RP
				{ givenCp(defaultPolicies), givenRp(givenSecurityPolicies(null, true)), defaultConfig, true }, // RP
				{ givenCp(givenSecurityPolicies(null, true)),
						givenRp(givenSecurityPolicies(null, false)), defaultConfig, false }, // RP
				{ givenCp(givenSecurityPolicies(null, false)),
						givenRp(givenSecurityPolicies(null, true)), defaultConfig, true }, // RP
				{ givenCp(givenSecurityPolicies(null, false)),
						givenRp(givenSecurityPolicies(null, true)), givenConfig(null, false), true }, // RP
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

	private static SecurityPolicies givenSecurityPolicies(Boolean requireSignedRequest, Boolean requireSignedAssertion) {
		return SecurityPolicies.builder()
							   .wsTrustIssueRequireSignedRequest(requireSignedRequest)
							   .wsTrustIssueRequireSignedAssertion(requireSignedAssertion)
							   .build();
	}

	private static WsTrustConfig givenConfig(Boolean requireSignedRequest, Boolean requireSignedAssertion) {
		var config = new WsTrustConfig();
		if (requireSignedRequest != null) {
			config.setIssueRequireSignedRequests(requireSignedRequest);
		}
		if (requireSignedAssertion != null) {
			config.setIssueRequireSignedAssertions(requireSignedAssertion);
		}
		return config;
	}

	@Test
	@Disabled
	void validate() {
		var cp = ClaimsParty.builder()
							.id(WsTrustTestUtil.XTB_ISSUER_ID)
							.build();
		when(relyingPartySetupService.getClaimsProviderSetupByIssuerId(WsTrustTestUtil.XTB_ISSUER_ID, null)).thenReturn(cp);
		when(trustBrokerProperties.getIssuer()).thenReturn(WsTrustTestUtil.TEST_TO);
		var assertion = WsTrustTestUtil.givenAssertion();
		var header = WsTrustTestUtil.givenRequestHeader(assertion);
		var rst = WsTrustTestUtil.givenIssueRstRequest();
		var result = wsTrustIssueValidator.validate(rst, header);
		assertThat(result.getValidatedAssertion(), is(assertion));
	}
}
