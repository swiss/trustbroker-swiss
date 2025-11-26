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

package swiss.trustbroker.wstrust.validator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

import java.time.Clock;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
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

}
