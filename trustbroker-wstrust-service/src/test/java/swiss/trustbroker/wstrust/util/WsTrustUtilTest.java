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

package swiss.trustbroker.wstrust.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.dto.NetworkConfig;

class WsTrustUtilTest {

	@BeforeAll
	static void setupAll() {
		SamlInitializer.initSamlSubSystem();
	}

	@ParameterizedTest
	@MethodSource
	void isNetworkAllowed(String network, List<String> allowedNetworks, boolean enforce, boolean expected) {
		var config = new NetworkConfig();
		var request = new MockHttpServletRequest();
		if (network != null) {
			request.addHeader(config.getNetworkHeader(), network);
		}
		assertThat(WsTrustUtil.isNetworkAllowed(allowedNetworks, enforce, request, config), is(expected));
	}

	static Object[][] isNetworkAllowed() {
		var config = new NetworkConfig();
		return new Object[][] {
				{ null, null, false, true },
				{ null, null, true, true },
				{ config.getInternetNetworkName(), null, true, true },
				{ config.getInternetNetworkName(), Collections.emptyList(), true, true },
				{ config.getInternetNetworkName(), List.of(config.getIntranetNetworkName()), false, true }, // not enforced, NOK
				{ config.getInternetNetworkName(), List.of(config.getInternetNetworkName()), true, true }, // enforced,OK
				{ config.getIntranetNetworkName(), List.of(config.getInternetNetworkName(), config.getIntranetNetworkName()),
						true, true }, // enforced,OK
				{ config.getInternetNetworkName(), List.of(config.getIntranetNetworkName()), true, false } // enforced, OK
		};
	}

	@ParameterizedTest
	@CsvSource(value = {
		"null,null,false,true",
		"10.10.10.10,null,false,true",
		"10.10.10.10,null,true,true",
		"10.10.10.10,,true,true",
		"10.10.10.10,^99\\..*$,false,true", // not enforced, NOK
		"10.10.10.10,^99\\.*$,true,false", // enforced, NOK
		"10.10.10.10,^(99\\..*|10\\.99\\..*)$,true,false", // enforced, NOK
		"10.10.10.10,^(99\\..*|10\\.10\\..*)$,true,true" // enforced, OK
	}, nullValues = "null")
	void isClientIpAllowed(String ip, String regex, boolean enforce, boolean expected) {
		assertThat(WsTrustUtil.isClientIpAllowed(regex, enforce, ip), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = { "testAddress,false", "testAddress,true", "null,false" }, nullValues = "null")
	void getEndpointReferenceAddress(String address, boolean wsa) {
		var request = WsTrustTestUtil.givenRst(WSTrustConstants.WSA_ACTION_RST_ISSUE, address, wsa);
		assertThat(WsTrustUtil.getEndpointReferenceAddress(request), is(address));
	}

	@Test
	void getNameID() {
		var assertion = WsTrustTestUtil.givenAssertion();
		assertThat(WsTrustUtil.getNameID(assertion).getValue(), is(WsTrustTestUtil.NAME_ID));
	}

	@Test
	void getAuthnContextClasses() {
		var assertion = WsTrustTestUtil.givenAssertion();
		assertThat(WsTrustUtil.getAuthnContextClasses(assertion), is(List.of(WsTrustTestUtil.CONTEXT_CLASS)));
	}
}
