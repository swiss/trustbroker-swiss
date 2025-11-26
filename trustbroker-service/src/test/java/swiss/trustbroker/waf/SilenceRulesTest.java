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

package swiss.trustbroker.waf;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.util.WebSupport;

class SilenceRulesTest {

	@ParameterizedTest
	@CsvSource(value = {
			"/,true",
			"/any,false",
			"/favicon.ico,true",
			"/favicon.ico:INTERNET,true",
			"/favicon.ico:INTRANET,true",
			"/favicon.ico:INTRANET:LB.IP.AD.DR,true",
			"/favicon.icon:INTRANET,false",
			"/apple-touch-icon-precomposed.png:INTERNET,true",
			"/apple-touch-icon-precomposed.png:INTRANET,true",
			"/apple-touch-icon-precomposedX.png:INTRANET,false",
			"/authtest/ntlm/:INTRANET,true",
			"/authtest/ntlm/:INTERNET,false",
			"/actuator/health,false",
			"/actuator/health:INTRANET,false",
			"/actuator/health:INTERNET,false",
			"/actuator/health:INTERNET:LB.IP.AD.DR,false",
			"/actuator/health:INTRANET:LB.IP.AD.DR,false", // we show the LB health check once per minute
			"/actuator/health:INTRANET:LB.IP.AD.DR,true",
			"/actuator/health:INTRANET:LB.IP.AD.DR,true"
	})
	void testSilenced(String pathAndNetwork, boolean silenced) {
		var request = new MockHttpServletRequest();
		var tokens = pathAndNetwork.split(":");
		var network = new NetworkConfig(); // default names INTERNET/INTRANET
		request.setRequestURI(tokens[0]);
		if (tokens.length > 1) {
			request.addHeader(network.getNetworkHeader(), tokens[1]);
		}
		if (tokens.length > 2) {
			request.addHeader(WebSupport.HTTP_HEADER_X_REAL_IP, tokens[2]);
		}
		assertThat("Sample " + pathAndNetwork + " should be silenced",
				SilenceRules.isSilenced(request, true, false, network), is(silenced));
	}

}
