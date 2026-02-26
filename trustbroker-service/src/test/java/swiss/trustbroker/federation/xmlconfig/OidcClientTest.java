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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class OidcClientTest {

	private static final String ORIGIN = "https://trustbroker.swiss";

	@ParameterizedTest
	@MethodSource
	void isTrustedOrigin(List<String> acUrls, String origin, boolean expected) {
		var acWhitelist = acUrls == null ? null :
				AcWhitelist.builder()
						   .acUrls(acUrls)
						   .build();
		var oidcClient = OidcClient.builder()
								   .redirectUris(acWhitelist)
								   .build();
		assertThat(oidcClient.isTrustedOrigin(origin), is(expected));
	}

	static Object[][] isTrustedOrigin() {
		return new Object[][] {
				{ null, null, false },
				{ null, ORIGIN, false },
				{ List.of(ORIGIN), null, false },
				{ List.of(ORIGIN), ORIGIN, true },
				// default port and path irrelevant for origin:
				{ List.of(ORIGIN + ":443/test"), ORIGIN, true },
				{ List.of(ORIGIN + "/test"), ORIGIN, true },
				// port and protocol relevant for origin:
				{ List.of(ORIGIN + ":8080"), ORIGIN, false },
				{ List.of("http://trustbroker.swiss"), ORIGIN, false },
		};
	}

}
