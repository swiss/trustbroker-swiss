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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.exception.TechnicalException;

class OidcTxRequestWrapperTest {

	private OidcTxRequestWrapper mapper;

	private MockHttpServletRequest request;

	@BeforeEach
	void setUp() {
		request = new MockHttpServletRequest();
		mapper = new OidcTxRequestWrapper(request);
	}

	@ParameterizedTest
	@MethodSource
	void getServletPath(String path, String mapped) {
		request.setServletPath(path);
		if (TechnicalException.class.getSimpleName().equals(mapped)) {
			var ex = assertThrows(TechnicalException.class, () -> {
				mapper.getServletPath();
			});
			assertThat(ex.getInternalMessage(), containsString("Invalid access to"));
		}
		else {
			assertThat(mapper.getServletPath(), is(mapped));
		}
	}

	static String[][] getServletPath() {
		return new String[][] {
				// not mapped
				{ null, null },
				{ "/", "/" },
				{ "/other/auth", "/other/auth" },
				{ "/realms/any", TechnicalException.class.getSimpleName() },
				{ "/any/realms", "/any/realms" },
				{ "/realms/any/token", "/oauth2/token" },
				{ "/realms/any/protocol/openid-connect/invalid", TechnicalException.class.getSimpleName() },
				{ "/.well-known/openid-configuration", "/.well-known/openid-configuration" },
				{ "/api/v1/openid-configuration", "/.well-known/openid-configuration" },
				{ "/oauth2/auth", TechnicalException.class.getSimpleName() },
				{ "/oauth2/authorize", "/oauth2/authorize" },
				{ "/oauth2/tokenX", TechnicalException.class.getSimpleName() },
				{ "/oauth2/token", "/oauth2/token" },
				// mapped
				{ "/realms/any/protocol/openid-connect/token", "/oauth2/token" },
				{ "/realms/any/protocol/openid-connect/token/introspect", "/oauth2/introspect" },
				{ "/realms/any/protocol/openid-connect/userinfo", "/userinfo" },
				{ "/realms/any/protocol/openid-connect/certs", "/oauth2/jwks" },
				{ "/realms/any/protocol/openid-connect/revoke", "/oauth2/revoke" },
				{ "/realms/any/protocol/openid-connect/logout", "/logout" },
				{ "/realms/any/.well-known", TechnicalException.class.getSimpleName() },
				{ "/realms/any/.well-known/openid-configuration", "/.well-known/openid-configuration" }
		};
	}

}
