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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.util.ApiSupport;

class OidcTxUtilTest {

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"/test,null",
			ApiSupport.KEYCLOAK_REALMS + "/client0,client0",
			ApiSupport.KEYCLOAK_REALMS + "/app1/test,app1",
			ApiSupport.KEYCLOAK_REALMS + "/ID2" + ApiSupport.PUBLIC_OIDC_CONFIG_PATH + ",ID2"
	}, nullValues = "null")
	void getKeycloakRealm(String path, String expectedRealm) {
		var result = OidcTxUtil.getKeycloakRealm(path);
		assertThat(result, is(expectedRealm));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,true",
			ApiSupport.PUBLIC_OIDC_CONFIG_PATH + ",realm1,true",
			ApiSupport.KEYCLOAK_REALMS + "/realm2" + ApiSupport.PUBLIC_OIDC_CONFIG_PATH + ",realm2,true",
			ApiSupport.KEYCLOAK_REALMS + "/otherRealm" + ApiSupport.PUBLIC_OIDC_CONFIG_PATH + ",realm1,false",
	}, nullValues = "null")
	void validateKeycloakRealm(String path, String realm, boolean expected) {
		var client = OidcClient.builder().realm(realm).build();
		var result = OidcTxUtil.validateKeycloakRealm(path, client, "https://localhost");
		assertThat(result, is(expected));
	}

}
