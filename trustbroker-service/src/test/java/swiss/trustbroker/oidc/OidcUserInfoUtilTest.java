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

package swiss.trustbroker.oidc;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.List;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.script.service.ScriptService;

class OidcUserInfoUtilTest {

	@Test
	void filterUnwantedClaimsRemovesConfiguredClaims() {
		var claims = new LinkedHashMap<String, Object>();
		claims.put("sub", "subject");
		claims.put("email", "user@example.org");
		claims.put("remove", "secret");
		var clientId = "client-1";
		var properties = new TrustBrokerProperties();
		properties.getOidc().setRemoveUserInfoClaims(List.of("remove"));
		var relyingPartyDefinitions = mock(RelyingPartyDefinitions.class);
		var scriptService = mock(ScriptService.class);
		var relyingParty = RelyingParty.builder().id("rp-issuer").build();
		when(relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, properties, true)).thenReturn(relyingParty);

		var filteredClaims = OidcUserInfoUtil.filterUnwantedClaims(claims, clientId, relyingPartyDefinitions, scriptService, properties);

		assertThat(filteredClaims.size(), is(2));
		assertThat(filteredClaims, hasEntry("sub", "subject"));
		assertThat(filteredClaims, hasEntry("email", "user@example.org"));
		assertThat(filteredClaims, not(hasKey("remove")));
		assertThat(claims, hasEntry("email", "user@example.org"));
		assertThat(claims, hasEntry("remove", "secret"));
	}
}
