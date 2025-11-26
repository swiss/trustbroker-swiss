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

package swiss.trustbroker.oidc.client.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.oidc.OidcMockTestData;

@SpringBootTest(classes = JwtClaimsService.class)
class JwtClaimsServiceTest {

	@MockitoBean
	private ClaimsMapperService claimsMapperService;

	@Autowired
	private JwtClaimsService jwtClaimsService;

	@Test
	void mapClaimsToAttributes() throws Exception {
		var client = OidcMockTestData.givenClient();
		var cp = OidcMockTestData.givenCpWithOidcClient(client);
		var jwtClaimsSet = givenJwtClaimsSet(null);

		// return unmodified list
		doAnswer(invocation -> invocation.getArgument(1)).when(claimsMapperService).applyMappers(any(), any(), any());

		var definitions = jwtClaimsService.mapClaimsToAttributes(jwtClaimsSet, cp);

		assertThat(definitions.size(), is(3));
		assertThat(definitions.get(new Definition(OidcMockTestData.CLAIM_GIVEN_NAME)),
				is(List.of(OidcMockTestData.GIVEN_NAME)));
		assertThat(definitions.get(new Definition(OidcMockTestData.CLAIM_FAMILY_NAME)),
				is(List.of(OidcMockTestData.FAMILY_NAME)));
		assertThat(definitions.get(new Definition(OidcMockTestData.CLAIM_EMAIL)),
				is(List.of(OidcMockTestData.EMAIL)));
	}

	@Test
	void getCtxClasses() throws Exception {
		var jwtClaimsSet = givenJwtClaimsSet(null);
		var claimsParty = ClaimsParty.builder().id("cpId").build();

		assertThat(jwtClaimsService.getCtxClasses(jwtClaimsSet, claimsParty), empty());

		var qoa = Qoa.builder().claim(OidcMockTestData.CLAIM_GIVEN_NAME).build();
		claimsParty.setQoa(qoa);
		assertThat(jwtClaimsService.getCtxClasses(jwtClaimsSet, claimsParty), contains(OidcMockTestData.GIVEN_NAME));

		var defaultQoa = "defaultQoa";
		qoa = Qoa.builder().defaultQoa(defaultQoa).build();
		claimsParty.setQoa(qoa);
		assertThat(jwtClaimsService.getCtxClasses(jwtClaimsSet, claimsParty), contains(defaultQoa));

		var acrClaim = OidcUtil.OIDC_ACR;
		var acrValue = "acrValue";
		jwtClaimsSet = givenJwtClaimsSet(Map.of(acrClaim, acrValue));
		assertThat(jwtClaimsService.getCtxClasses(jwtClaimsSet, claimsParty), contains(acrValue));
	}

	static JWTClaimsSet givenJwtClaimsSet(Map<String, Object> claims) throws ParseException {
		var userClaims = new HashMap<String, Object>(Map.of(
				OidcMockTestData.CLAIM_GIVEN_NAME, OidcMockTestData.GIVEN_NAME,
				OidcMockTestData.CLAIM_FAMILY_NAME, OidcMockTestData.FAMILY_NAME,
				OidcMockTestData.CLAIM_EMAIL, OidcMockTestData.EMAIL
		));
		if (claims != null) {
			userClaims.putAll(claims);
		}
		return JWTClaimsSet.parse(userClaims);
	}

}
