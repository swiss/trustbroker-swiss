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

package swiss.trustbroker.saml.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.StatusPolicy;
import swiss.trustbroker.saml.dto.CpResponse;

@SpringBootTest
@ContextConfiguration(classes = UnknownUserPolicyService.class)
class UnknownUserPolicyServiceTest {

	private static final String IDENTITY_QUERY = "IDENTITY";

	private static final String TENANT_QUERY = "TENANT";

	@Autowired
	UnknownUserPolicyService unknownUserPolicyService;

	@Test
	void blockUnknownUserResponseTest() {
		assertFalse(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(null, "Name"), givenClaimsParty(null)));
		assertFalse(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(null, null), givenClaimsParty(StatusPolicy.BLOCK)));
		assertFalse(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(StatusPolicy.ALLOW_UNKNOWN_USER, null), givenClaimsParty(StatusPolicy.BLOCK_UNKNOWN_USER)));
		assertFalse(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(StatusPolicy.BLOCK_UNKNOWN_USER, null), givenClaimsParty(StatusPolicy.ALLOW_UNKNOWN_USER)));
		assertTrue(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(StatusPolicy.BLOCK, null), givenClaimsParty(StatusPolicy.BLOCK_UNKNOWN_USER)));
		assertTrue(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(StatusPolicy.BLOCK_UNKNOWN_USER, null), givenClaimsParty(StatusPolicy.BLOCK_UNKNOWN_USER)));
		assertTrue(unknownUserPolicyService.blockUnknownUserResponse(
				givenCpResponse(StatusPolicy.BLOCK_UNKNOWN_USER, null), givenClaimsParty(null)));
		assertFalse(unknownUserPolicyService.blockUnknownUserResponse(new CpResponse(),
				givenClaimsParty(StatusPolicy.BLOCK_UNKNOWN_USER)));
	}

	@Test
	void getIdmUnknownUserStatusPolicyTest() {
		assertNull(unknownUserPolicyService.getIdmUnknownUserStatusPolicy(givenCpResponse(null, null)));
		assertNull(unknownUserPolicyService.getIdmUnknownUserStatusPolicy(new CpResponse()));
		assertEquals(StatusPolicy.BLOCK_UNKNOWN_USER, unknownUserPolicyService.getIdmUnknownUserStatusPolicy(
				givenCpResponse(StatusPolicy.BLOCK_UNKNOWN_USER, null)));
		assertEquals(StatusPolicy.ALLOW_UNKNOWN_USER, unknownUserPolicyService.getIdmUnknownUserStatusPolicy(
				givenCpResponse(StatusPolicy.ALLOW_UNKNOWN_USER, null)));
	}

	@Test
	void applyUnknownUserPolicyTest() {
		CpResponse cpResponseAborted = givenCpResponse(StatusPolicy.BLOCK, null);
		unknownUserPolicyService.applyUnknownUserPolicy(cpResponseAborted, givenClaimsParty(StatusPolicy.BLOCK_UNKNOWN_USER));
		assertTrue(cpResponseAborted.isAborted());

		CpResponse cpResponse = givenCpResponse(null, null);
		unknownUserPolicyService.applyUnknownUserPolicy(cpResponse, givenClaimsParty(null));
		assertFalse(cpResponse.isAborted());
	}

	private static CpResponse givenCpResponse(StatusPolicy statusPolicy, String nameAttribute) {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(Definition.ofNames(CoreAttributeName.FIRST_NAME), List.of("AAAAAA"));
		attributeValueMap.put(Definition.ofNames(CoreAttributeName.EMAIL), List.of("SSSSSS"));
		if (nameAttribute != null) {
			attributeValueMap.put(Definition.ofNames(CoreAttributeName.NAME), List.of(nameAttribute));
		}
		CpResponse cpResponse = new CpResponse();
		cpResponse.setUserDetails(attributeValueMap);
		cpResponse.setIdmLookup(givenIDMLookup(statusPolicy));
		return cpResponse;
	}

	private static IdmLookup givenIDMLookup(StatusPolicy statusPolicy) {
		var clientExtId = "extId1";
		IdmQuery idmQuery1 = IdmQuery.builder()
									 .name(IDENTITY_QUERY)
									 .statusPolicy(statusPolicy)
									 .clientExtId(clientExtId)
									 .build();
		IdmQuery idmQuery2 = IdmQuery.builder().name(TENANT_QUERY).clientExtId(clientExtId).build();

		List<IdmQuery> queries = new ArrayList<>();
		queries.add(idmQuery1);
		queries.add(idmQuery2);

		IdmLookup idmLookup = new IdmLookup();
		idmLookup.setQueries(queries);

		return idmLookup;
	}

	private ClaimsParty givenClaimsParty(StatusPolicy statusPolicy) {
		return ClaimsParty.builder()
				.statusPolicy(statusPolicy)
				.id("cpId")
				.build();
	}
}
