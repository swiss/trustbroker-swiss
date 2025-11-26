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

package swiss.trustbroker.federation.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.dto.ConfigElementStatus;
import swiss.trustbroker.federation.dto.ConfigStatus;
import swiss.trustbroker.federation.dto.ConfigStatusData;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;

@SpringBootTest
@ContextConfiguration(classes = XmlConfigStatusService.class)
class XmlConfigStatusServiceTest {

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Autowired
	private XmlConfigStatusService configStatusService;

	@Test
	void testGetConfigStatusErrorOk() {
		var emptyRpSetup = givenEmptyRpSetup();
		var emptyCpSetup = givenEmptyCpSetup();
		var rpSetup = givenRpSetup();
		var cpSetup = givenCpSetup();

		testGetConfigStatus(emptyRpSetup, emptyCpSetup, ConfigStatus.ERROR, Collections.emptyList(), Collections.emptyList());
		testGetConfigStatus(rpSetup, emptyCpSetup, ConfigStatus.ERROR, Collections.emptyList(), Collections.emptyList());
		testGetConfigStatus(emptyRpSetup, cpSetup, ConfigStatus.ERROR, Collections.emptyList(), Collections.emptyList());

		testGetConfigStatus(rpSetup, cpSetup, ConfigStatus.OK, Collections.emptyList(), Collections.emptyList());
	}

	@Test
	void testGetConfigStatusWarn() {
		var rpSetup = givenRpSetup();
		var unfilteredRps = new ArrayList<>(rpSetup.getRelyingParties());
		var invalidRp = RelyingParty.builder()
									.id("rp3")
									.enabled(FeatureEnum.INVALID)
									.build();
		invalidRp.getValidationStatus().addException(givenException("rp3"));
		unfilteredRps.add(invalidRp);
		var rpWithErrors = RelyingParty.builder()
									.id("rp4")
									.enabled(FeatureEnum.TRUE)
									.build();
		rpWithErrors.getValidationStatus().addError("rp4 invalid");
		unfilteredRps.add(rpWithErrors);
		rpSetup.setUnfilteredRelyingParties(unfilteredRps);
		var invalidRps = List.of(
				ConfigElementStatus.builder()
								   .id(invalidRp.getId())
								   .errors(List.of("rp3 invalid", "Invalid xml for rp3"))
								   .build(),
				ConfigElementStatus.builder()
								   .id(rpWithErrors.getId())
								   .errors(List.of("rp4 invalid"))
								   .build());

		var cpSetup = givenCpSetup();
		var unfilteredCps = new ArrayList<>(cpSetup.getClaimsParties());
		var invalidCp = ClaimsParty.builder()
								   .id("cp3")
								   .enabled(FeatureEnum.INVALID)
								   .build();
		invalidCp.getValidationStatus().addException(givenException("cp3"));
		unfilteredCps.add(invalidCp);
		var cpWithErrors = ClaimsParty.builder()
									   .id("cp4")
									   .enabled(FeatureEnum.TRUE)
									   .build();
		cpWithErrors.getValidationStatus().addError("cp4 invalid");
		unfilteredCps.add(cpWithErrors);
		cpSetup.setUnfilteredClaimsParties(unfilteredCps);
		var invalidCps = List.of(
				ConfigElementStatus.builder()
								   .id(invalidCp.getId())
								   .errors(List.of("cp3 invalid", "Invalid xml for cp3"))
								   .build(),
				ConfigElementStatus.builder()
								   .id(cpWithErrors.getId())
								   .errors(List.of("cp4 invalid"))
								   .build());

		testGetConfigStatus(rpSetup, cpSetup, ConfigStatus.WARN, invalidRps, invalidCps);
	}

	private static TechnicalException givenException(String id) {
		var cause = new IllegalArgumentException("Invalid xml for " + id);
		return new TechnicalException(id + " invalid", cause);
	}

	private static ClaimsProviderSetup givenEmptyCpSetup() {
		return ClaimsProviderSetup.builder().claimsParties(Collections.emptyList()).build();
	}

	private static RelyingPartySetup givenEmptyRpSetup() {
		return RelyingPartySetup.builder().relyingParties(Collections.emptyList()).build();
	}
	private static RelyingPartySetup givenRpSetup() {
		var rps = List.of(RelyingParty.builder().id("rp1").build(), RelyingParty.builder().id("rp2").build());
		return RelyingPartySetup.builder().relyingParties(rps).build();
	}

	private static ClaimsProviderSetup givenCpSetup() {
		var cps = List.of(ClaimsParty.builder().id("cp1").build(), ClaimsParty.builder().id("cp2").build());
		return ClaimsProviderSetup.builder().claimsParties(cps).build();
	}

	private void testGetConfigStatus(RelyingPartySetup rpSetup, ClaimsProviderSetup cpSetup, ConfigStatus error,
			List<ConfigElementStatus> rpStatuses, List<ConfigElementStatus> cpStatuses) {
		doReturn(rpSetup).when(relyingPartyDefinitions).getRelyingPartySetup();
		doReturn(cpSetup).when(relyingPartyDefinitions).getClaimsProviderSetup();
		var status = ConfigStatusData.builder()
									 .status(error)
									 .relyingParties(rpStatuses)
									 .claimsProviders(cpStatuses)
									 .build();

		var result = configStatusService.getConfigStatus();
		assertEquals(status, result);
	}

}
