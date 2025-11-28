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

package swiss.trustbroker.homerealmdiscovery.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static swiss.trustbroker.config.TestConstants.LATEST_INVALID_DEFINITION_PATH;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_CP;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_RP;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TestConstants;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;

class ClaimsProviderUtilTest {

	@Test
	void loadClaimsProviderSetup() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_SETUP_CP).getFile();
		var claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(definition);
		assertThat(claimsProviderSetup.getClaimsParties(), hasSize(TestConstants.VALID_TEST_CPS));
	}

	@Test
	void loadClaimsProviderSetupInvalid() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(LATEST_INVALID_DEFINITION_PATH +
				"SetupCPInvalidXml.xml").getFile();
		var claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(definition);
		assertThat(claimsProviderSetup.getClaimsParties(), hasSize(1));
		var cp = claimsProviderSetup.getClaimsParties().get(0);
		assertThat(cp.getId(), is(definition));
		assertThat(cp.getValidationStatus().getErrors(), hasSize(2));
	}

	@Test
	void loadRelyingPartySetup() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_SETUP_RP).getFile();
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(definition);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(TestConstants.VALID_TEST_RPS));
	}

	@Test
	void loadRelyingPartySetupInvalid() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(LATEST_INVALID_DEFINITION_PATH +
				"SetupRPInvalidXml.xml").getFile();
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(definition);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(1));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		assertThat(rp.getId(), is(definition));
		assertThat(rp.getValidationStatus().getErrors(), hasSize(2));
	}

	@ParameterizedTest
	@MethodSource(value = "addInvalidParty")
	void addInvalidRelyingParty(Exception ex, String message, String expectedMessage) {
		var rpId = "rp1";
		var setup = RelyingPartySetup.builder().build();
		ClaimsProviderUtil.addInvalidRelyingParty(setup, rpId, ex, message);
		assertThat(setup.getRelyingParties(), hasSize(1));
		var rp = setup.getRelyingParties().get(0);
		assertThat(rp.getId(), is(rpId));
		assertThat(rp.isValid(), is(false));
		validateStatus(expectedMessage, rp.getValidationStatus().getErrors());
	}

	@ParameterizedTest
	@MethodSource(value = "addInvalidParty")
	void addInvalidClaimsParty(Exception ex, String message, String expectedMessage) {
		var cpId = "cp1";
		var setup = ClaimsProviderSetup.builder().build();
		ClaimsProviderUtil.addInvalidClaimsParty(setup, cpId, ex, message);
		assertThat(setup.getClaimsParties(), hasSize(1));
		var cp = setup.getClaimsParties().get(0);
		assertThat(cp.getId(), is(cpId));
		assertThat(cp.isValid(), is(false));
		validateStatus(expectedMessage, cp.getValidationStatus().getErrors());
	}

	private static void validateStatus(String expectedMessage, List<String> errors) {
		if (expectedMessage == null) {
			assertThat(errors, hasSize(0));
		}
		else {
			assertThat(errors, hasSize(1));
			assertThat(errors.get(0), is(expectedMessage));
		}
	}

	static Object[][] addInvalidParty() {
		return new Object[][] {
				{ new TechnicalException("exMessage"), null, "exMessage" },
				{ null, "errMessage", "errMessage" },
				{ null, null, null },
		};
	}

}
