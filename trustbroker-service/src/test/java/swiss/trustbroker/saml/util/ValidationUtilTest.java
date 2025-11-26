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

package swiss.trustbroker.saml.util;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.saml.dto.ResponseData;

class ValidationUtilTest {

	@BeforeAll
	static void init() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void validateMissingRelayState() {
		var responseData = ResponseData.of(null, null, null);
		assertThrows(RequestDeniedException.class,
				() -> SamlValidationUtil.validateRelayState(responseData));
	}

	@Test
	void validateMissingRelayStateWithResponse() {
		var response = OpenSamlUtil.buildSamlObject(Response.class);
		var responseData = ResponseData.of(response, "", null);
		assertThrows(RequestDeniedException.class,
				() -> SamlValidationUtil.validateRelayState(responseData));
	}

	@Test
	void validateRelayState() {
		SamlValidationUtil.validateRelayState(ResponseData.of(null, "valid", null));
	}

	@Test
	void validateMissingResponse() {
		var responseData = ResponseData.of(null, "relayState", null);
		assertThrows(RequestDeniedException.class,
				() -> SamlValidationUtil.validateResponse(responseData));
	}

	@Test
	void validateResponse() {
		var response = OpenSamlUtil.buildSamlObject(Response.class);
		SamlValidationUtil.validateResponse(ResponseData.of(response, null, null));
	}

	@Test
	void validateMissingRequestProfileId() {
		assertThrows(RequestDeniedException.class,
				() -> SamlValidationUtil.validateProfileRequestId(null));
	}

	@Test
	void validateEmptyRequestProfileId() {
		assertThrows(RequestDeniedException.class,
				() -> SamlValidationUtil.validateProfileRequestId(""));
	}

	@Test
	void validateProfileRequestId() {
		SamlValidationUtil.validateProfileRequestId("validId");
	}

}
