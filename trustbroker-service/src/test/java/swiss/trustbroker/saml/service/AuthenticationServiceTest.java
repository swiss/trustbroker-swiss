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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class AuthenticationServiceTest {

	@BeforeAll
	static void init() {
		SamlTestBase.setup();
	}

	@Test
	void isSwitchToEnterprise() {
		var trustbrokerProperties = givenTrustbrokerProperties();
		var responseData = givenResponseData("anyStatus");

		var switchNoProperties = AuthenticationService.isSwitchToEnterprise(responseData, trustbrokerProperties);
		assertFalse(switchNoProperties);

		trustbrokerProperties.setHandleEnterpriseSwitch(true);
		var switchNoIdpId = AuthenticationService.isSwitchToEnterprise(responseData, trustbrokerProperties);
		assertFalse(switchNoIdpId);

		trustbrokerProperties.setHandleEnterpriseSwitch(false);
		trustbrokerProperties.setEnterpriseIdpId("urn:test:ENTERPRISE-LOGIN");
		var switchSetToFalse = AuthenticationService.isSwitchToEnterprise(responseData, trustbrokerProperties);
		assertFalse(switchSetToFalse);

		trustbrokerProperties.setHandleEnterpriseSwitch(true);
		var switchDifferentStatus = AuthenticationService.isSwitchToEnterprise(responseData, trustbrokerProperties);
		assertFalse(switchDifferentStatus);

		var switchTrue = AuthenticationService.isSwitchToEnterprise(
				givenResponseData("User requested context switch to Enterprise"), trustbrokerProperties);
		assertTrue(switchTrue);
	}

	private TrustBrokerProperties givenTrustbrokerProperties() {
		return new TrustBrokerProperties();
	}

	private ResponseData<?> givenResponseData(String statusMessage) {
		return ResponseData.builder()
				.response(givenResponse(statusMessage))
				.build();
	}

	private Response givenResponse(String statusMessage) {
		Response response = SamlFactory.createResponse(Response.class, "anyissuer");
		Status status = SamlFactory.createResponseStatus("Responder", statusMessage, "Responder");
		response.setStatus(status);
		return response;
	}

}
