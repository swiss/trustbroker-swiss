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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;

@SpringBootTest(classes = PolicyDecider.class)
class PolicyDeciderTest {

	@Test
	void isSchemaValidationEnabledTest(){
		SecurityPolicies policies = new SecurityPolicies();

		SecurityChecks security = new SecurityChecks();
		security.setValidateXmlSchema(true);
		TrustBrokerProperties properties = new TrustBrokerProperties();
		properties.setSecurity(security);

		// Global property set
		assertTrue(PolicyDecider.isSchemaValidationEnabled(policies, properties));

		//RP side config
		security.setValidateXmlSchema(false);
		policies.setValidateXmlSchema(true);
		assertFalse(PolicyDecider.isSchemaValidationEnabled(policies, properties));

		security.setValidateXmlSchema(true);
		policies.setValidateXmlSchema(false);
		assertFalse(PolicyDecider.isSchemaValidationEnabled(policies, properties));

	}

}
