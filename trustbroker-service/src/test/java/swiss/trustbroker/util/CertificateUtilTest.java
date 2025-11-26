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

package swiss.trustbroker.util;


import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class CertificateUtilTest {

	@Test
	void getXtbSignerCredentials() {
		var properties = new TrustBrokerProperties();
		properties.setSigner(SamlTestBase.dummyKeystoreProperties());
		properties.setRolloverSigner(SamlTestBase.dummyKeystoreProperties());
		assertThat(CertificateUtil.getXtbSignerCredentials(properties), hasSize(2));
	}

	@Test
	void getXtbSignerCredentialsNoSigners() {
		var properties = new TrustBrokerProperties();
		assertThat(CertificateUtil.getXtbSignerCredentials(properties), hasSize(0));
	}

	@Test
	void getXtbSignerCredentialsInvalidRolloverSigner() {
		var properties = new TrustBrokerProperties();
		properties.setSigner(SamlTestBase.dummyKeystoreProperties());
		// invalid rollover signer ignored
		properties.setRolloverSigner(SamlTestBase.dummyKeystoreProperties());
		properties.getRolloverSigner().setPassword("invalid");
		assertThat(CertificateUtil.getXtbSignerCredentials(properties), hasSize(1));
	}

	@Test
	void getXtbSignerCredentialsInvalidSigner() {
		var properties = new TrustBrokerProperties();
		properties.setSigner(SamlTestBase.dummyKeystoreProperties());
		properties.getSigner().setPassword("invalid");
		assertThrows(TechnicalException.class, () -> CertificateUtil.getXtbSignerCredentials(properties));
	}
}
