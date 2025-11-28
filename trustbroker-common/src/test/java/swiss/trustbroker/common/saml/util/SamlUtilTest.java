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

package swiss.trustbroker.common.saml.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class SamlUtilTest {

	@BeforeAll
	static void setup() {
		SamlTestBase.setup();
		TraceSupport.clearMdcTraceContext();
	}
	@BeforeAll
	static void cleanup() {
		TraceSupport.clearMdcTraceContext();
	}

	@Test
	void testSkiOidStringFromCert() {
		// openssl x509 -noout -in test-keystore.pem -ext subjectKeyIdentifier
		// X509v3 Subject Key Identifier:
		//     DB:16:2B:5A:7A:A6:17:3D:F6:D5:60:85:95:F4:8B:41:51:D7:A9:EA
		var certificate = (X509Certificate) CredentialReader.readPemCertificate(SamlTestBase.X509_RSAENC_PEM);
		assertThat(SamlUtil.getSkiOidString(certificate),
				equalTo("DB:16:2B:5A:7A:A6:17:3D:F6:D5:60:85:95:F4:8B:41:51:D7:A9:EA"));
	}

	@Test
	void createRelayState() {
		var relayState = SamlUtil.generateRelayState();
		assertThat(relayState, is(notNullValue()));
		assertThat(relayState, startsWith("S2-" + TraceSupport.getOwnTraceParent().replace(".", "-")));
		assertThat(relayState.length(), is(77));
	}

}