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
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.mock.web.MockHttpServletResponse;

class SoapUtilTest {

	private static final String SOAP_REQUEST = """
			<?xml version="1.0" encoding="UTF-8"?>
			<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/">
			  <soap11:Body>
				<saml2p:ArtifactResolve xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
					Destination="http://localhost:7070/authn/arp" ID="_3f033b15974261f5f5a3f634daaf0b1a" 
					IssueInstant="2023-05-10T13:56:39.660Z" Version="2.0">
				  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:MOCK</saml2:Issuer>
				  <saml2p:Artifact>AAQAAJc1A9VaukDonUq0wWeDvJoVnFEuzbT/fK/T9M3bxQyDBNKHlujCoeE=</saml2p:Artifact>
				</saml2p:ArtifactResolve>
			  </soap11:Body>
			</soap11:Envelope>
			""";

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void extractSamlObjectFromEnvelope() {
		var in = new ByteArrayInputStream(SOAP_REQUEST.getBytes(StandardCharsets.UTF_8));
		var result = SoapUtil.extractSamlObjectFromEnvelope(in, ArtifactResolve.class);

		assertThat(result.getID(), is("_3f033b15974261f5f5a3f634daaf0b1a"));
	}

	@Test
	void sendSoap11ResponseAndExtractSamlObject() {
		var issuerId = "issuer1Id";
		var samlResponse = SamlFactory.createResponse(Response.class, issuerId);
		var response = new MockHttpServletResponse();
		SoapUtil.sendSoap11Response(response, samlResponse);

		var result = SoapUtil.extractSamlObjectFromEnvelope(new ByteArrayInputStream(response.getContentAsByteArray()),
				Response.class);
		assertThat(result.getIssuer().getValue(), is(issuerId));
	}
}
