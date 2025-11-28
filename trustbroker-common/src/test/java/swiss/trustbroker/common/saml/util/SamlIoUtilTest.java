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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class SamlIoUtilTest {

	private static final String AUTHN_REQ = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpBdXRoblJlcXVl"
			+ "c3QgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIC8+"
			+ "Cg==";

	@BeforeAll
	static void setup() {
		SamlTestBase.setup();
	}

	@Test
	void testDecodeSamlPostDataToString() throws IOException {
		var ret = SamlIoUtil.decodeSamlPostDataToString(AUTHN_REQ, false);
		assertThat(ret, is(not(nullValue())));
		assertThat(ret, is("<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest "
				+ "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>"));
	}

	@Test
	void testDecodeSamlPostData() throws IOException {
		var ret = SamlIoUtil.decodeSamlPostData(AUTHN_REQ);
		assertThat(ret, instanceOf(AuthnRequest.class));
	}

	@Test
	void buildSamlRedirectQueryString() {
		var sigAlg = "mySigAlg";
		var request = "mySamlRequest";
		var relayState = "myRelayState";
		var signature = "mySignature";
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, request, relayState, signature);
		assertThat(query, containsString(SamlIoUtil.SAML_REQUEST_NAME + '=' + request));
		assertThat(query, containsString(SamlIoUtil.SAML_RELAY_STATE + '=' + relayState));
		assertThat(query, containsString(SamlIoUtil.SAML_REDIRECT_SIGNATURE + '=' + signature));
		assertThat(query, containsString(SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM + '=' + sigAlg));
	}

	@Test
	void buildSamlRedirectQueryStringMinimal() {
		var response = "mySamlResponse";
		var query = SamlIoUtil.buildSamlRedirectQueryString(null, false, response, null, null);
		assertThat(query, containsString(SamlIoUtil.SAML_RESPONSE_NAME + '=' + response));
		assertThat(query, not(containsString(SamlIoUtil.SAML_RELAY_STATE)));
		assertThat(query, not(containsString(SamlIoUtil.SAML_REDIRECT_SIGNATURE)));
		assertThat(query, not(containsString(SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM)));
	}

	@Test
	void getXmlObjectFromString() {
		assertThat(SamlIoUtil.getXmlObjectFromString(Response.class, null, "Test"), is(nullValue()));
		var authnRequest = SamlIoUtil.getXmlObjectFromString(AuthnRequest.class, OpenSamlUtilTest.AUTHN_ORIG, "Test");
		assertThat(authnRequest.getID(), is("AuthnRequest_24542162e7a65118bd8cc4ba5a9e98e9d9a70640"));
	}

	@Test
	void marshalXmlObject() {
		assertThat(SamlIoUtil.marshalXmlObject(null), is(nullValue()));
		var issuer = "myIssuer";
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, issuer);
		var requestString = SamlIoUtil.marshalXmlObject(authnRequest);
		assertThat(requestString, is(not(nullValue())));
		var decoded = Base64.getDecoder().decode(requestString.getBytes(StandardCharsets.UTF_8));
		var authnRequestParsed = SamlIoUtil.unmarshallAuthnRequest(new ByteArrayInputStream(decoded));
		assertThat(authnRequestParsed.getID(), is(authnRequest.getID()));
		assertThat(authnRequestParsed.getIssuer().getValue(), is(issuer));
	}

	@Test
	void buildSignedSamlRedirectQueryString() {
		var relayState = "myRelayState";
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, "myIssuer");
		var credential = SamlTestBase.dummyCredential();
		var response = SamlIoUtil.buildSignedSamlRedirectQueryString(authnRequest, credential, null, relayState);
		var encodedData = SamlIoUtil.encodeSamlRedirectData(authnRequest);
		assertThat(response, startsWith(SamlIoUtil.SAML_REQUEST_NAME + '=' + WebUtil.urlEncodeValue(encodedData)));
		assertThat(response, containsString('&' + SamlIoUtil.SAML_RELAY_STATE + '=' + relayState));
		assertThat(response, containsString('&' + SamlIoUtil.SAML_REDIRECT_SIGNATURE + '='));
	}

}
