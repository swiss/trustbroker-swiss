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
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.shared.codec.HTMLEncoder;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLArtifactContext;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = { swiss.trustbroker.common.saml.util.SamlTestConfiguration.class })
@ExtendWith(MockitoExtension.class)
class OpenSamlUtilTest {

	private static final String TEST_ORIG = """
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
							 xmlns:xs="http://www.w3.org/2001/XMLSchema"
							 Destination="https://test.trustbroker.swiss/api/v1/saml"
							 ID="Response_f8476123e6b0a3c29525524dbba916656b9b328b"
							 InResponseTo="id-d04bbb44-94e2-4a81-934a-e1890d811a70"
							 IssueInstant="2021-08-19T16:10:10.800Z"
							 Version="2.0"
							 >
				<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:MOCK</saml2:Issuer>
				<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
					<ds:SignedInfo>
						<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
						<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
						<ds:Reference URI="#Response_f8476123e6b0a3c29525524dbba916656b9b328b">
							<ds:Transforms>
								<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
								<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
									<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
															PrefixList="xs"
															/>
								</ds:Transform>
							</ds:Transforms>
							<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
							<ds:DigestValue>0123456789012345678901234567890123456789</ds:DigestValue>
						</ds:Reference>
					</ds:SignedInfo>
					<ds:SignatureValue/>
					<ds:SignatureValue />
					<ds:SignatureValue>0123456789</ds:SignatureValue>
					<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">0123456789</ds:SignatureValue>
					<ds:SignatureValue>01234567890</ds:SignatureValue>
					<ds:SignatureValue>012345678901234567890123456789012345678901234567890123456789</ds:SignatureValue>
					<ds:KeyInfo>
						<ds:X509Data>
			<ds:X509Certificate>0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789</ds:X509Certificate>
						</ds:X509Data>
					</ds:KeyInfo>
				</ds:Signature>
				<saml2p:Status>
					<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
				</saml2p:Status>
				<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
								 xmlns:xs="http://www.w3.org/2001/XMLSchema"
								 ID="Assertion_37316b5b1d2fd5c09cf98ba1deec8dea1b6e139a"
								 IssueInstant="2021-08-19T16:10:10.799Z"
								 Version="2.0"
								 >
					<saml2:Issuer>urn:test:MOCK</saml2:Issuer>
					<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						<ds:SignedInfo>
							<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
							<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
							<ds:Reference URI="#Assertion_37316b5b1d2fd5c09cf98ba1deec8dea1b6e139a">
								<ds:Transforms>
									<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
									<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
										<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
																PrefixList="xs"
																/>
									</ds:Transform>
								</ds:Transforms>
								<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
								<ds:DigestValue>0123456789012345678901234567890123456789</ds:DigestValue>
							</ds:Reference>
						</ds:SignedInfo>
						<ds:SignatureValue>012345678901234567890123456789012345678901234567890123456789</ds:SignatureValue>
						<ds:KeyInfo>
							<ds:X509Data>
								<ds:X509Certificate>0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789</ds:X509Certificate>
							</ds:X509Data>
						</ds:KeyInfo>
					</ds:Signature>
					<saml2:Subject>
						<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">98765</saml2:NameID>
						<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
							<saml2:SubjectConfirmationData InResponseTo="id-d04bbb44-94e2-4a81-934a-e1890d811a70"
														   NotOnOrAfter="2021-08-19T16:10:40.801Z"
														   />
						</saml2:SubjectConfirmation>
					</saml2:Subject>
					<saml2:Conditions NotBefore="2021-08-19T16:10:10.799Z"
									  NotOnOrAfter="2021-08-19T16:10:40.799Z"
									  >
						<saml2:AudienceRestriction>
							<saml2:Audience>http://test.trustbroker.swiss</saml2:Audience>
						</saml2:AudienceRestriction>
					</saml2:Conditions>
					<saml2:AuthnStatement AuthnInstant="2021-08-19T16:10:10.799Z">
						<saml2:AuthnContext>
							<saml2:AuthnContextClassRef>urn:qoa:names:classes:20</saml2:AuthnContextClassRef>
						</saml2:AuthnContext>
					</saml2:AuthnStatement>
					<saml2:AttributeStatement>
						<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier">
							<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
												  xsi:type="xs:string"
												  >uid=98765,ou=1234.test,o=XTB,c=CH</saml2:AttributeValue>
						</saml2:Attribute>
						<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
							<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
												  xsi:type="xs:string"
												  >98765</saml2:AttributeValue>
						</saml2:Attribute>
					</saml2:AttributeStatement>
				</saml2:Assertion>
			</saml2p:Response>
			""";

	private static final String TEST_SECURED = """
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
							 xmlns:xs="http://www.w3.org/2001/XMLSchema"
							 Destination="https://test.trustbroker.swiss/api/v1/saml"
							 ID="Response_f8476123e6b0a3c29525524dbba916656b9b328b"
							 InResponseTo="id-d04bbb44-94e2-4a81-934a-e1890d811a70"
							 IssueInstant="2021-08-19T16:10:10.800Z"
							 Version="2.0"
							 >
				<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:MOCK</saml2:Issuer>
				<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
					<ds:SignedInfo>
						<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
						<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
						<ds:Reference URI="#Response_f8476123e6b0a3c29525524dbba916656b9b328b">
							<ds:Transforms>
								<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
								<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
									<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
															PrefixList="xs"
															/>
								</ds:Transform>
							</ds:Transforms>
							<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
							<ds:DigestValue>0123456789**********</ds:DigestValue>
						</ds:Reference>
					</ds:SignedInfo>
					<ds:SignatureValue/>
					<ds:SignatureValue />
					<ds:SignatureValue>**********</ds:SignatureValue>
					<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">**********</ds:SignatureValue>
					<ds:SignatureValue>0123456789**********</ds:SignatureValue>
					<ds:SignatureValue>0123456789**********</ds:SignatureValue>
					<ds:KeyInfo>
						<ds:X509Data>
			<ds:X509Certificate>0123456789**********</ds:X509Certificate>
						</ds:X509Data>
					</ds:KeyInfo>
				</ds:Signature>
				<saml2p:Status>
					<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
				</saml2p:Status>
				<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
								 xmlns:xs="http://www.w3.org/2001/XMLSchema"
								 ID="Assertion_37316b5b1d2fd5c09cf98ba1deec8dea1b6e139a"
								 IssueInstant="2021-08-19T16:10:10.799Z"
								 Version="2.0"
								 >
					<saml2:Issuer>urn:test:MOCK</saml2:Issuer>
					<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						<ds:SignedInfo>
							<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
							<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
							<ds:Reference URI="#Assertion_37316b5b1d2fd5c09cf98ba1deec8dea1b6e139a">
								<ds:Transforms>
									<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
									<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
										<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
																PrefixList="xs"
																/>
									</ds:Transform>
								</ds:Transforms>
								<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
								<ds:DigestValue>0123456789**********</ds:DigestValue>
							</ds:Reference>
						</ds:SignedInfo>
						<ds:SignatureValue>0123456789**********</ds:SignatureValue>
						<ds:KeyInfo>
							<ds:X509Data>
								<ds:X509Certificate>0123456789**********</ds:X509Certificate>
							</ds:X509Data>
						</ds:KeyInfo>
					</ds:Signature>
					<saml2:Subject>
						<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">98765</saml2:NameID>
						<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
							<saml2:SubjectConfirmationData InResponseTo="id-d04bbb44-94e2-4a81-934a-e1890d811a70"
														   NotOnOrAfter="2021-08-19T16:10:40.801Z"
														   />
						</saml2:SubjectConfirmation>
					</saml2:Subject>
					<saml2:Conditions NotBefore="2021-08-19T16:10:10.799Z"
									  NotOnOrAfter="2021-08-19T16:10:40.799Z"
									  >
						<saml2:AudienceRestriction>
							<saml2:Audience>http://test.trustbroker.swiss</saml2:Audience>
						</saml2:AudienceRestriction>
					</saml2:Conditions>
					<saml2:AuthnStatement AuthnInstant="2021-08-19T16:10:10.799Z">
						<saml2:AuthnContext>
							<saml2:AuthnContextClassRef>urn:qoa:names:classes:20</saml2:AuthnContextClassRef>
						</saml2:AuthnContext>
					</saml2:AuthnStatement>
					<saml2:AttributeStatement>
						<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier">
							<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
												  xsi:type="xs:string"
												  >uid=98765,ou=1234.test,o=XTB,c=CH</saml2:AttributeValue>
						</saml2:Attribute>
						<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
							<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
												  xsi:type="xs:string"
												  >98765</saml2:AttributeValue>
						</saml2:Attribute>
					</saml2:AttributeStatement>
				</saml2:Assertion>
			</saml2p:Response>
			""";

	static final String AUTHN_ORIG = """
			<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
								 AssertionConsumerServiceURL="https://test.trustbroker.swiss/api/v1/saml"
								 Destination="https://test.trustbroker.swiss/api/v1/saml"
								 ForceAuthn="false"
								 ID="AuthnRequest_24542162e7a65118bd8cc4ba5a9e98e9d9a70640"
								 IssueInstant="2021-08-25T09:48:56.640Z"
								 Version="2.0"
								 >
				<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:SAMPLE</saml2:Issuer>
				<saml2:Conditions xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
								  NotBefore="2021-08-25T09:48:56.640Z"
								  NotOnOrAfter="2021-08-25T09:49:26.640Z"
								  />
				<saml2p:RequestedAuthnContext Comparison="exact">
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwareTimeSyncToken</saml2:AuthnContextClassRef>
					<saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract</saml2:AuthnContextClassRef>
				</saml2p:RequestedAuthnContext>
			</saml2p:AuthnRequest>
			""";

	private static final String TEST_ENTITY_DESCRIPTOR = """
			<EntityDescriptor
				xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
				entityID="loadbalancer-9.siroe.com">
				<SPSSODescriptor
					AuthnRequestsSigned="false"
					WantAssertionsSigned="false"
					protocolSupportEnumeration=
						"urn:oasis:names:tc:SAML:2.0:protocol">
					<KeyDescriptor use="signing">
						<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
							<X509Data>
			<ds:X509Certificate>0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789</ds:X509Certificate>
							</X509Data>
						</KeyInfo>
					</KeyDescriptor>
					<KeyDescriptor use="encryption">
						<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
							<X509Data>
			<ds:X509Certificate>0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789
			0123456789012345678901234567890123456789012345678901234567890123456789</ds:X509Certificate>
							</X509Data>
						</KeyInfo>
						<EncryptionMethod Algorithm=
							"https://www.w3.org/2001/04/xmlenc#aes128-cbc">
							<KeySize xmlns="https://www.w3.org/2001/04/xmlenc#">128</KeySize>
						</EncryptionMethod>
					</KeyDescriptor>
					<SingleLogoutService
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
						Location="https://LoadBalancer-9.siroe.com:3443/federation/
						SPSloRedirect/metaAlias/sp"
						ResponseLocation="https://LoadBalancer-9.siroe.com:3443/
						federation/SPSloRedirect/metaAlias/sp"/>
					<SingleLogoutService
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
						Location="https://LoadBalancer-9.siroe.com:3443/
						federation/SPSloSoap/metaAlias/sp"/>
				   <ManageNameIDService
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
						Location="https://LoadBalancer-9.siroe.com:3443/federation/
						SPMniRedirect/metaAlias/sp"
						ResponseLocation="https://LoadBalancer-9.siroe.com:3443/
						federation/SPMniRedirect/metaAlias/sp"/>
					<ManageNameIDService
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
						Location="https://LoadBalancer-9.siroe.com:3443/
						federation/SPMniSoap/metaAlias/sp"
						ResponseLocation="https://LoadBalancer-9.siroe.com:3443/
						federation/SPMniSoap/metaAlias/sp"/>
					<NameIDFormat>
						urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
					</NameIDFormat>
					<NameIDFormat>
						urn:oasis:names:tc:SAML:2.0:nameid-format:transient
					</NameIDFormat>
					<AssertionConsumerService
						isDefault="true"
						index="0"
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
						Location="https://LoadBalancer-9.siroe.com:3443/
						federation/Consumer/metaAlias/sp"/>
					<AssertionConsumerService
						index="1"
						Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
						Location="https://LoadBalancer-9.siroe.com:3443/
						federation/Consumer/metaAlias/sp"/>
				</SPSSODescriptor>
			</EntityDescriptor>
			""";

	private static final String TEST_RELAY_STATE = "myRelayState";

	private static final String TEST_DESTINATION = "https://localhost/myDestination";

	private static final String TEST_DESTINATION_ENCODED = "https&#x3a;&#x2f;&#x2f;localhost&#x2f;myDestination";

	private static final String TEST_ARP_URL = "https://localhost/saml/arp";

	@Autowired
	private VelocityEngine velocityEngine;

	@Mock
	private HttpClient httpClient;

	@Mock
	private HttpResponse httpResponse;

	@Mock
	private StatusLine statusLine;

	@Mock
	private HttpEntity httpEntity;

	@Bean
	public static VelocityEngine velocityEngine() {
		return OpenSamlUtil.createVelocityEngine(null);
	}

	@BeforeAll
	static void setup() {
		SamlTestBase.setup();
	}

	@Test
	void testReplaceSensitiveData() {
		String secured = OpenSamlUtil.replaceSensitiveData(TEST_ORIG);
		assertEquals(TEST_SECURED, secured);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"<parent><TestTag>abc</TestTag></parent>",
			"<parent><ns:TestTag>abc</ns:TestTag></parent>",
			"<parent><ns:TestTag  \t >abc</ns:TestTag></parent>",
			"<parent><TestTag/></parent>",
			"<parent><my:TestTag/></parent>",
			"<parent></TestTag></parent>",
			"<parent></any-ns:TestTag></parent>",
			"<parent><ns:TestTag xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>abc</parent>",
			"<parent><ns:TestTag  a-b:c_d=\"foo\" \rxyz  =\t\"bar\"   >",
	})
	void testGetXmlTagPattern(String xml) {
		var pattern = OpenSamlUtil.getXmlTagPattern("TestTag");
		assertTrue(pattern.matcher(xml).find());
	}

	@Test
	void testRelayStateForInjection() {
		var unsafeRelayState = "TestRelayState_\"' ,.-";
		var safeRelyState = HTMLEncoder.encodeForHTML(unsafeRelayState);
		assertEquals("TestRelayState_&quot;&#x27; ,.-", safeRelyState);
	}

	@Test
	void testExtractAuthnRequestContextClassesIfMissing() {
		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, "issuer");
		var result = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest);
		assertThat(result, is(empty()));
	}

	@Test
	void testExtractAuthnRequestContextClasses() {
		var inputClasses = List.of(SamlContextClass.NOMAD_TELEPHONY, SamlContextClass.KERBEROS,
				SamlContextClass.PASSWORD_PROTECTED_TRANSPORT,
				// not mapped -> removed:
				"urn:test:names:classes:StrongestPossible");
		var authnRequest = givenAuthnRequestWithContextClasses(inputClasses);
		var result = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest);
		assertThat(result, containsInAnyOrder(inputClasses.toArray()));
	}

	@Test
	void testExtractAuthnRequestContextClassesReplaceInbound() {
		var enforcedQoasClasses = List.of(SamlContextClass.TIME_SYNC_TOKEN, SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN);

		var inputClasses = List.of(SamlContextClass.NOMAD_TELEPHONY, SamlContextClass.KERBEROS,
				SamlContextClass.PASSWORD_PROTECTED_TRANSPORT,
				// not mapped -> removed:
				"urn:test:names:classes:StrongestPossible");

		var authnRequest = givenAuthnRequestWithContextClasses(inputClasses);
		var result = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest, false, Optional.of(enforcedQoasClasses));
		assertThat(result, containsInAnyOrder(inputClasses.toArray()));

		result = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest, true, Optional.of(enforcedQoasClasses));
		assertThat(result, containsInAnyOrder(enforcedQoasClasses.toArray()));
	}

	private static AuthnRequest givenAuthnRequestWithContextClasses(List<String> inputClasses) {
		var authnRequest = OpenSamlUtil.buildSamlObject(AuthnRequest.class);
		var reqAuthnContext = OpenSamlUtil.buildSamlObject(RequestedAuthnContext.class);
		authnRequest.setRequestedAuthnContext(reqAuthnContext);

		for (var name : inputClasses) {
			var contextClass = OpenSamlUtil.buildSamlObject(AuthnContextClassRef.class);
			contextClass.setURI(name);
			reqAuthnContext.getAuthnContextClassRefs().add(contextClass);
		}
		return authnRequest;
	}

	@Test
	void encodeSamlPostMessage() throws UnsupportedEncodingException {
		MessageContext context = buildMessageContext();
		MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
		OpenSamlUtil.encodeSamlPostMessage(httpServletResponse, context, velocityEngine, null);
		validateSamlMapping(httpServletResponse, SamlIoUtil.SAML_REQUEST_NAME);
	}

	@Test
	void encodeSamlRedirectMessage() {
		MessageContext context = buildMessageContext();
		MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
		OpenSamlUtil.encodeSamlRedirectMessage(httpServletResponse, context, null);
		assertThat(httpServletResponse.getStatus(), is(HttpServletResponse.SC_FOUND));
		var location = httpServletResponse.getHeader(HttpHeaders.LOCATION);
		assertThat(location, startsWith(TEST_DESTINATION + '?' + SamlIoUtil.SAML_REQUEST_NAME + '='));
		assertThat(location, endsWith('&' + SamlIoUtil.SAML_RELAY_STATE + '=' + TEST_RELAY_STATE));
	}

	@Test
	@SuppressWarnings("deprecation") // MessageContext.getSubcontext to be replaced
	void encodeSamLArtifactMessage() throws IOException {
		MessageContext context = buildMessageContext();
		var artifactContext = context.getSubcontext(SAMLArtifactContext.class, true);
		artifactContext.setSourceArtifactResolutionServiceEndpointIndex(0);
		artifactContext.setSourceArtifactResolutionServiceEndpointURL("https://localhost/artifacts");
		MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
		var artifactMap = OpenSamlUtil.createArtifactMap();
		OpenSamlUtil.encodeSamlArtifactMessage(httpServletResponse, context, velocityEngine, artifactMap);
		var samlObj = validateSamlMapping(httpServletResponse, SamlIoUtil.SAML_ARTIFACT_NAME);
		// artifact must be in the map for later reference:
		assertThat(artifactMap.get(samlObj), is(not(nullValue())));
	}

	// returns the value of the input field 'samlName'
	private String validateSamlMapping(MockHttpServletResponse httpServletResponse, String samlName) throws UnsupportedEncodingException {
		assertThat(httpServletResponse.getStatus(), is(HttpServletResponse.SC_OK));
		assertThat(httpServletResponse.getHeader(HttpHeaders.CONTENT_TYPE), startsWith(MediaType.TEXT_HTML_VALUE));
		var body = httpServletResponse.getContentAsString();
		// this is a rest, we can rely on the precise formatting
		assertThat(body, containsString("name=\"" + samlName + '"'));
		assertThat(body, containsString("name=\"" + SamlIoUtil.SAML_RELAY_STATE + '"'));
		assertThat(body, containsString("value=\"" + TEST_RELAY_STATE + '"'));
		assertThat(body, containsString("<form action=\"" + TEST_DESTINATION_ENCODED + '"'));
		// extract value of samlName field
		var pattern = "name=\"" + samlName + "\" value=\"([^\"]*)\"";
		var matcher = Pattern.compile(pattern, Pattern.MULTILINE).matcher(body);
		return matcher.find() ? matcher.group(1) : null;
	}

	private MessageContext buildMessageContext() {
		MessageContext context = new MessageContext();
		var authnRequest =
				SamlIoUtil.unmarshallAuthnRequest(new ByteArrayInputStream(AUTHN_ORIG.getBytes(StandardCharsets.UTF_8)));
		SAMLBindingSupport.setRelayState(context, TEST_RELAY_STATE);
		OpenSamlUtil.setEndpoint(context, TEST_DESTINATION);
		OpenSamlUtil.setIssuer(context, authnRequest.getIssuer().getValue());
		context.setMessage(authnRequest);
		return context;
	}

	@Test
	void isSamlArtifactRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setParameter(SamlIoUtil.SAML_ARTIFACT_NAME, "myArtifactId");
		assertThat(OpenSamlUtil.isSamlArtifactRequest(request), is (true));
		assertThat(OpenSamlUtil.isSamlRedirectRequest(request), is (false));
		assertThat(OpenSamlUtil.isSamlPostRequest(request), is (false));
	}

	@Test
	void isSamlPostRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setParameter(SamlIoUtil.SAML_REQUEST_NAME, "myRequest");
		assertThat(OpenSamlUtil.isSamlPostRequest(request), is (true));
		assertThat(OpenSamlUtil.isSamlRedirectRequest(request), is (false));
		assertThat(OpenSamlUtil.isSamlArtifactRequest(request), is (false));
	}

	@Test
	void isSamlRedirectRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setParameter(SamlIoUtil.SAML_REQUEST_NAME, "myRequest");
		assertThat(OpenSamlUtil.isSamlRedirectRequest(request), is (true));
		assertThat(OpenSamlUtil.isSamlArtifactRequest(request), is (false));
		assertThat(OpenSamlUtil.isSamlPostRequest(request), is (false));
	}

	@Test
	void isSamlRedirectResponse() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setParameter(SamlIoUtil.SAML_RESPONSE_NAME, "myResponse");
		assertThat(OpenSamlUtil.isSamlRedirectRequest(request), is (true));
		assertThat(OpenSamlUtil.isSamlArtifactRequest(request), is (false));
		assertThat(OpenSamlUtil.isSamlPostRequest(request), is (false));
	}

	@Test
	void extractSourceIdFromArtifactId() {
		var sourceId = OpenSamlUtil.calculateArtifactSourceIdFromIssuerId("selfIssuerId");
		assertThat(sourceId, is ("751fe121d6bb7ce905570ecf3b0517680a936d4a"));
		assertThat(OpenSamlUtil.extractSourceIdFromArtifactId("AAQAAHUf4SHWu3zpBVcOzzsFF2gKk21KuWvAcPkrMioRZTVelJpesIWszvg="),
				is(sourceId));
	}

	@Test
	void extractSourceIdFromMissingArtifactId() {
		assertThrows(TechnicalException.class, () -> OpenSamlUtil.extractSourceIdFromArtifactId(""));
	}

	@Test
	void extractSourceIdFromOtherTypeArtifactId() {
		assertThat(OpenSamlUtil.extractSourceIdFromArtifactId("b3RoZXJ0eXBlCg=="), is(""));
	}

	@Test
	void testStatus() {
		testNullStatus(null);
		var response = OpenSamlUtil.buildSamlObject(Response.class);
		testNullStatus(response);
		response.setStatus(OpenSamlUtil.buildSamlObject(Status.class));
		testNullStatus(response);
		response.getStatus().setStatusCode(OpenSamlUtil.buildSamlObject(StatusCode.class));
		response.getStatus().setStatusMessage(OpenSamlUtil.buildSamlObject(StatusMessage.class));
		testNullStatus(response);
		response.getStatus().getStatusCode().setStatusCode(OpenSamlUtil.buildSamlObject(StatusCode.class));
		testNullStatus(response);
		var code = "code1";
		response.getStatus().getStatusCode().setValue(code);
		var subCode = "subCode2";
		response.getStatus().getStatusCode().getStatusCode().setValue(subCode);
		var message = "Status message";
		response.getStatus().getStatusMessage().setValue(message);
		assertThat(OpenSamlUtil.getStatusCode(response), is(code));
		assertThat(OpenSamlUtil.getNestedStatusCode(response), is(subCode));
		assertThat(OpenSamlUtil.getStatusMessage(response), is(message));
	}

	private static void testNullStatus(Response response) {
		assertThat(OpenSamlUtil.getStatusCode(response), is(nullValue()));
		assertThat(OpenSamlUtil.getNestedStatusCode(response), is(nullValue()));
		assertThat(OpenSamlUtil.getStatusMessage(response), is(nullValue()));
	}

	@Test
	void checkAssertionsLimitationsNoAssertions() {
		List<Assertion> assertions = Collections.emptyList();
		List<EncryptedAssertion> encryptedAssertions = Collections.emptyList();
		assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkAssertionsLimitations(assertions, encryptedAssertions, "test"));	}

	@Test
	void checkAssertionsLimitationsSingleAssertion() {
		var assertion = OpenSamlUtil.buildAssertionObject(null);
		List<Assertion> assertions = List.of(assertion);
		assertDoesNotThrow(() -> OpenSamlUtil.checkAssertionsLimitations(assertions, Collections.emptyList(), "test"));
	}

	@Test
	void checkAssertionsLimitationsSingleEncryptedAssertion() {
		var encryptedAssertion = givenEncryptedAssertion(OpenSamlUtil.buildAssertionObject(null));
		List<EncryptedAssertion> encryptedAssertions = List.of(encryptedAssertion);
		assertDoesNotThrow(() -> OpenSamlUtil.checkAssertionsLimitations(Collections.emptyList(), encryptedAssertions, "test"));
	}

	@Test
	void checkAssertionsLimitationsOneOfEachAssertions() {
		var assertion = OpenSamlUtil.buildAssertionObject(null);
		List<Assertion> assertions = List.of(assertion);
		var encryptedAssertion = givenEncryptedAssertion(OpenSamlUtil.buildAssertionObject(null));
		List<EncryptedAssertion> encryptedAssertions = List.of(encryptedAssertion);
		assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkAssertionsLimitations(assertions, encryptedAssertions, "test"));
	}

	@Test
	void checkAssertionsLimitationsMultipleAssertions() {
		var assertion = OpenSamlUtil.buildAssertionObject(null);
		List<Assertion> assertions = List.of(assertion, assertion);
		List<EncryptedAssertion> encryptedAssertions = Collections.emptyList();
		assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkAssertionsLimitations(assertions, encryptedAssertions, "test"));
	}

	@Test
	void checkAssertionsLimitationsMultipleEncryptedAssertions() {
		List<Assertion> assertions = Collections.emptyList();
		var encryptedAssertion = givenEncryptedAssertion(OpenSamlUtil.buildAssertionObject(null));
		List<EncryptedAssertion> encryptedAssertions = List.of(encryptedAssertion, encryptedAssertion);
		assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkAssertionsLimitations(assertions, encryptedAssertions, "test"));
	}

	@Test
	void checkExtensionsOk() {
		var response = SamlFactory.createResponse(Response.class, "issuer");
		assertDoesNotThrow(() -> OpenSamlUtil.checkExtensions(response, "test"));
	}

	@Test
	void checkExtensionsPresent() {
		var response = SamlFactory.createResponse(Response.class, "alice");
		response.setExtensions(OpenSamlUtil.buildSamlObject(Extensions.class));
		assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkExtensions(response, "test"));
	}

	@Test
	void checkResponseLimitationsOk() {
		var response = SamlFactory.createResponse(Response.class, "issuer");
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject(null));
		assertDoesNotThrow(() -> OpenSamlUtil.checkResponseLimitations(response, "test"));
	}

	@Test
	void checkResponseLimitationsFailing() {
		var ex = assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkResponseLimitations(null, "test"));
		assertThat(ex.getInternalMessage(), containsString("Response context is missing"));
		var response = SamlFactory.createResponse(Response.class, "issuer");
		ex = assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkResponseLimitations(response, "test"));
		assertThat(ex.getInternalMessage(), containsString("No assertion"));
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject(null));
		response.setExtensions(OpenSamlUtil.buildSamlObject(Extensions.class));
		ex = assertThrows(RequestDeniedException.class,
				() -> OpenSamlUtil.checkResponseLimitations(response, "test"));
		assertThat(ex.getInternalMessage(), containsString("extension"));
	}

	private EncryptedAssertion givenEncryptedAssertion(Assertion assertion) {
		return EncryptionUtil.encryptAssertion(assertion, SamlTestBase.dummyCredential(),
				EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
				Encrypter.KeyPlacement.PEER,"urn:TEST", false);
	}

}
