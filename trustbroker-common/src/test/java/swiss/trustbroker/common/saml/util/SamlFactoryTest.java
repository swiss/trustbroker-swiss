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
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class SamlFactoryTest extends SamlTestBase {

	@BeforeAll
	@SuppressWarnings("java:S5786")
	public static void setup() {
		SamlTestBase.setup();
	}

	@Test
	void buildIssuerTest() {
		var issuer = SamlFactory.createIssuer("spEntity");
		assertNotNull(issuer.getValue());
	}

	@Test
	void buildNameIdPolicyTest() {
		var unspecified = NameIDType.UNSPECIFIED;
		var nameIdPolicy = SamlFactory.createNameIdPolicy(unspecified);
		assertEquals(unspecified, nameIdPolicy.getFormat());
		assertTrue(nameIdPolicy.getAllowCreate());
	}

	@Test
	void createKeyInfoCredentialNotSetTest() {
		var credential = mock(Credential.class);
		var ex = assertThrows(TechnicalException.class, () -> SamlFactory.createKeyInfo(credential));
		// NPE, newer Java versions provide more details in the message
		assertThat(ex.getInternalMessage(), startsWith("Failed to create KeyInfo with credential=null: "));
	}

	@Test
	void createKeyInfoTest() {
		var credential = dummyCredential();
		var keyInfo = SamlFactory.createKeyInfo(credential);
		assertNotNull(keyInfo);
	}

	@Test
	void createSignatureSha1DefaultTest() {
		var signature = SamlFactory.prepareSignableObject(
				dummyObject(), dummyCredential(), null, null, null);
		assertNotNull(signature.getSigningCredential());
		assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
		assertEquals(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, signature.getCanonicalizationAlgorithm());
		assertEquals("http://www.w3.org/2000/09/xmldsig#", signature.getSchemaLocation());
		assertDigestMethods(signature, SamlFactory.XML_SEC_DIGEST_METHOD_DEFAULT);
	}

	@Test
	void createSignatureSha1Test() {
		var signature = SamlFactory.prepareSignableObject(
				dummyObject(), dummyCredential(), SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, null,
				SamlFactory.XML_SEC_DIGEST_METHOD_SHA1);
		assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, signature.getSignatureAlgorithm());
		assertEquals(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, signature.getCanonicalizationAlgorithm());
		assertDigestMethods(signature, SamlFactory.XML_SEC_DIGEST_METHOD_SHA1);
	}

	@Test
	void createSignatureSha256Test() {
		var signature = SamlFactory.prepareSignableObject(
				dummyObject(), dummyCredential(), SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null, null);
		assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
		assertEquals(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, signature.getCanonicalizationAlgorithm());
		assertDigestMethods(signature, SamlFactory.XML_SEC_DIGEST_METHOD_DEFAULT);
	}

	@Test
	void createSignatureSha256C14nExplicitTest() {
		var signature = SamlFactory.prepareSignableObject(
				dummyObject(), dummyCredential(),
				SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
				SignatureConstants.ALGO_ID_C14N_EXCL_WITH_COMMENTS,
				null);
		assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
		assertEquals(SignatureConstants.ALGO_ID_C14N_EXCL_WITH_COMMENTS, signature.getCanonicalizationAlgorithm());
		assertDigestMethods(signature, SamlFactory.XML_SEC_DIGEST_METHOD_DEFAULT);
	}

	@Test
	void buildX509CertificateTest() {
		var credential = dummyCredential();
		var x509Data = SamlFactory.createX509Certificate(credential);
		assertNotNull(x509Data);
	}

	@Test
	void buildX509CertificateCredentialNullTest() {
		var x509Data = SamlFactory.createX509Certificate(null);
		assertNull(x509Data);
	}

	@Test
	void createAuthnStateTest() {
		var classRef = "classRef";
		var sessionIndex = "SESSION INDEX";
		var authnInstant = Instant.now();
		var sessionNotOnOrAfter = authnInstant.plusSeconds(180);
		var authnStates = SamlFactory.createAuthnStatements(List.of(classRef), sessionIndex, sessionNotOnOrAfter, authnInstant);
		var authnState = authnStates.get(0);
		assertNotNull(authnState.getAuthnInstant());
		assertNotNull(authnState.getSessionIndex());
		assertEquals(sessionIndex, authnState.getSessionIndex());
		assertEquals(sessionNotOnOrAfter, authnState.getSessionNotOnOrAfter());
		assertNotNull(authnState.getAuthnContext());
	}

	@Test
	void createAuthnContextTest() {
		var classRef = "classRef";
		var authnContext = SamlFactory.createAuthnContext(classRef);
		assertNotNull(authnContext.getAuthnContextClassRef());
	}

	@Test
	void createAuthnClassRefTest() {
		var classRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
		var authnClassRef = SamlFactory.createAuthnClassRef(classRef);
		assertNotNull(authnClassRef.getURI());
		assertEquals(classRef, authnClassRef.getURI());
	}

	@Test
	void createAttributeTest() {
		var value = "value";
		var type = "type";
		var attrOriginIssuer = "DEV";
		var attribute = SamlFactory.createAttribute(type, value, attrOriginIssuer);
		assertEquals(attribute.getName(), type);
		XSString attributeValue = (XSString) attribute.getAttributeValues().get(0);
		assertEquals(attributeValue.getValue(), value);
	}

	@Test
	void createAttributeValueNullTest() {
		var attributeValue = (XSString) SamlFactory.createAttributeValue((String) null);
		assertNull(attributeValue.getValue());
	}

	@Test
	void createAttributeValueTest() {
		var testAttribute = "test attribute";
		var attributeValue = (XSString) SamlFactory.createAttributeValue(testAttribute);
		assertEquals(testAttribute, attributeValue.getValue());
	}

	@Test
	void createSubjectConfirmationTest() {
		var authnRequest = "AuthnRequest_2649a84f022e60ebd301e2d13030342e1220f609";
		var recipient = "https://localhost:8321/SAML2.0/ServiceProvider/AssertionConsumer";
		var subjectConfirmation = SamlFactory.createSubjectConfirmation(authnRequest, recipient, 5, null);
		assertEquals(SubjectConfirmation.METHOD_BEARER, subjectConfirmation.getMethod());
		assertNotNull(subjectConfirmation.getSubjectConfirmationData());
	}

	@Test
	void createSubjectConfirmationDataTest() {
		var authnRequest = "AuthnRequest_2649a84f022e60ebd301e2d13030342e1220f609";
		var recipient = "https://localhost:8321/SAML2.0/ServiceProvider/AssertionConsumer";
		var subjectConfirmationData = SamlFactory.createSubjectConfirmationData(authnRequest, recipient, 5, null);
		assertNotNull(subjectConfirmationData.getInResponseTo());
		assertNotNull(subjectConfirmationData.getNotOnOrAfter());
		assertNotNull(subjectConfirmationData.getRecipient());
	}

	@Test
	void createNameIdSuccessTest() {
		var nameId = "eid\\5300\\32306";
		var nameID = SamlFactory.createNameId(nameId, NameIDType.UNSPECIFIED, null);
		assertNotNull(nameID.getFormat());
		assertEquals(NameIDType.UNSPECIFIED, nameID.getFormat());
		assertNotNull(nameID.getValue());
		assertEquals(nameId, nameID.getValue());
	}

	@Test
	void createAudienceSuccessTest() {
		var audience = SamlFactory.createAudience("audience");
		assertNotNull(audience);
		assertNotNull(audience.getURI());
	}

	@Test
	void createSubjectSuccessTest() {
		var validitySec = 600; // 10 minutes
		var authnRequest = "AuthnRequest_2649a84f022e60ebd301e2d13030342e1220f609";
		var recipient = "https://localhost:8321/SAML2.0/ServiceProvider/AssertionConsumer";
		var nameId = SamlFactory.createNameId("eid\\5300\\32306", NameIDType.UNSPECIFIED, null);
		var subject = SamlFactory.createSubject(nameId, authnRequest, recipient, validitySec, null);
		assertNotNull(subject.getNameID());
		assertEquals(1, subject.getSubjectConfirmations().size());
		var duration = Duration.between(Instant.now(),
				subject.getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter());
		assertThat(duration.getSeconds(), lessThanOrEqualTo((long)validitySec));
		assertThat(duration.getSeconds(), greaterThanOrEqualTo((long)validitySec-1));
	}

	@Test
	void createResponseStatusTest() {
		var statusCodeValue = "200";
		var responseStatus = SamlFactory.createResponseStatus(statusCodeValue);
		assertNotNull(responseStatus.getStatusCode());
		assertEquals(statusCodeValue, responseStatus.getStatusCode().getValue());
		assertNull(responseStatus.getStatusMessage());
	}

	@Test
	void createResponseStatusWithMessageTest() {
		var statusCodeValue = "403";
		var message = StatusCode.UNKNOWN_PRINCIPAL;
		var nestedStatus = StatusCode.NO_PASSIVE;
		var responseStatus = SamlFactory.createResponseStatus(statusCodeValue, message, nestedStatus);
		assertNotNull(responseStatus.getStatusCode());
		assertEquals(statusCodeValue, responseStatus.getStatusCode().getValue());
		assertNotNull(responseStatus.getStatusMessage());
		assertEquals(message, responseStatus.getStatusMessage().getValue());
		var nestedStatusCode = responseStatus.getStatusCode().getStatusCode();
		assertNotNull(nestedStatusCode);
		assertEquals(nestedStatus, nestedStatusCode.getValue());
	}

	private void assertDigestMethods(Signature signature, String expectedDigestMethod) {
		assertNotNull(signature.getContentReferences());
		assertEquals(1, signature.getContentReferences().size());
		assertEquals(expectedDigestMethod,
				((SAMLObjectContentReference)(signature.getContentReferences().get(0))).getDigestAlgorithm());
	}

	@Test
	void createLogoutRequest() {
		var issuerId = "issuer1";
		var destination = "https://localhost/logout";
		var qualifier = "qual";
		var nameId = SamlFactory.createNameId(issuerId, NameIDType.UNSPECIFIED, qualifier);

		var logoutRequest = SamlFactory.createLogoutRequest(issuerId, destination, nameId);

		assertThat(logoutRequest.getNameID(), is(not(nullValue())));
		assertThat(logoutRequest.getNameID().getValue(), is(issuerId));
		assertThat(logoutRequest.getNameID().getFormat(), is(NameIDType.UNSPECIFIED));
		assertThat(logoutRequest.getNameID().getSPNameQualifier(), is(qualifier));
		assertThat(logoutRequest.getDestination(), is(destination));
		assertThat(logoutRequest.getIssuer().getValue(), is(issuerId));
	}

	@Test
	void createRequestedAuthnContext() {
		var contextClasses = List.of("class1", "class2");
		var comparison = AuthnContextComparisonTypeEnumeration.MAXIMUM;
		var result = SamlFactory.createRequestedAuthnContext(contextClasses, comparison.name());
		assertThat(result.getComparison(), is(comparison));
		assertThat(result.getAuthnContextClassRefs()
				.stream()
				.map(AuthnContextClassRef::getURI)
				.toList(),
				is(contextClasses));
	}

	@Test
	void createRequestedAuthnContextEmpty() {
		var result = SamlFactory.createRequestedAuthnContext(null, null);
		assertThat(result.getComparison(), is(nullValue()));
		assertThat(result.getAuthnContextClassRefs(), hasSize(0));
	}

}
