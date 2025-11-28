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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.SkinnySamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = ResponseFactory.class)
class ResponseFactoryTest extends SamlTestBase {

	private static final int SUBJECT_VALIDITY_SECONDS = 600;

	private static final int AUDIENCE_VALIDITY_SECONDS = 400;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private QoaMappingService qoaMappingService;

	@Autowired
	private ResponseFactory responseFactory;

	@BeforeAll
	@SuppressWarnings("java:S5786")
	public static void setup() {
		SamlTestBase.setup();
		new CoreAttributeInitializer().init();

		// createAssertion needs this:
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_NAME);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.AUTH_LEVEL);
	}

	@Test
	void isSignatureValidTrueTest() {
		Signature signature = dummySignableObject().getSignature();
		Credential credential = SamlTestBase.dummyCredential();
		List<Credential> credentials = List.of(credential);
		boolean signatureValid = SamlUtil.isSignatureValid(signature, credentials);
		assertTrue(signatureValid);
	}

	@Test
	void isSignatureValidFalseTest() {
		Signature signature = dummySignableObject().getSignature();
		Credential credential = SamlTestBase.dummyInvalidCredential().get(0);
		List<Credential> credentials = List.of(credential);
		boolean signatureValid = SamlUtil.isSignatureValid(signature, credentials);
		assertFalse(signatureValid);
	}

	@Test
	void isSignatureOkForSaml20() {
		var xmlObject = realSignableObject(givenStandardSignature(), null);
		var credentials = List.of(SamlTestBase.dummyCredential());
		assertTrue(SamlUtil.isSignatureValid(xmlObject.getSignature(), credentials));

		// The following breaks when the opensaml/xml-security/xerxes stack changes unexpectedly when doing library maintenance.
		// Might be that all is fine but SAML2 is notorious for bad implementations (like ADFS) so we make sure we know
		// something changed.
		var assertionString = SerializeSupport.nodeToString(xmlObject.getDOM());

		// cross-check re-internalized signatures
		assertDemarshalledAssertionValid(assertionString, credentials);
		assertDemarshalledAssertionManipulated(assertionString, credentials);
		assertDemarshalledAssertionDigestCovered(assertionString, credentials);

		// check namespace behavior and data
		assertThat(assertionString, containsString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
		assertThat(assertionString, containsString(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()));
		assertThat(assertionString, containsString(SAMLConstants.SAML20_NS));
		assertThat(assertionString, containsString("xmlns:" + SAMLConstants.SAML20_PREFIX));

		// no-ADFS patch expectations
		assertThat(assertionString, containsString(
				"<saml2:Issuer>"));
		assertThat(assertionString, containsString(
				"<saml2:Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\">"
						+ "<saml2:AttributeValue>myClaimsName"
						+ "</saml2:AttributeValue></saml2:Attribute>"));
		// verify that Assertion.SignedInfo does the XSString removal stuff
		assertThat(assertionString, not(containsString(
				"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"")));
		// the corresponding InclusiveNamespaces must be removed too
		assertThat(assertionString, not(containsString(
				"<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" "
						+ "PrefixList=\"xsd\"/></ds:Transform>")));
		// opensaml likes certs with newlines, ADFS may be not
		assertThat(assertionString, containsString(
				SamlTestBase.TEST_CB_CERT_LINE_1 + '\n' + SamlTestBase.TEST_CB_CERT_LINE_2));
		// correct KeyInfo belonging to DIGSIG schema
		assertThat(assertionString, containsString(
				"<ds:KeyInfo>"));
	}

	@Test
	void isSignatureOkForAdfs() {
		var xmlObject = realSignableObject(givenAdfsCompliantSignature(), SamlFactory.XML_SEC_DIGEST_METHOD_SHA1);
		var credentials = List.of(SamlTestBase.dummyCredential());
		assertTrue(SamlUtil.isSignatureValid(xmlObject.getSignature(), credentials));

		// The following breaks when the opensaml/xml-security/xerxes stack changes unexpectedly when doing library maintenance.
		// Might be that all is fine but SAML2 is notorious for bad implementations (like ADFS) so we make sure we know
		// something changed.
		var assertionString = SerializeSupport.nodeToString(xmlObject.getDOM());

		// cross check re-internalized signatures
		assertDemarshalledAssertionValid(assertionString, credentials);
		assertDemarshalledAssertionManipulated(assertionString, credentials);
		assertDemarshalledAssertionDigestCovered(assertionString, credentials);

		// check namespace behavior and data
		assertThat(assertionString, containsString(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()));
		assertThat(assertionString, containsString(SAMLConstants.SAML20_NS));
		assertThat(assertionString, not(containsString("xmlns:" + SAMLConstants.SAML20_PREFIX)));
		assertThat(assertionString, not(containsString("xmlns:" + "saml"))); // we go for null NS, not "saml"

		// patch expectations
		assertThat(assertionString, containsString(
				"<Issuer>"));
		assertThat(assertionString, containsString(
				"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"));
		assertThat(assertionString, containsString(
				"<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"));
		assertThat(assertionString, containsString(
				"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"));
		assertThat(assertionString, containsString(
				"<Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\">"
						+ "<AttributeValue>myClaimsName</AttributeValue></Attribute>"));
		// verify that Assertion.SignedInfo does the XSString stuff (compliant but not accepted by ADFS)
		assertThat(assertionString, not(containsString(
				"<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" "
						+ "PrefixList=\"xsd\"/></ds:Transform>")));
		assertThat(assertionString, not(containsString(
				"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"")));
		// ADFS likes certs as oneliner
		assertThat(assertionString, containsString(
				SamlTestBase.TEST_CB_CERT_LINE_1 + SamlTestBase.TEST_CB_CERT_LINE_2));
		// funny enough ADFS forgets the ds: and adds digsig namespace again
		assertThat(assertionString, containsString(
				"<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
	}

	@Test
	void responseWrappingIsAdfsCompliant() {
		var assertion = realSignableObject(givenAdfsCompliantSignature(), null);
		var credentials = List.of(SamlTestBase.dummyCredential());
		assertTrue(SamlUtil.isSignatureValid(assertion.getSignature(), credentials));

		// wrap ADFS version into response
		var response = SamlFactory.createResponse(Response.class, assertion.getIssuer().getValue());
		response.setInResponseTo("_idfromrp");
		response.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));
		response.getAssertions().add(assertion);
		SamlUtil.prepareSamlObject(response, SkinnySamlUtil.ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES, null,
				OpenSamlUtil.SKINNY_ALL);

		// patching
		var responseString = OpenSamlUtil.samlObjectToString(response);
		assertTrue(SkinnySamlUtil.isPatchedResponse(response));
		responseString = SkinnySamlUtil.discardXmlDocHeader(responseString);

		// check result
		assertThat(responseString, containsString(
				"<Issuer>")); // in the Assertion
		assertThat(responseString, containsString(
				"<Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">")); // in the response
		assertThat(responseString, containsString(
				"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
		assertThat(responseString, containsString(
				"samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"));
	}

	@Test
	void buildRedirectBindingSignature() {
		var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
		// the value does not matter
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, "dummy", "relay", null);
		assertDoesNotThrow(() -> {
			SamlUtil.buildRedirectBindingSignature(SamlTestBase.dummyCredential(), sigAlg, query.getBytes(StandardCharsets.UTF_8));
		});
	}

	@Test
	void validateSignature() {
		var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
		// the value does not matter
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, "dummy", "relay", null);
		var credential = SamlTestBase.dummyCredential();
		var signatureBytes = SamlUtil.buildRedirectBindingSignature(credential, sigAlg,
				query.getBytes(StandardCharsets.UTF_8));
		assertTrue(
				SamlUtil.validateSignature(credential, sigAlg, query.getBytes(StandardCharsets.UTF_8), signatureBytes)
		);
	}

	@ParameterizedTest
	@CsvSource(value = { SignatureConstants.XMLSIG_NS + "unknownalgo", "null" }, nullValues = "null")
	void validateSignatureInvalidAlgorithm(String sigAlg) {
		// the value does not matter
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, "dummy", "relay", null);
		var credential = SamlTestBase.dummyCredential();
		// build signature with a valid algorithm
		var queryBytes = query.getBytes(StandardCharsets.UTF_8);
		var signatureBytes = SamlUtil.buildRedirectBindingSignature(credential, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1,
				queryBytes);
		assertThrows(
				TechnicalException.class,
				() -> SamlUtil.validateSignature(credential, sigAlg, queryBytes, signatureBytes)
		);
	}

	@Test
	void isRedirectSignatureValid() {
		var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
		// the value does not matter
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, "dummy", "relay", null);
		var credential = SamlTestBase.dummyCredential();
		var signatureBytes = SamlUtil.buildRedirectBindingSignature(credential, sigAlg,
				query.getBytes(StandardCharsets.UTF_8));
		assertTrue(
				SamlUtil.isRedirectSignatureValid(List.of(credential), sigAlg, query, signatureBytes)
		);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			",false",
			" ,false",
			"42,false",
			"1f,false",
			"colon:ized,false",
			"name,true",
			"_1234,true",
			"-name,false",
			"_12-34.56_78,true",
			"XTB_8a823fec-1715-4fed-a4ea-ecadd50fa742,true",
			"48a115c0-4d84-4567-97ff-98804c171388,false"
	}, nullValues = "null")
	void isValidNcName(String value, boolean result) {
		assertThat(SamlUtil.isValidNcName(value), is(result));
	}

	@Test
	void prependPrefixToRelayStatePrefixed() {
		var prefixedId = SamlUtil.XTB_RELAY_STATE_PREFIX + "_myId";
		var result = SamlUtil.prependPrefixToRelayState(prefixedId);
		assertThat(result, is(prefixedId));
	}

	@Test
	void prependPrefixToRelayStateUnprefixed() {
		var plainId = "_otherId";
		var result = SamlUtil.prependPrefixToRelayState(plainId);
		assertThat(result, is(SamlUtil.XTB_RELAY_STATE_PREFIX + plainId));
	}

	@Test
	void prependPrefixToRelayStateTooLong() {
		var tooLong = "1".repeat(80);
		var result = SamlUtil.prependPrefixToRelayState(tooLong);
		assertThat(result, startsWith(SamlUtil.XTB_RELAY_STATE_PREFIX));
		assertThat(result.length(), is(80));
	}

	@Test
	void setOriginalIssuerIfMissing() {
		var origIssuer = "origIss";
		var attribute = SamlFactory.createAttribute("name1", "value1", null);
		SamlUtil.setOriginalIssuerIfMissing(attribute, origIssuer);
		assertThat(attribute.getUnknownAttributes().get(SamlUtil.ORIGINAL_ISSUER_QNAME), is(origIssuer));
		var otherIssuer = "otherIssuer";
		attribute = SamlFactory.createAttribute("name1", "value1", otherIssuer);
		SamlUtil.setOriginalIssuerIfMissing(attribute, origIssuer);
		assertThat(attribute.getUnknownAttributes().get(SamlUtil.ORIGINAL_ISSUER_QNAME), is(otherIssuer));
	}

	@Test
	void x509SerialToHex() {
		var bigint = new BigInteger("255" ,10);
		var hexString = Hex.encodeHexString(bigint.toByteArray(), false);
		assertThat(hexString, is("00FF"));
	}

	@Test
	void testValidity() {
		var before = Instant.now();
		var signableXmlObject = realSignableObject(null, null);
		var after = Instant.now();

		// check conditions
		var conditions = signableXmlObject.getConditions();
		assertThat(conditions, is(not(nullValue())));
		checkValidity(before, after, AUDIENCE_VALIDITY_SECONDS, conditions.getNotBefore(), conditions.getNotOnOrAfter(), true);

		// check subject
		assertThat(signableXmlObject.getSubject(), is(not(nullValue())));
		assertThat(signableXmlObject.getSubject().getSubjectConfirmations(), is(not(empty())));
		var subjectConfirmationData =
				signableXmlObject.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData();
		assertThat(subjectConfirmationData, is(not(nullValue())));
		checkValidity(before, after, SUBJECT_VALIDITY_SECONDS, subjectConfirmationData.getNotBefore(),
				subjectConfirmationData.getNotOnOrAfter(), false);
	}

	void checkValidity(Instant before, Instant after, int validitySeconds, Instant notBefore, Instant notOnOrAfter,
			boolean expectNotBefore) {
		// the instant used for calculation is between before and after
		if (expectNotBefore || notBefore != null) {
			assertThat(notBefore, is(not(nullValue())));
			assertTrue(before.isBefore(notBefore));
			assertTrue(after.isAfter(notBefore));
		}
		assertThat(notOnOrAfter, is(not(nullValue())));
		assertTrue(before.plusSeconds(validitySeconds).isBefore(notOnOrAfter));
		assertTrue(after.plusSeconds(validitySeconds).isAfter(notOnOrAfter));
	}

	// data

	private Signature givenStandardSignature() {
		Signature signature = OpenSamlUtil.buildSamlObject(Signature.class);
		signature.setSigningCredential(SamlTestBase.dummyCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSchemaLocation(SignatureConstants.XMLSIG_NS);
		signature.setKeyInfo(createMockKeyInfo(SamlTestBase.dummyCredential()));
		return signature;
	}

	// ADFS uses sha1 per default according to most FederationMetadata endpoints but actually support
	// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 as well
	private Signature givenAdfsCompliantSignature() {
		Signature signature = OpenSamlUtil.buildSamlObject(Signature.class);
		signature.setSigningCredential(SamlTestBase.dummyCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SkinnySamlUtil.ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES); // OMIT is default actually
		signature.setSchemaLocation(SignatureConstants.XMLSIG_NS);
		signature.setKeyInfo(createMockKeyInfo(SamlTestBase.dummyCredential()));
		return signature;
	}

	private SignableXMLObject dummySignableObject() {
		Assertion signableXmlObject = OpenSamlUtil.buildAssertionObject();

		Signature newSignature = givenStandardSignature();
		signableXmlObject.setSignature(newSignature);

		SamlUtil.signSamlObject(signableXmlObject, newSignature);

		return signableXmlObject;
	}

	private Assertion realSignableObject(Signature signature, String digestMethod) {
		// grown data API, sorry
		var cpResponse = CpResponse.builder().build();
		Map<Definition, List<String>> attrDefs = new HashMap<>();
		attrDefs.put(Definition.builder()
				.name(CoreAttributeName.CLAIMS_NAME.getName())
				.namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
				.value("myClaimsName")
				.build(), List.of("myClaimsName"));
		var responseParams = ResponseParameters.builder()
											   .issuerId("issuer1")
											   .federationServiceIssuerId("issuer2")
											   .rpClientName("clientName")
											   .subjectValiditySeconds(SUBJECT_VALIDITY_SECONDS)
											   .audienceValiditySeconds(AUDIENCE_VALIDITY_SECONDS)
											   .skinnyAssertionStyle(OpenSamlUtil.SKINNY_ALL)
											   .build();

		cpResponse.setAttributes(attrDefs);
		var signableXmlObject = ResponseFactory.createSamlAssertion(cpResponse, new ConstAttributes(),
				cpResponse.getContextClasses(), responseParams, null);

		if (signature == null) {
			return signableXmlObject;
		}

		// test not standard digest
		if (digestMethod != null) {
			SamlFactory.createSignatureReference(signableXmlObject, signature, digestMethod);
		}
		else {
			signableXmlObject.setSignature(signature);
		}

		// sign
		SamlUtil.signSamlObject(signableXmlObject, signature);

		return signableXmlObject;
	}

	private KeyInfo createMockKeyInfo(Credential credential) {
		EncryptionConfiguration secConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getDataKeyInfoGeneratorManager();
		if (namedKeyInfoGeneratorManager == null) {
			throw new TechnicalException("NamedKeyInfoGeneratorManager is null");
		}
		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
		if (keyInfoGeneratorFactory == null) {
			throw new TechnicalException("KeyInfoGeneratorFactory is null");
		}
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		KeyInfo keyInfo = null;
		try {
			keyInfo = keyInfoGenerator.generate(credential);
			return keyInfo;
		}
		catch (SecurityException e) {
			throw new TechnicalException(String.format("Key generation exception: %s", e.getMessage()));
		}
	}

	// asserts

	private void assertDemarshalledAssertionValid(String assertionString, List<Credential> credentials) {
		// check signature on internalized data
		var inputValid = new ByteArrayInputStream(assertionString.getBytes(StandardCharsets.UTF_8));
		var inputAssertionValid = (Assertion) SamlIoUtil.unmarshallAssertion(inputValid);
		assertTrue(SamlUtil.isSignatureValid(inputAssertionValid.getSignature(), credentials),
				"SAML: " + assertionString);
	}

	private void assertDemarshalledAssertionManipulated(String assertionString, List<Credential> credentials) {
		// make sure we fail when input was manipulated
		var manipulated = assertionString.replace(CoreAttributeName.CLAIMS_NAME.getNamespaceUri(),
				CoreAttributeName.CLAIMS_NAME.getNamespaceUri() + "X");
		var inputManipulated = new ByteArrayInputStream(manipulated.getBytes(StandardCharsets.UTF_8));
		var inputAssertionManipulated = (Assertion) SamlIoUtil.unmarshallAssertion(inputManipulated);
		assertFalse(SamlUtil.isSignatureValid(inputAssertionManipulated.getSignature(), credentials),
				"SAML: " + manipulated);
	}

	private void assertDemarshalledAssertionDigestCovered(String assertionString, List<Credential> credentials) {
		var digestTag = "</ds:DigestValue>";
		var digestEndTagIdx = assertionString.indexOf(digestTag);
		assertThat(digestEndTagIdx, greaterThan(0));
		var manipulated = assertionString.substring(0, digestEndTagIdx - 5)
				+ "QED" + assertionString.substring(digestEndTagIdx - 2, assertionString.length());
		assertThat(manipulated.length(), equalTo(assertionString.length()));
		assertThat(manipulated, containsString("QED"));
		var inputManipulated = new ByteArrayInputStream(manipulated.getBytes(StandardCharsets.UTF_8));
		var inputAssertionManipulated = (Assertion) SamlIoUtil.unmarshallAssertion(inputManipulated);
		// digest is part of sec check
		assertFalse(SamlUtil.isSignatureValid(inputAssertionManipulated.getSignature(), credentials),
				"SAML: " + manipulated);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null,true",
			"null,null,null,false",
			"null,customFederationServiceIssuerId1,null,false",
			"customIssuerId1,customFederationServiceIssuerId1,customRecipientId1,false",
			"customIssuerId2,null,customRecipientId2,false"
	}, nullValues = "null")
	void createAssertion(String customIssuerId, String customFederationServiceIssuerId, String customRecipientId,
			boolean delegateOrigin) {
		// RP request
		var rpIssuerId = "rp1";
		var recipientId = "https://localhost:1234/acs";
		var rpContextClasses = List.of(SamlContextClass.NOMAD_TELEPHONY);
		var spStateData = StateData.builder()
				.id("authnRequestId1")
				.issuer(rpIssuerId)
				.assertionConsumerServiceUrl(recipientId)
				.comparisonType(QoaComparison.EXACT)
				.contextClasses(rpContextClasses)
				.build();

		// CP response
		var cpIssuerId = "cp1";
		var nameId = "subjectName1@me";
		var nameIdFormat = NameIDType.EMAIL;
		var sessionIndex = "sessionIdx1";
		var stateData = StateData.builder()
								 .id("sessionId1")
								 .spStateData(spStateData)
								 .ssoSessionId(sessionIndex)
								 .build();
		var relyingParty = RelyingParty.builder().id(rpIssuerId).build();
		doReturn(relyingParty).when(relyingPartySetupService)
					.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, null);
		doReturn(new QoaConfig(null, rpIssuerId))
				.when(qoaMappingService).getQoaConfiguration(spStateData, relyingParty);

		// manipulated CP response
		Map<Definition, List<String>> cpAttributes = new LinkedHashMap<>();
		var homeName = Definition.builder()
								 .name(CoreAttributeName.HOME_NAME.getName())
								 .namespaceUri(CoreAttributeName.HOME_NAME.getNamespaceUri())
								 .build();
		var homeNameValue = "homeName1";
		cpAttributes.put(homeName, List.of(homeNameValue));
		var userExtId = Definition.builder()
								  .name(CoreAttributeName.CLAIMS_NAME.getName())
								  .namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
								  .build();
		cpAttributes.put(userExtId, List.of("idp12345"));
		var userProperty = Definition.builder()
									 .name("userProperty1")
									 .namespaceUri("http://trustbroker.swiss/claims/id/" +
											 SamlFactory.CLIENT_NAME_TAG + "/unitProperty1")
									 .build();
		cpAttributes.put(userProperty, List.of("userProp1"));
		Map<Definition, List<String>> userDetails = new LinkedHashMap<>();
		var email = Definition.builder()
							  .name(CoreAttributeName.EMAIL.getName())
							  .namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
							  .build();
		userDetails.put(email, List.of("user@trustbroker.swiss"));
		Map<Definition, List<String>> properties = new LinkedHashMap<>();
		userDetails.put(userExtId, List.of("idm98765"));
		var contextClass = SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN;
		var cpResponse = CpResponse.builder()
								   .issuer(cpIssuerId)
								   .customIssuer(customFederationServiceIssuerId) // OnResponse customization
								   .attributes(cpAttributes)
								   .nameId(nameId)
								   .nameIdFormat(nameIdFormat)
								   .originalNameId(nameId)
								   .contextClasses(List.of(contextClass))
								   .userDetails(userDetails)
								   .properties(properties)
								   .build();
		var authLevel = Definition.builder()
								  .name(CoreAttributeName.AUTH_LEVEL.getName())
								  .namespaceUri(CoreAttributeName.AUTH_LEVEL.getNamespaceUri())
								  .value("normal")
								  .build();

		// federation
		var rp = RelyingParty.builder()
							 .id(rpIssuerId)
							 .rpSigner(SamlTestBase.dummyCredential())
							 .constAttributes(ConstAttributes.builder()
															 .attributeDefinitions(List.of(authLevel))
															 .build())
							 .securityPolicies(
									 SecurityPolicies.builder()
													 .delegateOrigin(delegateOrigin)
													 .build()
							 )
							 .attributesSelection(
									 AttributesSelection.builder()
														.definitions(List.of(homeName, userProperty, userExtId))
														.build()
							 )
							 .build();
		var cp = ClaimsParty.builder()
							.id(cpIssuerId)
							.originalIssuer(cpIssuerId)
							.build();

		// originalIssuer injection
		var allOriginalIssuerAnnotated = new ArrayList<>(List.of(CoreAttributeName.AUTH_LEVEL.getNamespaceUri()));
		allOriginalIssuerAnnotated.addAll(
				cpResponse.getAttributes().keySet().stream().map(Definition::getNamespaceUri).toList());
		allOriginalIssuerAnnotated.addAll(
				cpResponse.getUserDetails().keySet().stream().map(Definition::getNamespaceUri).toList());

		// configuration
		var clientName = "clientName1";
		var federationServiceIssuerId = "federation.trustbroker.swiss"; // global setting
		doReturn(rp).when(relyingPartySetupService)
					.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, null);
		doReturn(new QoaConfig(null, rpIssuerId)).when(qoaMappingService)
												 .getQoaConfiguration(spStateData, rp);
		doReturn(cp).when(relyingPartySetupService)
					.getClaimsProviderSetupByIssuerId(cpIssuerId, null);
		doReturn(clientName).when(relyingPartySetupService).getRpClientName(rp);
		doReturn(SecurityChecks.builder()
							   .doSignAssertions(true)
							   .build()).when(trustBrokerProperties)
										.getSecurity();
		doReturn(federationServiceIssuerId).when(trustBrokerProperties)
							  .getIssuer();
		doReturn(List.of(contextClass)).when(qoaMappingService).mapResponseQoasToOutbound(
						any(), argThat(qc -> cpIssuerId.equals(qc.issuerId())),
						eq(QoaComparison.EXACT), eq(rpContextClasses),
						argThat(qc -> rpIssuerId.equals(qc.issuerId())));

		// create assertion based on above sources
		var dropDuplicates = List.of(CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		var homeNameOriginalIssuer = "urn:cpIssuer";
		var homeNameOriginalIssuerMapping = List.of(
				RegexNameValue.builder()
							  .regex("cp[0-9]+")
							  .value(homeNameOriginalIssuer)
							  .build());
		var responseParameters = ResponseParameters.builder()
												   .rpIssuerId(rpIssuerId)
												   .recipientId(customRecipientId)
												   .issuerId(customIssuerId)
												   .requireOriginalIssuerClaims(allOriginalIssuerAnnotated)
												   .homeNameIssuerMapping(homeNameOriginalIssuerMapping)
												   .build();

		cpResponse.setAttributes(ClaimsMapperService.deduplicatedCpAttributes(cpResponse, dropDuplicates, null));
		var assertion = responseFactory.createAssertion(stateData, cpResponse, responseParameters);

		// verify
		var expectedFederationServiceIssuer = customFederationServiceIssuerId != null
				? customFederationServiceIssuerId : federationServiceIssuerId;
		var expectedAudience = customIssuerId != null ? customIssuerId : rpIssuerId;
		var expetedRecipient = customRecipientId != null ? customRecipientId : recipientId;
		var expectedOriginalIssuer = delegateOrigin ? cpIssuerId : null;
		assertThat(assertion.isSigned(), is(true));
		assertThat(assertion.getID(), is(not(nullValue())));
		assertThat(assertion.getIssueInstant(), is(not(nullValue())));
		assertThat(assertion.getIssuer()
							.getValue(), is(expectedFederationServiceIssuer));
		assertThat(assertion.getVersion(), is(SAMLVersion.VERSION_20));
		validateSubject(assertion.getSubject(), nameId, nameIdFormat, spStateData.getId(), expetedRecipient);
		validateConditions(assertion.getConditions(), expectedAudience);
		validateAuthnStatements(assertion.getAuthnStatements(), sessionIndex, contextClass);
		List<Map.Entry<Definition, List<String>>> expectedAttributes = new ArrayList<>();
		cpAttributes.remove(userExtId); // userExtId from cpAttributes is expected to be removed by filter
		cpAttributes.entrySet()
					 .forEach(expectedAttributes::add);
		userDetails.entrySet()
				   .forEach(expectedAttributes::add);
		properties.entrySet()
				  .forEach(expectedAttributes::add);
		expectedAttributes.addAll(Map.of(authLevel, authLevel.getMultiValues())
									 .entrySet());
		validateAttributeStatements(assertion.getAttributeStatements(), expectedOriginalIssuer,
				homeNameOriginalIssuer, clientName, expectedAttributes);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"null,null,false",
			"name1,null,false",
			"null,format1,false",
			"name2,format2,true"
	}, nullValues = "null")
	void createNameId(String nameId, String nameIdFormat, boolean expectNameId) {
		var cpResponse = CpResponse.builder().nameId(nameId).nameIdFormat(nameIdFormat).build();
		var result = ResponseFactory.createNameId(cpResponse);

		if (expectNameId) {
			assertThat(result, is(not(nullValue())));
			assertThat(result.getValue(), is(nameId));
			assertThat(result.getFormat(), is(nameIdFormat));
		}
		else {
			assertThat(result, is(nullValue()));
		}
	}

	@Test
	void filterCpAttributesTest() {
		CpResponse cpResponse = givenCpResponseWithAttr();
		List<Definition> cpAttributeDefinitions = Collections.emptyList();
		var samlProperties = new SamlProperties();
		samlProperties.setDropAttrSelectionIfNoFilter(true);

		ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions, samlProperties);
		assertThat(cpResponse.getAttributes(), is(not(nullValue())));
		assertThat(cpResponse.getAttributes().size(), is(0));

		cpResponse = givenCpResponseWithAttr();
		cpAttributeDefinitions = List.of(Definition.ofNames(CoreAttributeName.EMAIL));
		ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions, samlProperties);
		assertThat(cpResponse.getAttributes(), is(not(nullValue())));
		assertThat(cpResponse.getAttributes().size(), is(1));

		cpResponse = givenCpResponseWithAttr();
		cpAttributeDefinitions = Collections.emptyList();
		samlProperties.setDropAttrSelectionIfNoFilter(false);
		ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions, samlProperties);
		assertThat(cpResponse.getAttributes(), is(not(nullValue())));
		assertThat(cpResponse.getAttributes().size(), is(2));
	}

	private static CpResponse givenCpResponseWithAttr() {
		Map<Definition, List<String>> map = new HashMap<>();
		map.put(Definition.ofNames(CoreAttributeName.EMAIL), List.of("email"));
		map.put(Definition.ofNames(CoreAttributeName.NAME), List.of("name"));
		return CpResponse.builder()
				.attributes(map)
				.build();
	}

	private static void validateSubject(Subject subject, String nameId, String nameIdFormat, String inResponseTo, String recipient) {
		assertThat(subject, is(not(nullValue())));
		assertThat(subject.getNameID().getValue(), is(nameId));
		assertThat(subject.getNameID().getFormat(), is(nameIdFormat));
		assertThat(subject.getSubjectConfirmations(), hasSize(1));
		var subjectConfirmation = subject.getSubjectConfirmations().get(0).getSubjectConfirmationData();
		assertThat(subjectConfirmation.getInResponseTo(), is(inResponseTo));
		assertThat(subjectConfirmation.getRecipient(), is(recipient));
		assertThat(subjectConfirmation.getNotOnOrAfter(), is(not(nullValue())));
	}

	private static void validateConditions(Conditions conditions, String audience) {
		assertThat(conditions, is(not(nullValue())));
		assertThat(conditions.getNotOnOrAfter(), is(not(nullValue())));
		assertThat(conditions.getNotBefore(), is(not(nullValue())));
		assertThat(conditions.getAudienceRestrictions(), hasSize(1));
		var audienceRestriction = conditions.getAudienceRestrictions().get(0);
		assertThat(audienceRestriction.getAudiences(), hasSize(1));
		assertThat(audienceRestriction.getAudiences().get(0).getURI(), is(audience));
	}

	private static void validateAuthnStatements(List<AuthnStatement> authnStatements, String sessionIndex, String contextClass) {
		assertThat(authnStatements, hasSize(1));
		var authnStatement = authnStatements.get(0);
		assertThat(authnStatement.getAuthnInstant(), is(not(nullValue())));
		assertThat(authnStatement.getSessionIndex(), is(not(nullValue())));
		assertThat(authnStatement.getAuthnContext(), is(not(nullValue())));
		var authnContextClassRef = authnStatement.getAuthnContext().getAuthnContextClassRef();
		assertThat(authnContextClassRef, is(not(nullValue())));
		assertThat(authnContextClassRef.getURI(), is(contextClass));
	}

	private static void validateAttributeStatements(List<AttributeStatement> attributeStatements,
			String originalIssuer, String homeNameOriginalIssuer, String clientName,
			List<Map.Entry<Definition, List<String>>> attributeList) {
		assertThat(attributeStatements, hasSize(1));
		var attributeStatement = attributeStatements.get(0);
		var attributes = attributeStatement.getAttributes();
		for (var attribute : attributes) {
			var expected = attributeList.stream()
					.filter(entry -> entry.getKey().getNamespaceUri().replaceAll(SamlFactory.CLIENT_NAME_TAG, clientName)
							.equals(attribute.getName()))
					.findFirst().orElse(null);
			assertThat(expected, is(not(nullValue())));
			if (CoreAttributeName.HOME_NAME.equalsByNameOrNamespace(attribute.getName())) {
				validateAttribute(attribute, homeNameOriginalIssuer, expected.getValue());
			}
			else {
				validateAttribute(attribute, originalIssuer, expected.getValue());
			}
			attributeList.remove(expected);
		}
		assertThat(attributeList, is(empty()));
	}

	private static void validateAttribute(Attribute attribute, String originalIssuer, List<String> values) {
		assertThat(SamlUtil.getOriginalIssuerFromAttribute(attribute), is(originalIssuer));
		assertThat(SamlUtil.getAttributeValues(attribute), containsInAnyOrder(values.toArray()));
	}

}
