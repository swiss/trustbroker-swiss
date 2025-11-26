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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.test.util.MemoryAppender;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class AssertionValidatorTest {

	private static final String TEST_AUDIENCE = "http://localhost:8080";

	private static final String TEST_ISSUER = "http://localhost:8080";

	private static final String TEST_RECIPIENT = "rp1";

	private static final String AC_URL = "https://localhost:8080/adfs/ls";

	private static final String ARTIFACT_RESOLUTION_SERVICE_URL = "https://localhost/arp";

	private static final String ARTIFACT_ID = "artifactId";

	private static final Optional<List<Credential>> NO_CREDENTIALS = Optional.empty();

	TrustBrokerProperties properties;

	private MemoryAppender memoryAppender;

	private void enableDebug(Class clazz, MemoryAppender memoryAppender) {
		Logger logger = (Logger) LoggerFactory.getLogger(clazz);
		logger.setLevel(Level.DEBUG);
		logger.addAppender(memoryAppender);
	}

	@BeforeEach
	void setup() {
		// catch log output of interest
		memoryAppender = new MemoryAppender();
		memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		enableDebug(AssertionValidator.class, memoryAppender);
		memoryAppender.start();

		SamlInitializer.initSamlSubSystem();
		properties = new TrustBrokerProperties();
		properties.setIssuer(TEST_ISSUER);
		properties.getSecurity().setRequireSignedAuthnRequest(true);
		properties.getSecurity().setNotBeforeToleranceSec(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC);
		properties.getSecurity().setNotOnOrAfterToleranceSec(SecurityChecks.TOLERANCE_NOT_AFTER_SEC);
		properties.setSaml(new SamlProperties());
		properties.getSaml().setConsumerUrl(AC_URL);
	}

	@Test
	void validateResponseStatusInvalidStatusTest() {
		var response = givenResponseInvalidStatus();
		assertThrows(RequestDeniedException.class, () -> AssertionValidator.validateResponseStatus(true, response));
	}

	@Test
	void validateResponseStatusTest() {
		var response = givenResponseValidStatus();
		assertDoesNotThrow(() -> AssertionValidator.validateResponseStatus(true, response));
	}

	@Test
	void validateResponseUnexpectedValidStatusTest() {
		var response = givenResponseValidStatus();
		assertThrows(RequestDeniedException.class, () -> AssertionValidator.validateResponseStatus(false, response));
	}

	@Test
	void validateResponseStatusExpectedInvalidStatusTest() {
		var response = givenResponseInvalidStatus();
		assertDoesNotThrow(() -> AssertionValidator.validateResponseStatus(false, response));
	}

	@Test
	void validateAssertionNoAssertionTest() {
		var response = givenSamlResponse();
		var assertions = List.of(givenAssertion());
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer("idpIssuer")
				.build();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseAssertions(assertions, response, null, properties, null, null,
					expectedValues);
		});
	}

	@Test
	void validateAssertionMoreAssertionsTest() {
		var response = givenSamlResponse();
		response.getAssertions().add(givenAssertion());
		response.getAssertions().add(givenAssertion());
		var assertions = List.of(givenAssertion());
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer("idpIssuer")
				.build();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseAssertions(assertions, response, null, properties, null, null,
					expectedValues);
		});
	}

	@Test
	void validateAssertionNoSubjectTest() {
		var response = givenSamlResponse();
		response.getAssertions().add(givenAssertion());
		var assertions = List.of(givenAssertion());
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer("idpIssuer")
				.build();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseAssertions(assertions, response, null, properties, null, null,
					expectedValues);
		});
	}

	@Test
	void validateAssertionNoNameIdTest() {
		var response = givenSamlResponse();
		response.getAssertions().add(givenAssertion());
		response.getAssertions().get(0).setSubject(givenSubject());
		var assertions = List.of(givenAssertion());
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer("idpIssuer")
				.build();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseAssertions(assertions, response, null, properties, null, null,
					expectedValues);
		});
	}

	@Test
	void validateSignatureNoSignedTest() {
		var response = givenResponseWithAssertion();
		var assertion = response.getAssertions().get(0);
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAssertionSignature(assertion, null, properties);
		});
	}

	@Test
	void validateRelayStateOldNullTest() {
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRelayState(null, "newRelayState", properties, null);
		});
	}

	@Test
	void validateRelayStateNewNullTest() {
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRelayState("oldRelayState", null, properties, null);
		});
	}

	//@Test
	void validateRelayStateDifferentTest() {
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRelayState("oldRelayState", "newRelayState", properties, null);
		});
	}

	@Test
	void validateRelayStateSameTest() {
		assertDoesNotThrow(() -> {
			AssertionValidator.validateRelayState("oldRelayState", "oldRelayState", properties, null);
		});
	}

	@Test
	void validateTimestampTooOldTest() {
		var now = Instant.now();
		var incoming = now.plusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 120);
		var response = givenSamlResponse();
		response.setIssueInstant(incoming); // 2 minutes past
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseIssueInstant(response, now, properties);
		});
	}

	@Test
	void validateTimestampTooEarlyTest() {
		var now = Instant.now();
		var incoming = now.plus(5, ChronoUnit.MINUTES);
		var response = givenSamlResponse();
		response.setIssueInstant(incoming); // 5 minutes before our time
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseIssueInstant(response, now, properties);
		});
	}

	@Test
	void validateTimestampValidTest() {
		var response = givenSamlResponse();
		response.setIssueInstant(Instant.now().plusSeconds(1)); // valid since 1 sec

		assertDoesNotThrow(() -> {
			AssertionValidator.validateResponseIssueInstant(response, Instant.now(), properties);
		});
	}

	@Test
	void validateSubjectConfirmationEmptyFailTest() {
		var expectedRequestId = "123";
		String actualRequestId = null;
		var assertion = givenAssertionWithSubjectConfirmation(actualRequestId);
		var now = Instant.now();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAssertionSubject(assertion, now, expectedRequestId, true, false, null, properties);
		});
	}

	@Test
	void validateSubjectConfirmationEmptyOkTest() {
		var expectedRequestId = "123";
		String actualRequestId = null;
		var assertion = givenAssertionWithSubjectConfirmation(actualRequestId);
		assertDoesNotThrow(() -> {
			AssertionValidator.validateAssertionSubject(assertion, Instant.now(), expectedRequestId, false, false,
					null, properties);
		});
	}

	@Test
	void validateSubjectConfirmationNotSameRequestIdTest() {
		var expectedRequestId = "123";
		var actualRequestId = "4343";
		var assertion = givenAssertionWithSubjectConfirmation(actualRequestId);
		var now = Instant.now();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAssertionSubject(assertion, now, expectedRequestId, true, false, null, properties);
		});
	}

	@Test
	void validateSubjectConfirmationNotSameRecipientTest() {
		var expectedRequestId = "123";
		var expectedRecipient = "rpOther";
		var assertion = givenAssertionWithSubjectConfirmation(expectedRequestId);
		var now = Instant.now();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAssertionSubject(assertion, now, expectedRequestId, true, false, expectedRecipient,
					properties);
		});
	}

	@Test
	void validateSubjectConfirmationSameTest() {
		var expectedRequestId = "123";
		var actualRequestId = expectedRequestId;
		var assertion = givenAssertionWithSubjectConfirmation(actualRequestId);
		var now = Instant.now();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateAssertionSubject(assertion, now, expectedRequestId, true, false, TEST_RECIPIENT, properties);
		});
	}

	@Test
	void validateAudienceEmptyTest() {
		String trustbrokerIssuer = null;
		var assertion = givenAssertionWithAudienceRestrictions(trustbrokerIssuer);
		var now = Instant.now();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateConditions(assertion.getConditions(), now, null, false, properties, null, assertion);
		});
	}

	@Test
	void validateAudienceNotSameTest() {
		var trustbrokerIssuer = "wrong-issuer";
		var assertion = givenAssertionWithAudienceRestrictions(trustbrokerIssuer);
		var conditions = assertion.getConditions();
		var now = Instant.now();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateConditions(conditions, now, null, false, properties, null, assertion);
		});
	}

	@Test
	void validateAudienceSameTest() {
		var trustbrokerIssuer = TEST_ISSUER;
		var assertion = givenAssertionWithAudienceRestrictions(trustbrokerIssuer);
		var now = Instant.now();
		var conditions = assertion.getConditions();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateConditions(conditions, now, null, false, properties, null, assertion);
		});
	}

	@Test
	void validateAudienceAclUrlTest() {
		var trustbrokerAcUrl = AC_URL;
		var assertion = givenAssertionWithAudienceRestrictions(trustbrokerAcUrl);
		var now = Instant.now();
		var conditions = assertion.getConditions();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateConditions(conditions, now, null, false, properties, null, assertion);
		});
	}

	@Test
	void validateAudienceOverrideNotSameTest() {
		var assertion = givenAssertionWithAudienceRestrictions("otherAudience");
		var now = Instant.now();
		var conditions = assertion.getConditions();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateConditions(conditions, now, "expectedAudience", false, properties, null, assertion);
		});
	}

	@Test
	void validateAudienceOverrideSameTest() {
		var audience = "audience1";
		var assertion = givenAssertionWithAudienceRestrictions(audience);
		var now = Instant.now();
		var conditions = assertion.getConditions();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateConditions(conditions, now, audience, false, properties, null, assertion);
		});
	}

	@ParameterizedTest
	@CsvSource(value = {
			// no audience restriction -> throw depends on flags
			"false,false,null,false",
			"false,false,false,false",
			"false,true,false,false",
			"false,true,null,true",
			"false,false,true,true",
			// audience restriction present -> always throw if not matched
			"true,false,false,true",
			"true,true,false,true",
			"true,false,true,true"
	}, nullValues = "null")
	void validateAudienceRestrictionsOk(boolean hasAudience, boolean propsRestriction, Boolean policyRestriction,
			boolean expectException) {
		List<AudienceRestriction> audienceRestrictions = hasAudience ?
				givenAssertionWithAudienceRestrictions("audience1").getConditions().getAudienceRestrictions() :
				Collections.emptyList();
		properties.getSecurity().setRequireAudienceRestriction(propsRestriction);
		var secPol = new SecurityPolicies();
		secPol.setRequireAudienceRestriction(policyRestriction);
		if (expectException) {
			assertThrows(RequestDeniedException.class, () -> {
				AssertionValidator.validateAudienceRestrictions(audienceRestrictions, "other", properties, secPol, null);
			});
		}
		else {
			assertDoesNotThrow(() -> {
				AssertionValidator.validateAudienceRestrictions(audienceRestrictions, "other", properties, secPol, null);
			});
		}
	}

	private List<AudienceRestriction> givenAudience(String trustbrokerIssuer) {
		var audienceRestriction = OpenSamlUtil.buildSamlObject(AudienceRestriction.class);
		audienceRestriction.getAudiences().add(createAudience(trustbrokerIssuer));
		return List.of(audienceRestriction);
	}

	private AuthnStatement givenAuthnStatement(Instant authnInstant) {
		var authnStatement = OpenSamlUtil.buildSamlObject(AuthnStatement.class);
		authnStatement.setAuthnInstant(authnInstant);
		return authnStatement;
	}

	@ParameterizedTest
	@CsvSource({
			"invalid,false", // broken
			"xtb://app/redirect,true", // custom scheme
			"http://http.host.port.check,true", // trailing / ignored when path is empty
			"http://http.host.port.check/,true", // path irrelevant on but trailing / is matched (best practice)
			"https://http.host.port.check/,false", // check protocol
			"http://http.host.port.check/,true", // check /* match trailing /
			"http://http.host.port.check/path,true", // check /* match on path /
			"http://http.host.port.check:80/,true", // ignore default port
			"http://http.host.port.check:1443/,false", // check non-default port
			"http://https.path.check:443/allowed/,false", // check the protocol again
			"https://https.path.check:443/allowed,false", // path not matched (trailing /)
			"https://https.path.check:443/allowed/,true", // path matched exactly and default port is checked
			"https://https.path.check:443/allowed/?query=any,true", // query ignored
			"https://https.path.check:443/invalid/,false", // path not matched
			"https://https.path.check:443/allowed/invalid/,false" // path not matched
	})
	void isUrlInAcWhiteListTest(String networkUrl, boolean expectedResult) {
		AcWhitelist acWhiteList = givenWhiteList();
		AuthnRequest authRequest = givenSignedAuthnRequest(); // just for logging
		try {
			AssertionValidator.isUrlInAcWhiteList(acWhiteList, authRequest, networkUrl);
			assertTrue(expectedResult, "URL " + networkUrl + " wrongly matches " + acWhiteList);
		}
		catch (RequestDeniedException ex) {
			assertFalse(expectedResult, "URL " + networkUrl + " wrongöy did not match " + acWhiteList
					+ " resulting in public exception '" + ex.getMessage()
					+ "' and internal exception '" + ex.getInternalMessage() + "'");
		}
	}

	private void samlRedirectContext(AuthnRequest authnRequest, SignatureContext signatureContext, boolean redirectSigned) {
		var encodedRequest = SamlIoUtil.encodeSamlRedirectData(authnRequest);
		var relayState = "myRelayState";
		var sigAlg = redirectSigned ? SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1 : null;
		String signature = null;
		if (redirectSigned) {
			signature = SamlIoUtil.buildEncodedSamlRedirectSignature(authnRequest, SamlTestBase.dummyCredential(),
					sigAlg, relayState, encodedRequest);
		}
		var query = SamlIoUtil.buildSamlRedirectQueryString(sigAlg, true, encodedRequest, relayState, signature);
		signatureContext.setRequestUrl("/?" + query);
		signatureContext.setBinding(SamlBinding.REDIRECT);
	}

	private SignatureContext contextFor(boolean requireSignature) {
		return SignatureContext.builder()
				.binding(SamlBinding.POST)
				.requireSignature(requireSignature)
				.build();
	}

	private SignatureContext signed() {
		return contextFor(true);
	}

	private SignatureContext unsigned() {
		return contextFor(false);
	}

	@Test
	void validateRequestSignatureNotSignedTest() {
		var authnRequest = givenUnsignedAuthnRequest();
		var signatureContext = signed();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRequestSignature(authnRequest, null, properties, signatureContext);
		});
	}

	@Test
	void validateRequestSignatureNotSignedRedirectTest() {
		var authnRequest = givenUnsignedAuthnRequest();
		var signatureContext = signed();
		samlRedirectContext(authnRequest, signatureContext, false);
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRequestSignature(authnRequest, null, properties, signatureContext);
		});
	}

	@Test
	void validateRequestSignatureNotSignedAllowedByRp() {
		var authnRequest = givenUnsignedAuthnRequest();
		AssertionValidator.validateRequestSignature(authnRequest, null, properties, unsigned());
	}

	@Test
	void validateRedirectRequestSignatureNotSignedAllowedByRp() {
		var authnRequest = givenUnsignedAuthnRequest();
		var signatureContext = unsigned();
		samlRedirectContext(authnRequest, signatureContext, false);
		AssertionValidator.validateRequestSignature(authnRequest, null, properties, signatureContext);
	}

	@Test
	void validateRequestSignatureNotSignedTestAllowedByProperties() {
		var authnRequest = givenUnsignedAuthnRequest();
		properties.getSecurity().setRequireSignedAuthnRequest(false);
		AssertionValidator.validateRequestSignature(authnRequest, null, properties, signed());
	}

	@Test
	void validateRequestSignatureNoTrustStore() {
		var authnRequest = givenSignedAuthnRequest();
		var signatureContext = signed();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRequestSignature(authnRequest, null, properties, signatureContext);
		});
	}

	@Test
	void validateRequestSignatureInvalid() {
		var authnRequest = givenSignedAuthnRequest();
		var credentials = SamlTestBase.dummyInvalidCredential();
		var signatureContext = signed();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRequestSignature(authnRequest, credentials, properties, signatureContext);
		});
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" }) // test with or without embedded certificate
	void validateRequestSignatureIncomplete(boolean emptyKeyInfo) {
		var authnRequest = givenIncompletelySignedAuthnRequest(emptyKeyInfo);
		var credentials = SamlTestBase.dummyInvalidCredential();
		var signatureContext = signed();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRequestSignature(authnRequest, credentials, properties, signatureContext);
		});
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" }) // test with or without embedded certificate
	void validateRequestIgnoreSignatureIncomplete(boolean emptyKeyInfo) {
		var authnRequest = givenIncompletelySignedAuthnRequest(emptyKeyInfo);
		var credentials = SamlTestBase.dummyInvalidCredential();
		var signatureContext = unsigned();
		assertFalse(AssertionValidator.validateRequestSignature(authnRequest, credentials, properties, signatureContext)
									  .isSignatureValidated());
	}

	@Test
	void validateResponseSignatureInvalidTest() {
		var authnRequest = givenSamlResponse();
		var credentials = SamlTestBase.dummyInvalidCredential();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateResponseSignature(authnRequest, credentials, true);
		});
	}

	@Test
	void validateRequestSignatureValidTest() {
		var authnRequest = givenSignedAuthnRequest();
		var claimTrustStore = givenClaimTrustStore();
		var signatureContext = signed();

		assertTrue(AssertionValidator.validateRequestSignature(authnRequest, claimTrustStore, properties, signatureContext)
									 .isSignatureValidated());
	}

	@Test
	void validateRequestSignatureValidRedirectTest() {
		// redirect is signed, SAML request not
		var authnRequest = givenUnsignedAuthnRequest();
		var claimTrustStore = givenClaimTrustStore();
		var signatureContext = signed();
		samlRedirectContext(authnRequest, signatureContext, true);

		assertTrue(AssertionValidator.validateRequestSignature(authnRequest, claimTrustStore, properties, signatureContext)
									 .isSignatureValidated());
	}

	@Test
	void validateRequestSignatureValidRedirectTestWithSignedSamlMessage() {
		// redirect is unsigned, SAML request is signed
		var authnRequest = givenSignedAuthnRequest();
		var claimTrustStore = givenClaimTrustStore();
		var signatureContext = signed();
		samlRedirectContext(authnRequest, signatureContext, false);

		assertTrue(AssertionValidator.validateRequestSignature(authnRequest, claimTrustStore, properties, signatureContext)
									 .isSignatureValidated());
	}

	@Test
	void validateRequestIdNullTest() {
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAuthnRequestId(null);
		});
	}

	@Test
	void validateRequestIdEmptyTest() {
		var authnRequest = givenSignedAuthnRequest();
		authnRequest.setID("");
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateAuthnRequestId(authnRequest);
		});
	}

	@Test
	void validateRequestIdValidTest() {
		var authnRequest = givenSignedAuthnRequest();
		assertDoesNotThrow(() -> {
			AssertionValidator.validateAuthnRequestId(authnRequest);
		});
	}

	@Test
	void validateAssertionWrongSignerTest() {
		var expectedRequestId = "req123";
		var assertion = givenSignedAssertionWithSubjectConfirmation(expectedRequestId);
		var now = Instant.now();
		var credentials = SamlTestBase.dummyInvalidCredential();
		var expectedAssertionId = assertion.getID();
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedRequestId(expectedRequestId)
				.expectedAssertionId(expectedAssertionId)
				.build();
		assertThrows(RequestDeniedException.class, () -> AssertionValidator.validateAssertion(assertion, now,
					credentials, properties, null, null,  expectedValues));
	}

	@Test
	void validateAssertionWrongSignerTestSignatureOptional() {
		properties.getSecurity().setRequireSignedAssertion(false);
		var expectedRequestId = "req123";
		var assertion = givenSignedAssertionWithSubjectConfirmation(expectedRequestId);
		var now = Instant.now();
		var credentials = SamlTestBase.dummyInvalidCredential();
		var expectedIssuer = assertion.getIssuer().getValue();
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedRequestId(expectedRequestId)
				.expectedIssuer(expectedIssuer)
				.build();
		assertFalse(AssertionValidator.validateAssertion(assertion, now, credentials, properties, null, null, expectedValues)
									  .isSignatureValidated());
	}

	@Test
	void validateRedirectBindingSignature() {
		var claimTrustStore = givenClaimTrustStore();
		var samlMessage = "mySamlMessage"; // content not relevant for signature validation
		var relayState = UUID.randomUUID().toString();
		var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
		var queryString = SamlIoUtil.buildSamlRedirectQueryString(sigAlg,
				true, samlMessage, relayState, null);
		var signature = SamlUtil.buildRedirectBindingSignature(claimTrustStore.get(0), sigAlg,
				queryString.getBytes(StandardCharsets.UTF_8));
		// path is not relevant:
		var url = "/adfs/ls?" + SamlIoUtil.buildSamlRedirectQueryString(sigAlg,
				true, samlMessage, relayState, Base64Util.encode(signature, Base64Util.Base64Encoding.UNCHUNKED));
		var signatureContext = SignatureContext.forRedirectBinding(url);

		assertDoesNotThrow(() -> {
			AssertionValidator.validateRedirectBindingSignature(signatureContext, claimTrustStore);
		});
	}

	@Test
	void validateTimestampBeforeRange() {
		var now = Instant.now();
		// one second before start of validity
		var incoming = now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC - 1);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		assertThrows(RequestDeniedException.class,
				() -> AssertionValidator.validateTimestampInRange("Test", incoming, now, -5L, 480L,	xmlobj));
	}

	@Test
	void validateTimestampStartOfRange() {
		var now = Instant.now();
		var incoming = now.minusSeconds(-SecurityChecks.TOLERANCE_NOT_BEFORE_SEC);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		assertDoesNotThrow(
				() -> AssertionValidator.validateTimestampInRange("Test", incoming, now, -5L, 480L,	xmlobj));
	}

	@Test
	void validateTimestampEndOfRange() {
		var now = Instant.now();
		var incoming = now.minusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		assertDoesNotThrow(
				() -> AssertionValidator.validateTimestampInRange("Test", incoming, now, -5L, 480L,	xmlobj));
	}

	@Test
	void validateTimestampAfterRange() {
		var now = Instant.now();
		// one millisecond after end of validity
		var incoming = now.minusSeconds(SecurityChecks.TOLERANCE_NOT_AFTER_SEC + 1);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		assertThrows(RequestDeniedException.class,
				() -> AssertionValidator.validateTimestampInRange("Test", incoming, now, -5L, 480L,	xmlobj));
	}

	@Test
	void validateIssueInstant() {
		var now = Instant.now();
		var tolerance = SecurityChecks.LIFETIME_TOKEN_SEC;
		// valid
		var incomingValid = now.minusSeconds(tolerance - 1);
		AssertionValidator.checkIssueInstantTimeRange(null, now, 0, tolerance, incomingValid);
		// gone
		var incomingExpired = now.minusSeconds(tolerance + 1);
		assertThrows(RequestDeniedException.class,
				() -> AssertionValidator.checkIssueInstantTimeRange(null, now, 0, tolerance, incomingExpired));
		// clock skew - tolerance is negative
		var incomingSkewedOk = now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC);
		AssertionValidator.checkIssueInstantTimeRange(null, now, SecurityChecks.TOLERANCE_NOT_BEFORE_SEC,
						tolerance, incomingSkewedOk);
		// tolerance is negative
		var incomingSkewedTooMuch = now.minusSeconds(SecurityChecks.TOLERANCE_NOT_BEFORE_SEC).plusSeconds(1);
		assertThrows(RequestDeniedException.class,
				() -> AssertionValidator.checkIssueInstantTimeRange(null, now, SecurityChecks.TOLERANCE_NOT_BEFORE_SEC,
						tolerance, incomingSkewedTooMuch));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"6,true", // 6 seconds in the future not accepted
			"5,false", // 5
			"-6,false" // past not checked in this test
	})
	void testTimestampValidNotBefore(long secondsBeforeNow, boolean expectException) {
		var now = Instant.now();
		var msgBefore = now.plusSeconds(secondsBeforeNow);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		try {
			AssertionValidator.validateNotBeforeAndNotAfter(
					"Test", msgBefore, null, now,
					SecurityChecks.TOLERANCE_NOT_BEFORE_SEC, SecurityChecks.TOLERANCE_NOT_AFTER_SEC,
					xmlobj);
			assertFalse(expectException, "Expect rejected timestamp with tolerance");
		}
		catch (RequestDeniedException ex) {
			assertTrue(expectException, "Expect valid timestamp with tolerance, got: " + ex.getInternalMessage());
		}
	}

	@ParameterizedTest
	@CsvSource(value = {
			"479,false", // valid for another 1 sec
			"480,true", // expired just now
			"481,true" // valid for 1 sec still
	})
	void testTimestampValidNotOnOrAfter(long secondsAfterNow, boolean expectException) {
		var now = Instant.now();
		var msgAfter = now.minusSeconds(secondsAfterNow);
		var xmlobj = OpenSamlUtil.buildSamlObject(Response.class);
		try {
			AssertionValidator.validateNotBeforeAndNotAfter(
					"Test", null, msgAfter, now,
					SecurityChecks.TOLERANCE_NOT_BEFORE_SEC,	SecurityChecks.TOLERANCE_NOT_AFTER_SEC,
					xmlobj);
			assertFalse(expectException, "Expect rejected timestamp with tolerance");
		}
		catch (RequestDeniedException ex) {
			assertTrue(expectException, "Expect valid timestamp with tolerance, got: " + ex.getInternalMessage());
		}
	}

	@Test
	void testDoubleSignature() {
		var truststore = givenClaimTrustStore();
		var assertion = givenAssertion();
		// response and assertion need to have differing IDs for the references
		assertion.setID(OpenSamlUtil.generateSecureRandomId());
		// AttributeStatement needed to produce Transforms:
		var attribute = SamlFactory.createAttribute("foo", "bar", "any");
		assertion.getAttributeStatements().add(SamlFactory.createAttributeStatement(List.of(attribute)));

		var response = givenResponseValidStatus();
		response.setID(OpenSamlUtil.generateSecureRandomId());
		response.getAssertions().add(assertion);

		SamlTestBase.signSamlObject(assertion);
		SamlTestBase.signSamlObject(response);

		// copy response for verification to avoid internal state issues:
		var responseStr = SamlIoUtil.xmlObjectToString(response, false);
		var responseCopy =
				SamlIoUtil.unmarshallResponse(new ByteArrayInputStream(responseStr.getBytes(StandardCharsets.UTF_8)));
		assertTrue(AssertionValidator.validateResponseSignature(responseCopy, truststore, true)
									 .isSignatureValidated());
		assertTrue(AssertionValidator.validateAssertionSignature(responseCopy.getAssertions().get(0), truststore, properties)
									 .isSignatureValidated());
	}

	@Test
	void validateArtifactResolve() {
		mockArtifactProperties(true);
		var artifact = SamlFactory.createArtifact(ARTIFACT_ID);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, TEST_ISSUER, ARTIFACT_RESOLUTION_SERVICE_URL);
		var credential = SamlTestBase.dummyCredential();
		var signatureParams = SignatureParameters.builder().credential(credential).build();
		SamlFactory.signSignableObject(artifactResolve, signatureParams);
		assertTrue(AssertionValidator.validateArtifactResolve(artifactResolve, properties, List.of(credential))
									 .isSignatureValidated());
	}

	@Test
	void validateArtifactResolveMissingSignaturePermitted() {
		mockArtifactProperties(false);
		var artifact = SamlFactory.createArtifact(ARTIFACT_ID);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, TEST_ISSUER, ARTIFACT_RESOLUTION_SERVICE_URL);
		assertFalse(AssertionValidator.validateArtifactResolve(artifactResolve, properties, Collections.emptyList())
									  .isSignatureValidated());
	}

	@Test
	void validateArtifactResolveMissingRequiredSignature() {
		mockArtifactProperties(true);
		var artifact = SamlFactory.createArtifact(ARTIFACT_ID);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, TEST_ISSUER, ARTIFACT_RESOLUTION_SERVICE_URL);
		List<Credential> trustCredentials = Collections.emptyList();
		assertThrows(RequestDeniedException.class, () ->
				AssertionValidator.validateArtifactResolve(artifactResolve, properties, trustCredentials));
	}

	@Test
	void validateArtifactResolveWrongDestination() {
		mockArtifactProperties(false);
		var artifact = SamlFactory.createArtifact(ARTIFACT_ID);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, TEST_ISSUER, "https://other.localdomain");
		List<Credential> trustCredentials = Collections.emptyList();
		assertThrows(RequestDeniedException.class, () ->
				AssertionValidator.validateArtifactResolve(artifactResolve, properties, trustCredentials));
	}

	@Test
	void validateArtifactResolveExpired() {
		mockArtifactProperties(false);
		var artifact = SamlFactory.createArtifact(ARTIFACT_ID);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, TEST_ISSUER, "https://other.localdomain");
		artifactResolve.setIssueInstant(Instant.EPOCH);
		List<Credential> trustCredentials = Collections.emptyList();
		assertThrows(RequestDeniedException.class, () ->
				AssertionValidator.validateArtifactResolve(artifactResolve, properties, trustCredentials));
	}

	@ParameterizedTest
	@MethodSource(value = "requireRestrictions")
	void requireAudienceRestriction(Boolean cpRequire, boolean propsRequire, boolean expectedRequire) {
		var secPol = SecurityPolicies.builder().requireAudienceRestriction(cpRequire).build();
		properties.getSecurity().setRequireAudienceRestriction(propsRequire);

		assertThat(AssertionValidator.requireAudienceRestriction(properties, secPol), is(expectedRequire));
		assertThat(AssertionValidator.requireAudienceRestriction(properties, null), is(propsRequire));
	}

	@ParameterizedTest
	@MethodSource(value = "requireRestrictions")
	void requireSignedResponse(Boolean cpRequire, boolean propsRequire, boolean expectedRequire) {
		var secPol = SecurityPolicies.builder().requireSignedResponse(cpRequire).build();
		properties.getSecurity().setRequireSignedResponse(propsRequire);

		assertThat(AssertionValidator.requireSignedResponse(properties, secPol), is(expectedRequire));
		assertThat(AssertionValidator.requireSignedResponse(properties, null), is(propsRequire));
	}

	static Boolean[][] requireRestrictions() {
		return new Boolean[][] {
				{ false, true, false },
				{ true, false, true },
				{ null, true, true }
		};
	}

	@Test
	void testWhiteList() throws URISyntaxException {
		ArrayList<String> urls = givenWhitelistUrls();
		var acWhitelist = AcWhitelist.builder().acUrls(urls).build();
		List<URI> acNetUrls = acWhitelist.getAcNetUrls();
		assertThat(acNetUrls, is(List.of(
				new URI("http://http.host.port.check/.*"), new URI("https://https.path.check/allowed/"),
				new URI("https://https.path.port.check:1111/allowed/"), new URI("xtb://app/redirect")
		)));
		List<String> origins = acWhitelist.getOrigins();
		assertThat(origins, is(List.of(
				"http://http.host.port.check", "https://https.path.check",
				"https://https.path.port.check:1111", "xtb://app"
		)));
		acWhitelist = AcWhitelist.builder().acUrls(urls).build();
		assertThat(acWhitelist.getAcNetUrls(), is(acNetUrls));
		assertThat(acWhitelist.getOrigins(), is(origins));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"0,0,true", // now
			"-5,0,true", // after OK
			"-6,0,false", // after NOK
			"3600,0,true", // before OK
			"3601,0,false", // before NOK
			"3600,3600,true", // before OK
			"3601,3600,false", // before NOK
			"7200,7200,true", // before OK due to SecurityPolicies
			"7201,7200,false" // before NOK despite SecurityPolicies
	})
	void testValidateAssertionAuthnStatements(int authnSecsBeforeNow, int notOnOrAfterSeconds, boolean ok) {
		var assertion = givenAssertion();
		var now = Instant.now();
		var statement = givenAuthnStatement(now.minusSeconds(authnSecsBeforeNow));
		assertion.getAuthnStatements().add(statement);
		var secPol = SecurityPolicies.builder().notOnOrAfterSeconds(notOnOrAfterSeconds).build();
		var claimsParty = new ClaimsParty();
		claimsParty.setSecurityPolicies(secPol);
		var rpQoaConf = new QoaConfig(null, "any");
		if (ok) {
			assertDoesNotThrow(() -> AssertionValidator.validateAssertionAuthnStatements(assertion, now, claimsParty,
					rpQoaConf, properties, null, QoaComparison.EXACT, false));
		}
		else {
			assertThrows(RequestDeniedException.class,
					() -> AssertionValidator.validateAssertionAuthnStatements(assertion, now, claimsParty,
							rpQoaConf, properties, null, QoaComparison.EXACT, false));
		}
	}

	@Test
	void validateRstAssertionNoAssertionTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(null, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
	}

	@Test
	void validateRstAssertionNoAssertionIdTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setID("");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("ID missing", ex);
	}

	@Test
	void validateRstAssertionNullAssertionIdTest() {
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setID(null);
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("ID missing", ex);
	}

	@Test
	void validateRstAssertionNullSubjectTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setSubject(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("Subject missing", ex);
	}

	@Test
	void validateRstAssertionNullNameIdTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion(null, TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("NameId missing", ex);
	}

	@Test
	void validateRstAssertionNoNameIdTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("NameId missing", ex);
	}

	@Test
	void validateRstAssertionEmptySubjectConfirmationsTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getSubject().getSubjectConfirmations().clear();
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("SubjectConfirmations missing", ex);
	}

	@Test
	void validateRstAssertionWrongMethodInSubjectConfirmationTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, "Invalid-Method");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("SubjectConfirmation.Method missing", ex);
	}

	@Test
	void validateRstAssertionNullIssuerTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setIssuer(null); // empty
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("Assertion.Issuer missing", ex);
	}

	@Test
	void validateRstAssertionEmptyIssuerTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getIssuer().setValue(""); // empty
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("Assertion.Issuer missing", ex);
	}

	@Test // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 24, Line 976
	void validateRstAssertionInvalidAudienceRestrictionTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", "Invalid-Audience", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("Audience missing or invalid", ex);
	}

	@Test // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 24, Line 976
	void validateRstAssertionValidAudienceRestrictionTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(true)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertFalse(AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS)
									  .isSignatureValidated());
	}

	@Test
	void validateRstAssertionInvalidAudiencesTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", "invalidAudience", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS);
		});
		assertException("Audience missing or invalid", ex);
	}

	@Test
	void validateRstAssertionEmptyAttributeStatementsTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getAttributeStatements().clear();
		assertFalse(AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS)
									  .isSignatureValidated());
		assertLog("AttributeStatements missing", Level.INFO);
	}

	@Test
	void validateRstAssertionValidTest() {
		var secPol = SecurityPolicies
				.builder()
				.requireAudienceRestriction(false)
				.build();
		Assertion assertion = givenRstAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertFalse(AssertionValidator.validateRstAssertion(assertion, properties, null, secPol, null, null, NO_CREDENTIALS)
									  .isSignatureValidated());
	}

	@ParameterizedTest
	@MethodSource
	void testValidateAssertionAuthnStatementsTest(List<String> requestCtxClasses, QoaConfig config, boolean enforceQoaIfMissing, boolean isException) {
		Map<String, Integer> map = new HashMap<>();
		map.put(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, 10);
		map.put(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, 20);

		if (isException) {
			var ex = assertThrows(RequestDeniedException.class, () -> {
				AssertionValidator.validateAuthnContextClassRefs(config, requestCtxClasses, AuthnContextComparisonTypeEnumeration.EXACT, map, enforceQoaIfMissing);
			});
			assertException("Missing request context class from request or SetupRp configuration with ID=Issuer", ex);
		} else {

			assertDoesNotThrow(() -> {
				AssertionValidator.validateAuthnContextClassRefs(config, requestCtxClasses, AuthnContextComparisonTypeEnumeration.EXACT, map, enforceQoaIfMissing);
			});
		}
	}

	static Object[][] testValidateAssertionAuthnStatementsTest() {
		return new Object[][] {
				{ Collections.emptyList(), new QoaConfig(null, "Issuer"), false, false },
				{ Collections.emptyList(), new QoaConfig(null, "Issuer"), true, true },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().build(), "Issuer"), false, false },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().build(), "Issuer"), true, true },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().enforce(true).build(), "Issuer"), true, true },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().enforce(true).build(), "Issuer"), false, true },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().enforce(false).build(), "Issuer"), true, false },
				{ Collections.emptyList(), new QoaConfig(Qoa.builder().enforce(false).classes(List.of(AcClass.builder().build())).build(), "Issuer"), true, false },
				{ List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED), new QoaConfig(Qoa.builder().enforce(false).build(), "Issuer"), true, false },
		};
	}

	private void mockArtifactProperties(boolean requireSignedArtifactResolve) {
		var saml = new SamlProperties();
		properties.setSaml(saml);
		var ar = new ArtifactResolution();
		saml.setArtifactResolution(ar);
		ar.setServiceUrl(ARTIFACT_RESOLUTION_SERVICE_URL);
		properties.getSecurity().setRequireSignedArtifactResolve(requireSignedArtifactResolve);
	}

	private List<Credential> givenClaimTrustStore() {
		return List.of(SamlTestBase.dummyCredential());
	}

	private AuthnRequest givenSignedAuthnRequest() {
		var authnRequest = givenUnsignedAuthnRequest();

		SamlTestBase.signSamlObject(authnRequest);

		return authnRequest;
	}

	private AuthnRequest givenUnsignedAuthnRequest() {
		var authnRequest = OpenSamlUtil.buildSamlObject(AuthnRequest.class);
		authnRequest.setID("ID test");
		authnRequest.setIssuer(dummyIssuer());
		authnRequest.setDestination("ssoURL");
		authnRequest.setAssertionConsumerServiceURL("assertionConsumerServiceURL");
		authnRequest.setID("id");
		return authnRequest;
	}

	private AuthnRequest givenIncompletelySignedAuthnRequest(boolean emptyKeyInfo) {
		var authnRequest = givenUnsignedAuthnRequest();
		var signature = SamlTestBase.givenSignature(emptyKeyInfo);
		// signature present, but not signed - DOM needs to be prepared so the request is considered signed:
		authnRequest.setSignature(signature);
		SamlUtil.prepareSamlObject(authnRequest, signature.getCanonicalizationAlgorithm(), signature, OpenSamlUtil.SKINNY_ALL);
		return authnRequest;
	}

	private Issuer dummyIssuer() {
		var issuer = OpenSamlUtil.buildSamlObject(Issuer.class);
		issuer.setValue("spEntity");
		return issuer;
	}

	static Audience createAudience(String aud) {
		var audience = OpenSamlUtil.buildSamlObject(Audience.class);
		audience.setURI(aud);
		return audience;
	}

	private List<SubjectConfirmation> givenSubjectConfirmation(String requestId) {
		var subjectConfirmation = OpenSamlUtil.buildSamlObject(SubjectConfirmation.class);
		subjectConfirmation.setSubjectConfirmationData(givenSubjectConfirmationData(requestId));
		return List.of(subjectConfirmation);
	}

	private SubjectConfirmationData givenSubjectConfirmationData(String requestId) {
		var subjectConfirmationData = OpenSamlUtil.buildSamlObject(SubjectConfirmationData.class);
		subjectConfirmationData.setInResponseTo(requestId);
		subjectConfirmationData.setNotOnOrAfter(Instant.now().plusSeconds(58));
		subjectConfirmationData.setRecipient(TEST_RECIPIENT);
		return subjectConfirmationData;
	}

	private AcWhitelist givenWhiteList() {
		ArrayList<String> urls = givenWhitelistUrls();
		return AcWhitelist.builder().acUrls(urls).build();
	}

	private static ArrayList<String> givenWhitelistUrls() {
		var urls = new ArrayList<String>();
		urls.add("ignore-broken"); // resilience on accepting broken ACL entries
		urls.add("https://"); // resilience on accepting broken ACL entries
		urls.add("http://http.host.port.check/.*"); // new regexp feature
		urls.add("https://https.path.check/allowed/"); // existing exact match feature
		urls.add("https://https.path.port.check:1111/allowed/"); // including port
		urls.add("xtb://app/redirect"); // custom scheme
		return urls;
	}

	private Subject givenSubject() {
		var subject = OpenSamlUtil.buildSamlObject(Subject.class);
		subject.setNameID(OpenSamlUtil.buildSamlObject(NameID.class));
		subject.getNameID().setValue("Some-Name-ID");
		return subject;
	}

	private Assertion givenAssertion() {
		return OpenSamlUtil.buildAssertionObject();
	}

	private Assertion givenAssertionWithSubjectConfirmation(String actualRequestId) {
		var assertion = givenAssertion();
		assertion.setSubject(givenSubject());
		if (actualRequestId != null) {
			assertion.getSubject().getSubjectConfirmations().addAll(givenSubjectConfirmation(actualRequestId));
		}
		return assertion;
	}

	private Assertion givenAssertionWithAudienceRestrictions(String actualIssuer) {
		var assertion = givenAssertion();
		assertion.setConditions(OpenSamlUtil.buildSamlObject(Conditions.class));
		if (actualIssuer != null) {
			assertion.getConditions().getAudienceRestrictions().addAll(givenAudience(actualIssuer));
		}
		return assertion;
	}

	private Assertion givenSignedAssertionWithSubjectConfirmation(String actualRequestId) {
		var assertion = givenAssertionWithSubjectConfirmation(actualRequestId);
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(Instant.now());
		var issuer = OpenSamlUtil.buildSamlObject(Issuer.class);
		issuer.setValue("myIssuer");
		assertion.setIssuer(issuer);
		SamlTestBase.signSamlObject(assertion);
		return assertion;
	}

	private Response givenResponseWithAssertion() {
		var resp = OpenSamlUtil.buildSamlObject(Response.class);
		var assertion = givenAssertion();
		resp.getAssertions().add(assertion);
		return resp;
	}

	private Response givenSamlResponse() {
		var resp = OpenSamlUtil.buildSamlObject(Response.class);
		var issuer = OpenSamlUtil.buildSamlObject(Issuer.class);
		issuer.setValue("test");
		resp.setIssueInstant(Instant.now());
		resp.setIssuer(issuer);
		return resp;
	}

	private Response givenResponseInvalidStatus() {
		var resp = OpenSamlUtil.buildSamlObject(Response.class);
		var status = OpenSamlUtil.buildSamlObject(Status.class);
		var statusCode = OpenSamlUtil.buildSamlObject(StatusCode.class);
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
		status.setStatusCode(statusCode);
		resp.setStatus(status);
		return resp;
	}

	private Response givenResponseValidStatus() {
		var resp = OpenSamlUtil.buildSamlObject(Response.class);
		var status = OpenSamlUtil.buildSamlObject(Status.class);
		var statusCode = OpenSamlUtil.buildSamlObject(StatusCode.class);
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
		status.setStatusCode(statusCode);
		resp.setStatus(status);
		return resp;
	}

	private Assertion givenRstAssertion(String nameId, String audience, String subjectConfirmation) {
		Assertion assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		// ID
		assertion.setID(UUID.randomUUID().toString());
		// issuer
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue(TEST_AUDIENCE);
		// subject
		assertion.setSubject(givenRstSubjectNameIdAndConfirmations(givenRstSubject(), givenRstNameId(nameId),
				givenRstSubjectConfirmations(), givenRstSubjectConfirmation(subjectConfirmation)));
		// audience
		assertion.setConditions(givenRstAudienceOfConditions(givenRstConditions(),
				givenRstAudienceRestrictions(), givenRstAudiences(audience)));
		// attributes
		assertion.getAttributeStatements().addAll(giveRstAttributeStatements());
		return assertion;
	}

	private void assertException(String expectedString, Exception ex) {
		assertTrue(((RequestDeniedException)ex).getInternalMessage().contains(expectedString),
				"'" + expectedString + "' not found in: " + ex.getMessage());
	}

	private Subject givenRstSubjectNameIdAndConfirmations(Subject subject, NameID nameID,
			List<SubjectConfirmation> subjectConfirmations, SubjectConfirmation subjectConfirmation) {
		if (subject == null) {
			return subject;
		}
		subject.setNameID(nameID);
		if (subjectConfirmations == null) {
			return subject;
		}
		subjectConfirmations.add(subjectConfirmation);
		subject.getSubjectConfirmations().addAll(subjectConfirmations);
		return subject;
	}

	private Subject givenRstSubject() {
		return OpenSamlUtil.buildSamlObject(Subject.class);
	}

	private Conditions givenRstAudienceOfConditions(Conditions conditions, List<AudienceRestriction> audienceRestrictions,
			List<Audience> audiences) {
		if (audienceRestrictions == null) {
			return conditions;
		}

		conditions.getAudienceRestrictions().addAll(audienceRestrictions);
		if (audiences != null) {
			conditions.getAudienceRestrictions().add(givenRstAudienceRestWithAudience(audiences));
		}

		return conditions;
	}

	private List<SubjectConfirmation> givenRstSubjectConfirmations() {
		return new ArrayList<>();
	}

	private NameID givenRstNameId(String nameIdValue) {
		NameID nameID = OpenSamlUtil.buildSamlObject(NameID.class);
		nameID.setValue(nameIdValue);
		return nameID;
	}

	private AudienceRestriction givenRstAudienceRestWithAudience(List<Audience> audiences) {
		AudienceRestriction audienceRestriction = OpenSamlUtil.buildSamlObject(AudienceRestriction.class);
		audienceRestriction.getAudiences()
						   .addAll(audiences);
		return audienceRestriction;

	}

	private Conditions givenRstConditions() {
		return OpenSamlUtil.buildSamlObject(Conditions.class);
	}

	private SubjectConfirmation givenRstSubjectConfirmation(String method) {
		SubjectConfirmation subjectConfirmation = OpenSamlUtil.buildSamlObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(method);
		return subjectConfirmation;
	}

	private List<AttributeStatement> giveRstAttributeStatements() {
		List<AttributeStatement> attributeStatements = new ArrayList<>();
		AttributeStatement attributeStatement = OpenSamlUtil.buildSamlObject(AttributeStatement.class);
		attributeStatements.add(attributeStatement);
		return attributeStatements;
	}

	private List<Audience> givenRstAudiences(String audienceUrl) {
		List<Audience> audiences = new ArrayList<>();
		Audience audience = OpenSamlUtil.buildSamlObject(Audience.class);
		audience.setURI(audienceUrl);
		audiences.add(audience);
		return audiences;
	}

	private List<AudienceRestriction> givenRstAudienceRestrictions() {
		return new ArrayList<>();
	}

	private void assertLog(String expectedString, Level level) {
		assertTrue(memoryAppender.contains(expectedString, level),
				"'" + expectedString + "' not found in: " + getLastLogLine());
	}

	private String getLastLogLine() {
		List<ILoggingEvent> list = memoryAppender.getLoggedEvents();
		if (list.size() >0) {
			return list.get(list.size() - 1).getFormattedMessage();
		}
		return "empty log";
	}

}
