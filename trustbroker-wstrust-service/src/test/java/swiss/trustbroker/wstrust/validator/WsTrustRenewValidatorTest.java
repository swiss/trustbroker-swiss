/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.wstrust.validator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wssecurity.BinarySecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.util.WsTrustTestUtil;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration(classes = {
		WsTrustRenewValidator.class
})
class WsTrustRenewValidatorTest {

	@MockitoBean
	private SsoService ssoService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private Clock clock;

	@Autowired
	private WsTrustRenewValidator wsTrustRenewValidator;

	private WsTrustConfig wsTrustConfig;

	private SecurityChecks securityChecks;

	@BeforeAll
	static void setupAll() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void setup() {
		wsTrustConfig = new WsTrustConfig();
		when(trustBrokerProperties.getWstrust()).thenReturn(wsTrustConfig);
		securityChecks = new SecurityChecks();
		when(trustBrokerProperties.getSecurity()).thenReturn(securityChecks);
	}

	@ParameterizedTest
	@MethodSource
	void applies(RequestType requestType, boolean enabled, boolean expectedResult) {
		wsTrustConfig.setRenewEnabled(enabled);
		assertThat(wsTrustRenewValidator.applies(requestType), is(expectedResult));
	}

	static Object[][] applies() {
		return new Object[][] {
				{ WsTrustUtil.createRequestType(RequestType.RENEW), true, true },
				{ WsTrustUtil.createRequestType(RequestType.RENEW), false, false },
				{ WsTrustUtil.createRequestType(RequestType.ISSUE), true, false }
		};
	}

	@Test
	void findValidSsoSession() {
		var stateData = mockSsoSession(true);
		var assertion = WsTrustTestUtil.givenAssertion();

		var ssoSession = wsTrustRenewValidator.findValidSsoSession(assertion);

		assertTrue(ssoSession.isPresent());
		assertThat(ssoSession.get(), is(stateData));
	}


	@Test
	void noValidSsoSessionNotRequired() {
		wsTrustConfig.setRenewRequiresSsoSession(false);
		mockSsoSession(false);
		var assertion = WsTrustTestUtil.givenAssertion();

		var ssoSession = wsTrustRenewValidator.findValidSsoSession(assertion);

		assertTrue(ssoSession.isEmpty());
	}

	@Test
	void noValidSsoSessionRequired() {
		wsTrustConfig.setRenewRequiresSsoSession(true);
		mockSsoSession(false);
		var assertion = WsTrustTestUtil.givenAssertion();

		assertThrows(RequestDeniedException.class, () -> wsTrustRenewValidator.findValidSsoSession(assertion));
	}

	@Test
	void validateSecurityToken() throws Exception {
		wsTrustConfig.setRenewRequiresSecurityToken(true);
		var relyingParty = givenRelyingParty();
		var securityToken = givenSecurityToken();

		assertDoesNotThrow(() -> wsTrustRenewValidator.validateSecurityToken(securityToken, relyingParty));
	}

	@Test
	void validateSecurityTokenNotRequired() {
		wsTrustConfig.setRenewRequiresSecurityToken(false);
		var relyingParty = givenRelyingParty();

		assertDoesNotThrow(() -> wsTrustRenewValidator.validateSecurityToken(null, relyingParty));
	}

	@ParameterizedTest
	@MethodSource
	void validateSecurityTokenInvalid(BinarySecurityToken securityToken) {
		wsTrustConfig.setRenewRequiresSecurityToken(true);
		var relyingParty = givenRelyingParty();

		assertThrows(RequestDeniedException.class,
				() -> wsTrustRenewValidator.validateSecurityToken(securityToken, relyingParty));
	}

	static Object[][] validateSecurityTokenInvalid() throws Exception {
		return new Object[][] {
				// wrong value type
				{ givenSecurityToken("otherValueType", WSSConstants.ENCODING_BASE64_BINARY, null) },
				// wrong encoding
				{ givenSecurityToken(WSSConstants.VALUE_X509_V3, "otherEncoding", null) },
				// missing value
				{ givenSecurityToken(WSSConstants.VALUE_X509_V3, WSSConstants.ENCODING_BASE64_BINARY, null) },
				// invalid value
				{ givenSecurityToken(WSSConstants.VALUE_X509_V3, WSSConstants.ENCODING_BASE64_BINARY, "AABBCCDD") },
				// invalid PEM certificate
				{ givenSecurityToken(WSSConstants.VALUE_X509_V3, WSSConstants.ENCODING_BASE64_BINARY,
						givenCertValue(SamlTestBase.TEST_IDP_MOCK_CERTIFICATE_PEM)) },
				// invalid Base64 DER certificate
				{ givenSecurityToken(WSSConstants.VALUE_X509_V3, WSSConstants.ENCODING_BASE64_BINARY,
						givenCertValue(SamlTestBase.TEST_IDP_MOCK_CERTIFICATE_DER_BASE64)) }
		};
	}

	@ParameterizedTest
	@MethodSource
	void validate(Instant now, Long notOnOrAfterToleranceSecs, boolean expectFailure) throws Exception {
		if (notOnOrAfterToleranceSecs != null) {
			securityChecks.setRenewNotOnOrAfterToleranceRenewSec(notOnOrAfterToleranceSecs);
		}
		// If true requires a SoapMessage signed with private key for RelyingParty.SignerTrustStore:
		wsTrustConfig.setRenewRequireSignedRequests(false);
		var relyingParty = givenRelyingParty();
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(WsTrustTestUtil.RP_ISSUER_ID, null)).thenReturn(relyingParty);
		var securityToken = givenSecurityToken();
		var assertion = WsTrustTestUtil.givenAssertion();
		SamlTestBase.signSamlObject(assertion);
		var rst = WsTrustTestUtil.givenRenewRstRequest(assertion);
		mockSsoSession(true);
		when(trustBrokerProperties.getIssuer()).thenReturn(WsTrustTestUtil.XTB_ISSUER_ID);
		when(clock.instant()).thenReturn(now);
		var requestHeader = new SoapMessageHeader();
		requestHeader.setSecurityToken(securityToken);
		requestHeader.setRequestTimestamp(WsTrustUtil.createTimestamp(now, now.plusSeconds(60)));

		if (expectFailure) {
			assertThrows(RequestDeniedException.class, () -> wsTrustRenewValidator.validate(rst, requestHeader));
		}
		else {
			var result = wsTrustRenewValidator.validate(rst, requestHeader);

			assertThat(result.getValidatedAssertion(), is(assertion));
			assertThat(result.isRecomputeAttributes(), is(false));
			assertThat(result.getIssuerId(), is(WsTrustTestUtil.RP_ISSUER_ID));
			assertThat(result.getRecipientId(), is(WsTrustTestUtil.RP_ISSUER_ID));
			assertThat(result.isUseAssertionLifetime(), is(true));
			assertThat(result.getSessionIndex(), is(WsTrustTestUtil.SSO_SESSION_ID));
		}
	}

	static Object[][] validate() {
		return new Object[][] {
				{ WsTrustTestUtil.NOW, null, false },
				{ WsTrustTestUtil.NOW.plusSeconds(SecurityChecks.RENEW_TOLERANCE_NOT_AFTER_SEC), null, false },
				{ WsTrustTestUtil.NOW.plusSeconds(10_000L), 10_000L, false },
				{ WsTrustTestUtil.NOW.plusSeconds(SecurityChecks.RENEW_TOLERANCE_NOT_AFTER_SEC + WsTrustTestUtil.SUBJECT_VALID_SECS - 1), null, false },
				{ WsTrustTestUtil.NOW.plusSeconds(SecurityChecks.RENEW_TOLERANCE_NOT_AFTER_SEC + WsTrustTestUtil.SUBJECT_VALID_SECS), null, true },
				// SUBJECT_VALID_SECS < CONDITION_VALID_SECS
				{ WsTrustTestUtil.NOW.plusSeconds(SecurityChecks.RENEW_TOLERANCE_NOT_AFTER_SEC + WsTrustTestUtil.CONDITION_VALID_SECS - 1), null, true },
				{ WsTrustTestUtil.NOW.plusSeconds(SecurityChecks.RENEW_TOLERANCE_NOT_AFTER_SEC + WsTrustTestUtil.CONDITION_VALID_SECS), null, true }
		};
	}

	private BinarySecurityToken givenSecurityToken() throws Exception {
		var certValue = givenCertValue(SamlTestBase.X509_CERT_PEM);
		return givenSecurityToken(WSSConstants.VALUE_X509_V3, WSSConstants.ENCODING_BASE64_BINARY, certValue);
	}

	private static String givenCertValue(String file) throws Exception {
		var certFile = SamlTestBase.filePathFromClassPath(file);
		return Files.readString(Path.of(certFile));
	}

	private static BinarySecurityToken givenSecurityToken(String valueType, String encoding, String value) {
		var securityToken = (BinarySecurityToken) XMLObjectSupport.buildXMLObject(BinarySecurityToken.ELEMENT_NAME);
		securityToken.setValueType(valueType);
		securityToken.setEncodingType(encoding);
		securityToken.setValue(value);
		return securityToken;
	}

	private RelyingParty givenRelyingParty() {
		var trustCredentials = SamlTestBase.dummyCredentials(SamlTestBase.X509_RSAENC_P12);
		return RelyingParty.builder()
						   .id(WsTrustTestUtil.RP_ISSUER_ID)
						   .rpTrustCredentials(trustCredentials)
						   .build();
	}

	private StateData mockSsoSession(boolean present) {
		var stateData = givenStateData();
		when(ssoService.findValidSsoSessionForSessionIndexes(List.of(WsTrustTestUtil.SSO_SESSION_ID)))
				.thenReturn(present ? Optional.of(givenStateData()) : Optional.empty());
		return stateData;
	}

	private static StateData givenStateData() {
		return StateData.builder()
						.id("id1")
						.ssoSessionId(WsTrustTestUtil.SSO_SESSION_ID)
						.build();
	}

}
