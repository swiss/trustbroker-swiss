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

package swiss.trustbroker.oidc.client.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcMockTestData;

class OidcClaimValidatorServiceTest {

	private TrustBrokerProperties trustBrokerProperties;

	private OidcClaimValidatorService oidcClaimValidatorService;

	@BeforeEach
	void setUp() {
		var clock = Clock.fixed(Instant.ofEpochMilli(0), ZoneOffset.UTC);
		trustBrokerProperties = new TrustBrokerProperties();
		oidcClaimValidatorService = new OidcClaimValidatorService(trustBrokerProperties, clock);
	}

	@ParameterizedTest
	@MethodSource
	void validNotBefore(Date check, boolean expected) {
		assertThat(oidcClaimValidatorService.validNotBefore(check, 0), is(expected));
	}

	static Object[][] validNotBefore() {
		return new Object[][] {
				{ null, true },
				{ new Date(0), true },
				// negative constant
				{ new Date(-SecurityChecks.TOLERANCE_NOT_BEFORE_SEC), true },
				{ new Date(1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void validNotOnOrAfter(Date check, boolean expected) {
		assertThat(oidcClaimValidatorService.validNotOnOrAfter(check, 0), is(expected));
	}

	static Object[][] validNotOnOrAfter() {
		return new Object[][] {
				{ null, true },
				{ new Date(0), true },
				// positive constant
				{ new Date(1 - SecurityChecks.TOLERANCE_NOT_AFTER_SEC), true },
				{ new Date(-SecurityChecks.TOLERANCE_NOT_AFTER_SEC), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void validateValidClaims(String issuerId, JWTClaimsSet jwtClaims) {
		var client = OidcMockTestData.givenClient();
		client.setIssuerId(issuerId);
		var cp = OidcMockTestData.givenCpWithOidcClient(client);
		assertDoesNotThrow(() -> oidcClaimValidatorService.validateClaims(
				jwtClaims, cp, client, OidcMockTestData.CP_ISSUER_ID, OidcMockTestData.NONCE));
	}

	static Object[][] validateValidClaims() {
		return new Object[][] {
				{ null, givenClaims(null, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT,  OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
				{ null, givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,OidcMockTestData.CLIENT_ID, OidcMockTestData.NONCE) },
				{ "remoteIssuer", givenClaims(OidcMockTestData.JWT_ID, "remoteIssuer", new Date(0), new Date(0),
						new Date(0), OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID,
						new Date(-SecurityChecks.TOLERANCE_NOT_BEFORE_SEC), new Date(-SecurityChecks.TOLERANCE_NOT_BEFORE_SEC),
						new Date(1 - SecurityChecks.TOLERANCE_NOT_AFTER_SEC),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
		};
	}

	@ParameterizedTest
	@MethodSource
	void validateInvalidClaims(String configIssuerId, String requestedNonce, JWTClaimsSet jwtClaims) {
		var cp = ClaimsParty.builder().id(OidcMockTestData.CP_ISSUER_ID).build();
		var client = OidcClient.builder().id(OidcMockTestData.CLIENT_ID).issuerId(configIssuerId).build();
		assertThrows(RequestDeniedException.class, () -> oidcClaimValidatorService.validateClaims(
						jwtClaims, cp, client, OidcMockTestData.CP_ISSUER_ID, requestedNonce));
	}

	static Object[][] validateInvalidClaims() {
		return new Object[][] {
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, null, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
				{ "otherIssuer", OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0),
						new Date(0), OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, "wong_iss", new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC),
						new Date(0), new Date(0), OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0),
						new Date(1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0),
						new Date(-SecurityChecks.TOLERANCE_NOT_AFTER_SEC),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						null, OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT,"wrong_aud", null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, "wrong_azp", OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, null) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID, null, "wrong_nonce") },
				{ null, null, givenClaims(null, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0), new Date(0),
						OidcMockTestData.SUBJECT,  OidcMockTestData.CLIENT_ID, null, OidcMockTestData.NONCE) },

		};
	}

	private static JWTClaimsSet givenClaims(String id, String issuer,
			Date issuedAt, Date notBefore, Date expires,
			String subject, String audience, String authorizedParty, String nonce) {
		return new JWTClaimsSet.Builder()
				.jwtID(id)
				.issuer(issuer)
				.issueTime(issuedAt)
				.notBeforeTime(notBefore)
				.expirationTime(expires)
				.subject(subject)
				.audience(audience)
				.claim(OidcUtil.OIDC_AUTHORIZED_PARTY, authorizedParty)
				.claim(OidcUtil.OIDC_NONCE, nonce)
				.build();
	}
}
