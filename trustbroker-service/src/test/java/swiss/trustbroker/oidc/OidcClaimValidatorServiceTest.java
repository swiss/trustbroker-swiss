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

package swiss.trustbroker.oidc;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;

class OidcClaimValidatorServiceTest {

	private static final String CLIENT_ID = "client-123";
	private static final String COUNTERPARTY = "cp-001";
	private static final String TOKEN_TYPE = "id_token";

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
				{ new Date((1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC) * 1000), false }
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
				{ new Date(-SecurityChecks.TOLERANCE_NOT_AFTER_SEC * 1000), false }
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
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date((1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC) * 1000),
						new Date(0), new Date(0), OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0),
						new Date((1 - SecurityChecks.TOLERANCE_NOT_BEFORE_SEC) * 1000), new Date(0),
						OidcMockTestData.SUBJECT, OidcMockTestData.CLIENT_ID,null, OidcMockTestData.NONCE) },
				{ null, OidcMockTestData.NONCE,
						givenClaims(OidcMockTestData.JWT_ID, OidcMockTestData.CP_ISSUER_ID, new Date(0), new Date(0),
						new Date(-SecurityChecks.TOLERANCE_NOT_AFTER_SEC * 1000),
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

	@Test
	void validateSubAudAzpTest() {
		var client = givenOidcClient();
		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateSubAudAzp(null, COUNTERPARTY, client, TOKEN_TYPE, true)
		);

		final JWTClaimsSet claims = new JWTClaimsSet.Builder().build();
		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateSubAudAzp(
						claims, COUNTERPARTY, client, TOKEN_TYPE, true)
		);

		final JWTClaimsSet missingAud = new JWTClaimsSet.Builder()
				.subject("user123")
				.build();
		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateSubAudAzp(
						missingAud, COUNTERPARTY, client, TOKEN_TYPE, true)
		);
		assertDoesNotThrow(() ->
				OidcClaimValidatorService.validateSubAudAzp(
						missingAud, COUNTERPARTY, client, TOKEN_TYPE, false)
		);

		final JWTClaimsSet wrongAud = new JWTClaimsSet.Builder()
				.subject("user123")
				.audience("other-client")
				.build();
		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateSubAudAzp(
						wrongAud, COUNTERPARTY, client, TOKEN_TYPE, false)
		);

		final JWTClaimsSet correctAud = new JWTClaimsSet.Builder()
				.subject("user123")
				.audience(CLIENT_ID)
				.build();
		assertDoesNotThrow(() ->
				OidcClaimValidatorService.validateSubAudAzp(
						correctAud, COUNTERPARTY, client, TOKEN_TYPE, true)
		);

		final JWTClaimsSet wrongAzp = new JWTClaimsSet.Builder()
				.subject("user123")
				.audience(CLIENT_ID)
				.claim(OidcUtil.OIDC_AUTHORIZED_PARTY, "other-client")
				.build();
		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateSubAudAzp(
						wrongAzp, COUNTERPARTY, client, TOKEN_TYPE, true)
		);

		final JWTClaimsSet missingAzp = new JWTClaimsSet.Builder()
				.subject("user123")
				.audience(CLIENT_ID)
				.build();
		assertDoesNotThrow(() ->
				OidcClaimValidatorService.validateSubAudAzp(
						missingAzp, COUNTERPARTY, client, TOKEN_TYPE, true)
		);

		final JWTClaimsSet correctAzp = new JWTClaimsSet.Builder()
				.subject("user123")
				.audience(CLIENT_ID)
				.claim(OidcUtil.OIDC_AUTHORIZED_PARTY, CLIENT_ID)
				.build();
		assertDoesNotThrow(() ->
				OidcClaimValidatorService.validateSubAudAzp(
						correctAzp, COUNTERPARTY, client, TOKEN_TYPE, true)
		);
	}

	@Test
	void validateAcrsReturnsEmptyListWithoutAcrAndWithoutQoa() {
		var claims = new JWTClaimsSet.Builder().build();
		var cpClient = OidcClient.builder().id("cp-client").build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		var relyingParty = RelyingParty.builder().id("rp").build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		var acrs = OidcClaimValidatorService.validateAcrs(claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties);

		assertThat(acrs, is(List.of()));
	}

	@Test
	void validateAcrsReturnsAcrStringAsSingleElementList() {
		var claims = new JWTClaimsSet.Builder().claim(OidcUtil.OIDC_ACR, "acr-1").build();
		var cpClient = OidcClient.builder().id("cp-client").build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		var relyingParty = RelyingParty.builder().id("rp").build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		var acrs = OidcClaimValidatorService.validateAcrs(claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties);

		assertThat(acrs, is(List.of("acr-1")));
	}

	@Test
	void validateAcrsReturnsCollectionWithStringConversion() {
		var claims = new JWTClaimsSet.Builder().claim(OidcUtil.OIDC_ACR, List.of("acr-1", 20)).build();
		var cpClient = OidcClient.builder().id("cp-client").build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		var relyingParty = RelyingParty.builder().id("rp").build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		var acrs = OidcClaimValidatorService.validateAcrs(claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties);

		assertThat(acrs, is(List.of("acr-1", "20")));
	}

	@Test
	void validateAcrsThrowsWhenCpQoaIsEnforcedAndAcrMissing() {
		trustBrokerProperties.setQoa(QualityOfAuthenticationConfig.builder().mapping(Map.of("acr-1", 10)).build());
		var claims = new JWTClaimsSet.Builder().build();
		var cpQoa = Qoa.builder().enforce(true).classes(List.of(AcClass.builder().contextClass("acr-1").build())).build();
		var cpClient = OidcClient.builder().id("cp-client").qoa(cpQoa).build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		var relyingParty = RelyingParty.builder().id("rp").build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		assertThrows(RequestDeniedException.class, () ->
				OidcClaimValidatorService.validateAcrs(claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties));
	}

	@Test
	void validateAcrsUsesRpQoaFallbackFromRelyingParty() {
		trustBrokerProperties.setQoa(QualityOfAuthenticationConfig.builder().mapping(Map.of("acr-1", 10)).build());
		var claims = new JWTClaimsSet.Builder().claim(OidcUtil.OIDC_ACR, "acr-1").build();
		var cpClient = OidcClient.builder().id("cp-client").build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		var rpQoa = Qoa.builder()
				.enforce(true)
				.classes(List.of(AcClass.builder().contextClass("acr-1").order(10).build()))
				.build();
		var relyingParty = RelyingParty.builder().id("rp").qoa(rpQoa).build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		assertDoesNotThrow(() -> OidcClaimValidatorService.validateAcrs(
				claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties));
	}

	@Test
	void validateAcrsUsesCpClientQoaBeforeClaimsPartyQoa() {
		var claims = new JWTClaimsSet.Builder().claim(OidcUtil.OIDC_ACR, "acr-1").build();
		var cpQoaOnClient = Qoa.builder().enforce(false).classes(List.of(AcClass.builder().contextClass("other").build())).build();
		var cpClient = OidcClient.builder().id("cp-client").qoa(cpQoaOnClient).build();
		var claimsParty = OidcMockTestData.givenCpWithOidcClient(cpClient);
		claimsParty.setQoa(Qoa.builder().enforce(true).classes(List.of(AcClass.builder().contextClass("must-match-party").build())).build());
		var relyingParty = RelyingParty.builder().id("rp").build();
		var rpOidcClient = OidcClient.builder().id("rp-client").build();

		assertDoesNotThrow(() -> OidcClaimValidatorService.validateAcrs(
				claims, claimsParty, relyingParty, rpOidcClient, trustBrokerProperties));
	}

	@ParameterizedTest
	@MethodSource
	void getAcrStringListReturnsExpected(Object acrInput, List<String> expected) {
		assertThat(OidcClaimValidatorService.getAcrStringList(acrInput), is(expected));
	}

	static Object[][] getAcrStringListReturnsExpected() {
		return new Object[][] {
				{ null, List.of() },
				{ "acr-1", List.of("acr-1") },
				{ List.of("acr-1", 20), List.of("acr-1", "20") },
				{ 42, List.of() }
		};
	}

	@Test
	void validateQoaAllowsNullQoa() {
		var counterParty = ClaimsParty.builder().id("cp").build();

		assertDoesNotThrow(() -> OidcClaimValidatorService.validateQoa(counterParty, trustBrokerProperties, null, List.of("acr-1")));
	}

	@Test
	void validateQoaThrowsWhenAcrMissingAndEnforced() {
		var counterParty = ClaimsParty.builder().id("cp").build();
		var qoa = Qoa.builder().enforce(true).classes(List.of(AcClass.builder().contextClass("acr-1").order(10).build())).build();
		List<String> acrList = List.of();

		assertThrows(RequestDeniedException.class,
				() -> OidcClaimValidatorService.validateQoa(counterParty, trustBrokerProperties, qoa, acrList));
	}

	@Test
	void validateQoaThrowsForInvalidAcrWhenEnforced() {
		trustBrokerProperties.setQoa(QualityOfAuthenticationConfig.builder().mapping(Map.of("acr-1", 10, "acr-2", 20)).build());
		var counterParty = ClaimsParty.builder().id("cp").build();
		var qoa = Qoa.builder().enforce(true).classes(List.of(AcClass.builder().contextClass("acr-1").order(10).build())).build();
		List<String> acrList = List.of("acr-2");

		assertThrows(RequestDeniedException.class,
				() -> OidcClaimValidatorService.validateQoa(counterParty, trustBrokerProperties, qoa, acrList));
	}

	@Test
	void validateQoaAcceptsMatchingAcrWhenEnforced() {
		trustBrokerProperties.setQoa(QualityOfAuthenticationConfig.builder().mapping(Map.of("acr-1", 10)).build());
		var counterParty = ClaimsParty.builder().id("cp").build();
		var qoa = Qoa.builder().enforce(true).classes(List.of(AcClass.builder().contextClass("acr-1").order(10).build())).build();

		assertDoesNotThrow(() -> OidcClaimValidatorService.validateQoa(counterParty, trustBrokerProperties, qoa, List.of("acr-1")));
	}

	private OidcClient givenOidcClient() {
		return OidcClient.builder()
						 .id(CLIENT_ID)
						 .clientSecret("secret1")
						 .redirectUris(AcWhitelist.builder()
												  .acUrls(List.of("https://localhost/test"))
												  .build())

						 .build();
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
