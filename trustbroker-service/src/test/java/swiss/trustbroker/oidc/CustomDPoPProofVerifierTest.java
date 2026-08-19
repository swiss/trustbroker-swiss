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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

class CustomDPoPProofVerifierTest {

	@Test
	void verifyIfAvailableReturnsNullWhenProofMissing() {
		var authentication = mock(OAuth2AuthorizationGrantAuthenticationToken.class);
		when(authentication.getAdditionalParameters()).thenReturn(Map.of());

		assertNull(CustomDPoPProofVerifier.verifyIfAvailable(authentication));
	}

	@Test
	void verifyIfAvailableReturnsNullWhenProofBlank() {
		var authentication = mock(OAuth2AuthorizationGrantAuthenticationToken.class);
		when(authentication.getAdditionalParameters()).thenReturn(Map.of("dpop_proof", "   "));

		assertNull(CustomDPoPProofVerifier.verifyIfAvailable(authentication));
	}

	@Test
	void verifyIfAvailableThrowsInvalidDpopProofForMalformedJwt() {
		var authentication = mock(OAuth2AuthorizationGrantAuthenticationToken.class);
		when(authentication.getAdditionalParameters()).thenReturn(Map.of(
				"dpop_proof", "not-a-jwt",
				"dpop_method", "POST",
				"dpop_target_uri", "https://server.example.com/oauth2/token"));

		var ex = assertThrows(OAuth2AuthenticationException.class,
				() -> CustomDPoPProofVerifier.verifyIfAvailable(authentication));

		assertEquals(OAuth2ErrorCodes.INVALID_DPOP_PROOF, ex.getError().getErrorCode());
	}

	@Test
	void verifyIfAvailableReturnsJwtForValidProof() throws Exception {
		var method = "POST";
		var targetUri = "https://server.example.com/oauth2/token";
		var proof = createValidDpopProof(method, targetUri);
		var authentication = mock(OAuth2AuthorizationGrantAuthenticationToken.class);
		when(authentication.getAdditionalParameters()).thenReturn(Map.of(
				"dpop_proof", proof,
				"dpop_method", method,
				"dpop_target_uri", targetUri));

		var jwt = CustomDPoPProofVerifier.verifyIfAvailable(authentication);

		assertNotNull(jwt);
		assertEquals(method, jwt.getClaimAsString("htm"));
		assertEquals(targetUri, jwt.getClaimAsString("htu"));
	}

	private static String createValidDpopProof(String method, String targetUri) throws Exception {
		ECKey ecJwk = new ECKeyGenerator(Curve.P_256)
				.keyID("test-kid")
				.generate();
		var signer = new ECDSASigner(ecJwk);

		var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
				.type(new JOSEObjectType("dpop+jwt"))
				.jwk(ecJwk.toPublicJWK())
				.build();
		var claims = new JWTClaimsSet.Builder()
				.jwtID(UUID.randomUUID().toString())
				.issueTime(new Date())
				.claim("htm", method)
				.claim("htu", targetUri)
				.build();
		var signedJwt = new SignedJWT(header, claims);
		signedJwt.sign(signer);
		return signedJwt.serialize();
	}

}

