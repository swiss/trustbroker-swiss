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

package swiss.trustbroker.common.oidc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Objects;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.security.credential.Credential;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class JwtUtilTest {

	@Test
	void validateTokenTest() {
		assertDoesNotThrow(() -> JwtUtil.validateToken(OidcTestBase.givenPKCEAccessToken()));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"keyId,RSA-OAEP-256,A256GCM,RSA",
			"keyId,RSA-OAEP-512,A128GCM,RSA",
			"keyId,A256KW,A256GCM,NONE",
			"keyId,ECDH-ES+A128KW,A128GCM,EC",
			"keyId,RSA1_5,A128CBC-HS256,RSA",
	})
	void generateEncryptedTokenTest(String keyId, String encAlg, String encMethod, String credType) {
		var jwkSource = OidcTestBase.givenJwkSource(null);
		var encCredential = encryptionCred("rsa_public.pem");
		if (!Objects.equals(credType, "NONE") &&Objects.equals(EncAlgFamily.valueOf(credType), EncAlgFamily.EC)) {
			encCredential = encryptionCred("ec_public.pem");
		}
		var claims = JwtClaimsSet.builder().subject("subject").build();
		var jwsHeader = JwkUtil.buildJwsHeader(jwkSource);
		var parameters = JwtEncoderParameters.from(jwsHeader, claims);

		var jweHeader = OidcUtil.getJWEHeader(true, encAlg, encMethod, keyId);
		if (credType.equals("NONE")) {
			Credential finalEncCredential = encCredential;
			assertThrows(TechnicalException.class, () -> JwtUtil.generateEncryptedToken(parameters, false, jwkSource,
					finalEncCredential, jweHeader, "id"));
		}
		else {
			testJWEGenerator(parameters, jwkSource, encCredential, jweHeader, encAlg, encMethod, keyId);
		}
	}

	private Credential encryptionCred(String fileName) {
		var filePathFromClassPath = SamlTestBase.filePathFromClassPath(fileName);
		var credentials = CredentialReader.readTrustCertCredentialFromPem(filePathFromClassPath);

		return credentials.get(0);
	}

	private static void testJWEGenerator(JwtEncoderParameters parameters, JWKSource<SecurityContext> jwkSource,
										 Credential encCredential, JWEHeader jweHeader, String encAlg, String encMethod, String keyId) {
		var jwt = JwtUtil.generateEncryptedToken(parameters, false, jwkSource, encCredential, jweHeader, "id");

		assertNotNull(jwt);
		assertNotNull(jwt.getHeaders());
		assertNotNull(jwt.getClaims());
		assertEquals(5, jwt.getTokenValue().split("\\.").length);
		assertEquals(encAlg, jwt.getHeaders().get("alg"));
		assertEquals(encMethod, jwt.getHeaders().get("enc"));
		assertEquals("JWT", jwt.getHeaders().get("cty"));
		assertEquals(keyId, jwt.getHeaders().get("kid"));
	}

	private String rsaEncJwt() {
		return "eyJraWQiOiJrZXlJZCIsImN0eSI6IkpXVCIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.r41uJZ6YbOLCr1XChcNP-X-S3uGxORJvXBXfQ6vcdTuthWJaWL1pEthKdRY7DCowyK-y6Qo18_hOjAv7zd8xr8dYWXv68l_r4ZN-sISK2UpmSIcrvmXuC8oO8cgudoDViX_b7nq7pwN6VnSKWwO1QPHIUoG-FA5KTywECD5bag47WScN6scR0DYX0hj11y1WyAbKs-XZ7p90tu6amJIxziLMzoA6wJmgIy6Yr8dy6hGbvitvrf3g-74Rq1gKkhUgn4eYIE3J4Oy86drI4wgDL8_n_yhW_IkB7cxe5l0P9cwLFO6azqD_deV2a51DRkpPdDyZBR1JJyge9BiOddOqCg.Kb6wTFkOOHK3pHnT.nRjVyo-PtgPBODy1_H-4WjA.ksn_MytE0AfNrBDMaPYHKQ";
	}

	private String ecEncJwt() {
		return "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJYQ2x2ZUVGRUQxVzVhTHpHbFNCZWs5WHVmUHF2T1ZjdTBJVlN2N0txeWFjIiwieSI6IkM5NjludGhtRlR5emZvM2ZrN3hqS0N1cmdzZzRwZFVDWWRKSzczZWlwdlkifSwia2lkIjoia2V5SWQiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiRUNESC1FUytBMTI4S1cifQ.BNhUEOpmHdQLbq2KKvoxh6JYMe-BnqiY.mqoI4AtXDHf3Avw_.tiYcqQsY5j1ZaEumeyIAMg4.hOpTVD4oNjFBwi-3mJ5ldA";
	}

	@Test
	void decryptJwtTest() {
		var decryptionCred = decryptionCred("rsa_public.pem", "rsa_private.pem", "testit");
		var token = rsaEncJwt();
		validateDecryption(token, decryptionCred, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

		decryptionCred = decryptionCred("ec_public.pem", "ec_private.pem", null);
		token = ecEncJwt();
		validateDecryption(token, decryptionCred, JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM);
	}

	private static void validateDecryption(String token, Credential rsaEncCred, JWEAlgorithm algorithm, EncryptionMethod method) {
		assertDoesNotThrow(() -> {
			EncryptedJWT decryptJwt = JwtUtil.decryptJwt(token, rsaEncCred, "clientId");
			assertNotNull(decryptJwt);
			assertNotNull(decryptJwt.getPayload());
			assertTrue(decryptJwt.getPayload().toJSONObject().containsKey("sub"));
			assertNotNull(decryptJwt.getHeader());
			assertEquals(algorithm, decryptJwt.getHeader().getAlgorithm());
			assertEquals(method, decryptJwt.getHeader().getEncryptionMethod());
			return decryptJwt;
		});
	}

	private Credential decryptionCred(String publicKey, String privateKey, String password) {
		var publicKeyPath = SamlTestBase.filePathFromClassPath(publicKey);
		var privateKeyPath = SamlTestBase.filePathFromClassPath(privateKey);
		return CredentialReader.createCredential(publicKeyPath, "pem", password, null, privateKeyPath);
	}
}
