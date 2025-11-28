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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public class OidcTestBase {

	public static String givenPKCEAccessToken() {
		return "eyJraWQiOiI1MDUxNTM1Ni0wMjU1LTRhNjEtOGMxYS0yYWEyZWM2Mzg1OWMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
				+ ".eyJwcm9maWxlTmFtZSI6IjExMjQzMVxcUHJvZmlsZS1DSEw1MDExMjU5OTMiLCJzdWIiOiIxMTM1NTUiLCJ1c2VyRXh0SWQiOiIxMTM1NT"
				+ "UiLCJyb2xlIjpbIkhBUlJPRFMtd2Vha2F1dG9zaWxlbnQuQUxMT1ciLCJDb25zdFJvbGUuQUxMT1ciLCIxMTI0MzFcXEhBUlJPRFMtd2Vha2"
				+ "F1dG9zaWxlbnQuQUxMT1ciXSwib2lkY19mbGFnIjpmYWxzZSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODAiLCJsYW5ndWFnZSI6Im"
				+ "RlIiwidHlwIjoiQmVhcmVyIiwic3NvU2Vzc2lvbklkIjoic3NvLWU5YTJkMTdkLWM5Y2ItNDhiNS1iOTUxLWY5N2U3YTg4ZWE3NiIsInNpZCI"
				+ "6IjU5OUE0Q0MwNjU0N0RGNkQxRUY2RkJFQTU5ODQxMEQ5Iiwic3RyaW5nX2NsYWltX2FzX2xpc3QiOlsic3NvLWU5YTJkMTdkLWM5Y2ItN"
				+ "DhiNS1iOTUxLWY5N2U3YTg4ZWE3NiJdLCJhY3IiOiJ1cm46cW9hLmVpYW0uYWRtaW4uY2g6bmFtZXM6dGM6YWM6Y2xhc3NlczoyMCIsInV"
				+ "uaXRFeHRJZCI6WyI1MDEuc2VsZnJlZzIiLCIxMTI0MzFcXDUwMS5zZWxmcmVnMiJdLCJzdXJuYW1lIjoiVHJlbnlpIiwiYXpwIjoiVEVT"
				+ "VExBLWd1ZXN0YXV0b3NpbGVudCIsInNjb3BlIjoib3BlbmlkIGVtYWlsIiwiYXV0aF90aW1lIjoxNzE2ODc4OTYxLCJKU09OVHJlZSI6"
				+ "eyJzdWJ0cmVlIjp7ImVwb2NoMTk3MCI6ODYzOTksIm51bTIwMjMiOjIwMjN9fSwiZXhwIjoxNzE2ODgwMTYyLCJzZXNzaW9uUHJ"
				+ "vZmlsZUV4dElkIjoiMTEyNDMxIiwic2Vzc2lvbl9zdGF0ZSI6IjU5OUE0Q0MwNjU0N0RGNkQxRUY2RkJFQTU5ODQxMEQ5Iiw"
				+ "iaWF0IjoxNzE2ODc4OTYyLCJqdGkiOiJhN2YzMzBhNS0yY2ZhLTQ0YzAtYjcwMS0zOTI1MTE4NzcyZGYiLCJ1bml0TmFtZSI6"
				+ "WyI1MDEuc2VsZnJlZzIiLCIxMTI0MzFcXDUwMS5zZWxmcmVnMiJdLCJzdWJfaWQiOiIxMTM1NTUiLCJjbGllbnRFeHRJZCI6Wy"
				+ "I1MzAwIiwiNTAxIl0sImdpdmVuX25hbWUiOiJJbXJlIiwibm9uY2UiOiIxNWZlNWY3Yy0xZjhjLTQ4YmMtOWNmZS05YTlhMjQyND"
				+ "g3YmIiLCJsaXN0X2NsYWltX2FzX3N0cmluZyI6IkhBUlJPRFMtd2Vha2F1dG9zaWxlbnQuQUxMT1cgQ29uc3RSb2xlLkFMTE9XI"
				+ "iwiYXVkIjoiVEVTVExBLWd1ZXN0YXV0b3NpbGVudCIsIkFycmF5MCI6WyJJbXJlIFRyZW55aSIsIm51bGwiLCJudWxsIl0sIm5"
				+ "iZiI6MTcxNjg3ODk2MiwiaG9tZVJlYWxtIjoidXJuOmVpYW0uYWRtaW4uY2g6aWRwOmUtaWQ6Q0gtTE9HSU4tREVWVEVTVCIsIk"
				+ "pTT05BcnJheTEiOlsiSW1yZSBUcmVueWkiLCJudWxsIiwibnVsbCJdLCJKU09OQXJyYXkyIjpbIkltcmUgVHJlbnlpIiwibnVsbC"
				+ "IsIm51bGwiXSwiSG9tZU5hbWUiOiJFLUlEIENILUxPR0lOIiwidG9sb3dlcl92YWx1ZSI6ImFueWNhc2V2YWx1ZXRvYmVjb252ZXJ0ZWR"
				+ "0b2xvd2VyIiwiSlNPTkFycmF5MyI6WyJJbXJlIFRyZW55aSIsIm51bGwiLCJudWxsIl0sImJvb2xlYW5fZmxhZyI6dHJ1ZSwibmFtZSI6IlRy"
				+ "ZW55aSBJbXJlIiwiSlNPTk9iamVjdDAiOnsibGluZTAiOiJUcmVueWkifSwiSlNPTk9iamVjdDIiOnsibGluZTMiOiJudWxsIiwibGluZTIi"
				+ "OiJudWxsIiwibGluZTEiOiJJbXJlIFRyZW55aSJ9LCJKU09OT2JqZWN0MSI6eyJsaW5lMyI6Im51bGwiLCJsaW5lMiI6Im51bGwiLCJsaW5l"
				+ "MSI6IkltcmUgVHJlbnlpIn0sImZhbWlseV9uYW1lIjoiVHJlbnlpIiwiYmlydGhfdGltZSI6ODYzOTksIkpTT05PYmplY3QzIjp7ImxpbmU"
				+ "zIjoibnVsbCIsImxpbmUyIjoibnVsbCIsImxpbmUxIjoiSW1yZSBUcmVueWkifX0.o_pe3fnQYELy1qqc9afrWLYzxVm2Q09PQNYklzJiSF"
				+ "GYh5YJtp41LGd6OAaOUU4_baCOGqKUFhEzQADd174L2QgSatA5xxBa6L8-YohxB6HkHtAVgJR_rKRY9npoCiArJSVNWvdD1eHn_onsYQZx"
				+ "LW_MZ4TL_8oQopYZHlPTOKieWazeF2u6olkb2gSc5htHExXF8Qxv_jo6JnG3ZP3yymNxGhngAfshdE7Y8vSesj87Z42TfAU8s2kiMs9Z"
				+ "LCCCEeXaEFpQj-XfODQoeFEBvA3MS8RtjGl0z1-KPaWPixfITjynRB-pxpVg3dLazEMOUuQ5Pkj3ZSa51KHUcb4wuA";
	}

	public static JWKSource<SecurityContext> givenJwkSource(String keyId) {
		// Generate RSA key pair
		RSAKey rsaKey = generateRsaKey(keyId, null, null);

		// Wrap in JWKSet
		JWKSet jwkSet = new JWKSet(rsaKey);

		// Return static JWKSource
		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}

	public static JWKSet givenJwkSet(String keyId) {
		RSAKey rsaKey = generateRsaKey(keyId, null, null);

		// Wrap in JWKSet
		return new JWKSet(rsaKey);
	}

	public static JWKSet givenEncJwkSet(JWEAlgorithm algorithm, JWEAlgorithm alg2) {
		List<JWK> keys = new ArrayList<>();
		var rsaKey1 = generateRsaKey("keyId", KeyUse.ENCRYPTION, algorithm);
		keys.add(rsaKey1);
		if (alg2 != null) {
			var rsaKey2 = generateRsaKey("keyId2", KeyUse.ENCRYPTION, alg2);
			keys.add(rsaKey2);
		}
		// Wrap in JWKSet
		return new JWKSet(keys);
	}

	private static RSAKey generateRsaKey(String keyId, KeyUse use, JWEAlgorithm algorithm) {
		// Generate RSA key pair
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();

		// Create RSA JWK
		var rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate());

		if (keyId == null) {
			keyId = UUID.randomUUID().toString();
		}

		if (use != null) {
			rsaJWK.keyUse(use);
		}

		if (algorithm != null) {
			rsaJWK.algorithm(algorithm);
		}

		return rsaJWK
				.keyID(keyId)
				.build();
	}
}
