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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

class JwkUtilTest {

	@Test
	void buildJwsHeaderTest() {
		String keyId = "keyId";
		var header = JwkUtil.buildJwsHeader(OidcTestBase.givenJwkSource(keyId));
		assertEquals(JwsAlgorithms.RS256, header.getAlgorithm().getName());
		assertEquals(keyId, header.getKeyId());
	}

	@Test
	void getKeyIdFromJwkSource() {
		String keyId = "keyId";
		var jwkKeyId = JwkUtil.getKeyIdFromJwkSource(OidcTestBase.givenJwkSource(keyId));
		assertEquals(keyId, jwkKeyId);
	}

	@Test
	void getKeyIdFromJwkSourceWithAlgorithmTest() {
		String keyId = "keyId";

		assertNull(JwkUtil.findEncJwkForAlg(new JWKSet(), JwsAlgorithms.RS256, "clientId", "http//test.com"));
		assertNull(JwkUtil.findEncJwkForAlg(OidcTestBase.givenJwkSet(keyId), JwsAlgorithms.RS256, "clientId", "http//test.com"));

		var singleKey = JwkUtil.findEncJwkForAlg(OidcTestBase.givenEncJwkSet(JWEAlgorithm.RSA_OAEP_256, null), JwsAlgorithms.RS256, "clientId", "http//test.com");
		assertNotNull(singleKey);
		assertEquals(JWEAlgorithm.RSA_OAEP_256, singleKey.getAlgorithm());

		var keyWithWrongAlg = JwkUtil.findEncJwkForAlg(OidcTestBase.givenEncJwkSet(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP_256), JwsAlgorithms.RS256, "clientId", "http//test.com");
		assertNotNull(keyWithWrongAlg);
		assertEquals(JWEAlgorithm.RSA_OAEP_256, keyWithWrongAlg.getAlgorithm());

		var keyWithMatchingAlg = JwkUtil.findEncJwkForAlg(OidcTestBase.givenEncJwkSet(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP_512), JWEAlgorithm.RSA_OAEP_256.getName(), "clientId", "http//test.com");
		assertNotNull(keyWithMatchingAlg);
		assertEquals(JWEAlgorithm.RSA_OAEP_256, singleKey.getAlgorithm());
	}
}
