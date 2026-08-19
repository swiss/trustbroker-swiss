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

package swiss.trustbroker.federation.xmlconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import org.junit.jupiter.api.Test;
import swiss.trustbroker.util.DefaultUtil;

class DefaultUtilTest {

	@Test
	void applyDefaultValuesSecurityPolicies() {
		Set<Object> visited = new HashSet<>();

		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .build();
		assertNull(rpObject.getSecurityPolicies().getRequireSignedAuthnRequest());
		assertNull(rpObject.getSecurityPolicies().getRequireSignedLogoutNotificationRequest());
		assertNull(rpObject.getSecurityPolicies().getRequireEncryptedAssertion());
		assertNull(rpObject.getSecurityPolicies().getValidateXmlSchema());
		assertNull(rpObject.getSecurityPolicies().getNotOnOrAfterSeconds());

		DefaultUtil.applyDefaultValues(rpObject, visited);

		assertTrue(rpObject.getSecurityPolicies().getRequireSignedAuthnRequest());
		assertTrue(rpObject.getSecurityPolicies().getRequireSignedLogoutNotificationRequest());
		assertTrue(rpObject.getSecurityPolicies().getRequireEncryptedAssertion());
		assertTrue(rpObject.getSecurityPolicies().getValidateXmlSchema());
		assertEquals(3600, rpObject.getSecurityPolicies().getNotOnOrAfterSeconds());
	}

	@Test
	void applyDefaultValuesOidcSecurityPolicies() {
		Set<Object> visited = new HashSet<>();

		OidcClient client = OidcClient.builder().build();
		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .oidc(Oidc.builder()
		                                              .clients(List.of(client))
		                                              .build())
		                                    .build();

		assertNull(client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertNull(client.getOidcSecurityPolicies().getEncryptionMethod());
		assertNull(client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertNull(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());

		DefaultUtil.applyDefaultValues(rpObject, visited);

		assertEquals(JWEAlgorithm.RSA_OAEP_256.getName(), client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertEquals(EncryptionMethod.A256GCM.getName(), client.getOidcSecurityPolicies().getEncryptionMethod());
		assertEquals(1, client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertFalse(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertEquals(60, client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertEquals(1, client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertEquals(60, client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertEquals(3600, client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());
	}

	@Test
	void applyDefaultValuesOidcSecurityPoliciesIfNotSet() {
		Set<Object> visited = new HashSet<>();
		String alg = JWEAlgorithm.ECDH_ES_A128KW.getName();
		OidcClient client = OidcClient.builder()
		                              .oidcSecurityPolicies(
											  OidcSecurityPolicies.builder()
				                                                  .allowPublicClientTokenExchange(true)
				                                                  .encryptionAlgorithm(alg)
				                                                  .build())
		                              .build();
		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .oidc(Oidc.builder()
		                                              .clients(List.of(client))
		                                              .build())
		                                    .build();

		assertNotNull(client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertNull(client.getOidcSecurityPolicies().getEncryptionMethod());
		assertNull(client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertNotNull(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());

		DefaultUtil.applyDefaultValues(rpObject, visited);

		assertEquals(alg, client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertEquals(EncryptionMethod.A256GCM.getName(), client.getOidcSecurityPolicies().getEncryptionMethod());
		assertEquals(1, client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertTrue(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertEquals(60, client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertEquals(1, client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertEquals(60, client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertEquals(3600, client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());
	}
}
