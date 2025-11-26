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

package swiss.trustbroker.common.saml.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class EncryptionUtilTest {

	@BeforeAll
	static void init() {
		SamlInitializer.initSamlSubSystem();
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" } )
	void encryptAssertionTest(boolean useSki) {
		var inputAssertion = givenAssertion();
		var encryptedAssertion = EncryptionUtil.encryptAssertion(inputAssertion, givenCredentials().get(0),
				EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
				Encrypter.KeyPlacement.PEER,"issuer:TEST", useSki);
		assertNotNull(encryptedAssertion);
	}

	@Test
	void decryptAssertionTest() {
		var inputAssertion = givenAssertion();
		var encryptedAssertion = givenEncryptedAssertion(inputAssertion);
		List<Credential> credentials = givenCredentials();

		var assertion = EncryptionUtil.decryptAssertion(encryptedAssertion, credentials, "ANY-ID", "issuerId");
		assertNotNull(assertion);
		assertEquals(inputAssertion.getID(), assertion.getID());
		assertEquals(inputAssertion.getIssuer().getValue(), assertion.getIssuer().getValue());
	}

	@Test
	void decryptAssertionWithMultipleCredsTest() {
		var inputAssertion = givenAssertion();
		var encryptedAssertion = givenEncryptedAssertion(inputAssertion);
		List<Credential> credentials = givenMultipleCredentials();

		var assertion = EncryptionUtil.decryptAssertion(encryptedAssertion, credentials, "ANY-ID", "issuerId");
		assertNotNull(assertion);
		assertEquals(inputAssertion.getID(), assertion.getID());
		assertEquals(inputAssertion.getIssuer().getValue(), assertion.getIssuer().getValue());
	}

	private List<Credential> givenMultipleCredentials() {
		List<Credential> credentials = SamlTestBase.dummyInvalidCredential();
		credentials.add(SamlTestBase.dummyCredential());
		return credentials;
	}

	private List<Credential> givenCredentials() {
		return List.of(SamlTestBase.dummyCredential());
	}

	private EncryptedAssertion givenEncryptedAssertion(Assertion assertion) {
		return EncryptionUtil.encryptAssertion(assertion, givenCredentials().get(0),
				EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
				Encrypter.KeyPlacement.PEER,"issuer:TEST", false);
	}

	private Assertion givenAssertion() {
		var assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		// ID
		assertion.setID(UUID.randomUUID().toString());
		// issuer
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue("TEST_AUDIENCE");

		// attributes
		assertion.getAttributeStatements().addAll(giveAttributeStatements());
		return assertion;
	}

	private List<AttributeStatement> giveAttributeStatements() {
		List<AttributeStatement> attributeStatements = new ArrayList<>();
		var attributeStatement = OpenSamlUtil.buildSamlObject(AttributeStatement.class);
		attributeStatements.add(attributeStatement);
		return attributeStatements;
	}


}
