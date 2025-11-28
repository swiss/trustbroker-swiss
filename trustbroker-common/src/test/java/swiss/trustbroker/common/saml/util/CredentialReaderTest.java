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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.test.saml.util.SamlTestBase;

/**
 * Tests the PEM, JKS, P12 and AES256 RSA key handling. We expect cerType to be optional if file extension is set and
 * that all these formats can be handled.
 */
class CredentialReaderTest {

	//------------------------------------------------------------------------------------
	// Functional tests
	//------------------------------------------------------------------------------------

	@Test
	void testPemKeystore() {
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_PEM, null, SamlTestBase.X509_RSAENC_PW, null);
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_PEM, "pem", SamlTestBase.X509_RSAENC_PW, SamlTestBase.X509_RSAENC_PEM);
		// Service variant
		Credential credential1 = CredentialReader.getCredential(SamlTestBase.X509_RSAENC_PEM, null, SamlTestBase.X509_RSAENC_PW, null, null);
		Credential credential2 = CredentialReader.getCredential(SamlTestBase.X509_RSAENC_PEM, "pem", SamlTestBase.X509_RSAENC_PW, "irrelevant", SamlTestBase.X509_RSAENC_PEM);
		assertEquals(credential1.getEntityId(), credential2.getEntityId());
	}

	@Test
	void testJksKeystore() {
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_JKS, null, SamlTestBase.X509_RSAENC_PW, null);
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_JKS, "jks", SamlTestBase.X509_RSAENC_PW, SamlTestBase.X509_RSAENC_JKS);
		// Service variant does not work with opensaml library
	}

	@Test
	void testPkcs12Keystore() {
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_P12, null, SamlTestBase.X509_RSAENC_PW, null);
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_P12, "pkcs12", SamlTestBase.X509_RSAENC_PW, SamlTestBase.X509_RSAENC_P12);
		CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_PFX, "pkcs12", SamlTestBase.X509_RSAENC_PW, null);
		// we expect reader to complain when type is missing and extenstion is unknown
		assertThrows(TechnicalException.class, () -> {
			CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_PFX, null, SamlTestBase.X509_RSAENC_PW, null);
		});
		// Service variant does not work with opensaml library
	}

	@Test
	void testPemCertificate() {
		Certificate certificate = CredentialReader.readPemCertificate(SamlTestBase.X509_RSAENC_PEM);
		assertTrue(certificate.toString().contains("CN=UnitTestCert"), "Unexpected cert: " + certificate);
	}

	@Test
	void testPemPrivateKey() {
		PrivateKey privateKey = CredentialReader.readPemPrivateKey(SamlTestBase.X509_RSAENC_PEM, SamlTestBase.X509_RSAENC_PW);
		assertTrue(privateKey.toString().contains("db5d60b92676bcef2"), "Unexpected cert: " + privateKey);
	}

	@Test
	void testAnySupportedKeystore() throws KeyStoreException {
		KeyStore keyStore1 = CredentialReader.readKeystoreFromFile(SamlTestBase.X509_RSAENC_P12, SamlTestBase.X509_RSAENC_PW);
		KeyStore keyStore2 = CredentialReader.readKeystoreFromFile(SamlTestBase.X509_RSAENC_JKS, SamlTestBase.X509_RSAENC_PW);
		assertEquals(keyStore1.size(), keyStore2.size());
		assertEquals(keyStore1.aliases().nextElement(), keyStore2.aliases().nextElement());
	}

	//------------------------------------------------------------------------------------
	// Error and ecurity tests
	//------------------------------------------------------------------------------------

	@Test
	void testPemKeystoreInvalidPassphrase() {
		assertThrows(TechnicalException.class, () -> {
			CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_PEM, null, "wrong", null);
		});
	}

	@Test
	void testPkcs12KeystoreInvalidPassphrase() {
		assertThrows(TechnicalException.class, () -> {
			CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_P12, null, "wrong", null);
		});
	}

	@Test
	void testJksKeystoreInvalidPassphrase() {
		assertThrows(TechnicalException.class, () -> {
			CredentialReader.checkKeystore(SamlTestBase.X509_RSAENC_JKS, null, "wrong", null);
		});
	}

	@Test
	void testPemTruststoreWithPrivateKey() {
		List<Credential> creds = CredentialReader.readTrustCredentials(SamlTestBase.X509_RSAENC_PEM, null, null, null);
		assertEquals(1, creds.size());
	}

}
