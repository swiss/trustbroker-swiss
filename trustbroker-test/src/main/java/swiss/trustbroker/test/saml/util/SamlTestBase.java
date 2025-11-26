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

package swiss.trustbroker.test.saml.util;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import lombok.Builder;
import lombok.Data;
import net.shibboleth.shared.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.AttributeRegistry;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;

@SuppressWarnings("java:S1118")
public class SamlTestBase {

	@Data
	@Builder
	public static class TestAttributeName implements AttributeName {

		private String name;

		private String altName;

		private String namespaceUri;

		private List<String> oidcNameList;

		private String mappers;

		public static TestAttributeName of(AttributeName attributeName) {
			return TestAttributeName.builder()
									.name(attributeName.getName())
									.namespaceUri(attributeName.getNamespaceUri())
									.altName(attributeName.getAltName())
									.oidcNameList(attributeName.getOidcNameList())
									.build();
		}

	}

	// openssl pkcs12 -export -in trustbroker-inventories/DEMO/keystore/token-signer/keystore.pem \
	//   -inkey trustbroker-inventories/DEMO/keystore/token-signer/keystore.pem -name signertb -out test-tb-signer-keystore.p12
	// keytool -importkeystore -keystore test-tb-signer-keystore.jks -srckeystore test-tb-signer-keystore.p12 \
	//   -storepass testit -keypass testit -noprompt -alias signertb -srcstorepass testit
	public static final String TEST_TB_KEYSTORE_JKS = "test-tb-signer-keystore.jks";

	// trustbroker-inventories/DEMO/keystore/token-signer/keystore.pem certificate split at 76 characters:
	public static final String TEST_CB_CERT_LINE_1 =
			"MIIDiTCCAnGgAwIBAgIUDgvNPf9rOzYuMgi37W7yRw/I81IwDQYJKoZIhvcNAQELBQAwVDELMAkG";

	public static final String TEST_CB_CERT_LINE_2 =
			"A1UEBhMCY2gxGjAYBgNVBAoMEXRydXN0YnJva2VyLnN3aXNzMQ0wCwYDVQQLDARkZW1vMRowGAYD";

	// openssl pkcs12 -export -in test-idp-mock-keystore.pem -inkey test-idp-mock-keystore.pem -name mocksigner \
	//   -out test-idp-mock-keystore.p12
	// keytool -importkeystore -keystore test-idp-mock-keystore.jks -srckeystore test-idp-mock-keystore.p12  \
	//   -storepass testit -keypass testit -noprompt -alias mocksigner -srcstorepass testit
	public static final String TEST_IDP_MOCK_KEYSTORE_JKS = "test-idp-mock-keystore.jks";

	public static final String TEST_IDP_MOCK_KEYSTORE_PEM = "test-idp-mock-keystore.pem";

	public static final String TEST_IDP_MOCK_CERTIFICATE_PEM = "test-idp-mock-cert.pem";

	public static final String TEST_IDP_MOCK_CERTIFICATE_DER_BASE64 = "test-idp-mock-keystore.der.base64";

	@SuppressWarnings("java:S2068") // (test JKS password)
	public static final String TEST_KEYSTORE_PW = "testit";

	public static final String TEST_KEYSTORE_TB_ALIAS = "signertb";

	public static final String TEST_IDP_MOCK_KEYSTORE_ALIAS = "mocksigner";

	// openssl req -new -x509 -days 3650 -newkey rsa:2048 -nodes -passin pass:testit -out test-keystore.pem -keyout key.pem
	// openssl rsa -in key.pem -aes256 -passout pass:testit>>test-keystore.pem
	// test-key.pem only the key, test-cert.pem only the cert, test-ca.pem the same self-signed cert (we could set up a test CA)
	public static final String X509_RSAENC_PEM = "test-keystore.pem";

	public static final String X509_CERT_PEM = "test-cert.pem";

	// openssl pkcs12 -export -in test-keystore.pem -inkey test-keystore.pem -passin pass:testit -passout pass:testit >
	// test-keystore.p12
	public static final String X509_RSAENC_P12 = "test-keystore.p12";

	// pfx is the windows naming
	public static final String X509_RSAENC_PFX = "test-keystore.pfx";

	// keytool -importkeystore -srckeystore test-keystore.p12 -srcstoretype pkcs12 -destkeystore test-keystore.jks
	// -deststoretype jks -deststorepass testit
	public static final String X509_RSAENC_JKS = "test-keystore.jks";

	@SuppressWarnings("java:S2068") // (test JKS password)
	public static final String X509_RSAENC_PW = "testit";

	public static final String X509_RSAENC_ALIAS = "1";

	public static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	public static Credential dummyCredential() {
		return dummyCredential(TEST_TB_KEYSTORE_JKS, TEST_KEYSTORE_PW, TEST_KEYSTORE_TB_ALIAS);
	}

	public static Credential dummyCredential(String certFileName, String password, String alias) {
		var spkeystoreJks = filePathFromClassPath(certFileName);
		try {
			var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			var file = new File(spkeystoreJks);
			var inputStream = new FileInputStream(file);
			keystore.load(inputStream, password.toCharArray());
			inputStream.close();

			var passwordMap = new HashMap<String, String>();
			passwordMap.put(alias, password);
			var resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

			var criterion = new EntityIdCriterion(alias);
			var criteriaSet = new CriteriaSet();
			criteriaSet.add(criterion);

			return resolver.resolveSingle(criteriaSet);
		}
		catch (Exception e) {
			throw new TechnicalException("Dummy credential keystore read failed ", e);
		}
	}

	public static KeystoreProperties dummyKeystoreProperties() {
		return KeystoreProperties.builder()
								 .signerKey(filePathFromClassPath(TEST_TB_KEYSTORE_JKS))
								 .signerCert(filePathFromClassPath(TEST_TB_KEYSTORE_JKS))
								 .password(TEST_KEYSTORE_PW)
								 .keyEntryId(TEST_KEYSTORE_TB_ALIAS)
								 .build();
	}

	public static SignableSAMLObject dummyObject() {
		return OpenSamlUtil.buildSamlObject(AuthnRequest.class); // the most simple object we can set a signature on
	}

	public static List<Credential> dummyInvalidCredential() {
		return dummyCredentials(TEST_IDP_MOCK_KEYSTORE_JKS);
	}

	public static List<Credential> dummyCredentials() {
		return dummyCredentials(TEST_TB_KEYSTORE_JKS);
	}

	public static List<Credential> dummyCredentials(String keystore) {
		var spkeystoreJks = filePathFromClassPath(keystore);
		return CredentialReader.readTrustCredentials(spkeystoreJks, "jks", TEST_KEYSTORE_PW, null);
	}

	public static String filePathFromClassPath(String fileName) {
		// map back to unit test execution using file
		return filePathStringFromClassloader(fileName)
				.replaceAll("build/libs/.*", "src/main/resources/" + fileName)
				.replace("file:", "");
	}

	public static File fileFromClassPath(String fileName) {
		return new File(filePathStringFromClassloader(fileName));
	}

	private static String filePathStringFromClassloader(String fileName) {
		var resource = SamlUtil.class.getClassLoader().getResource(fileName);
		if (resource == null) {
			throw new IllegalArgumentException("Missing file on classpath: " + fileName);
		}
		return resource.getFile();
	}

	public static String buildRedirectQueryString(RequestAbstractType request, boolean doubleSignature) {
		var signatureObj = request.getSignature();
		var sigAlg = signatureObj.getSignatureAlgorithm();
		// the normal redirect way is to use a separate query parameter for the signature and remove it from the message
		// if the signature is present in the message as well, we validate both signatures, verify that this does not break
		if (!doubleSignature) {
			request.setSignature(null);
		}
		var relayState = UUID.randomUUID().toString();
		var credential = SamlTestBase.dummyCredential();
		return SamlIoUtil.buildSignedSamlRedirectQueryString(request, credential, sigAlg, relayState);
	}

	public static void setAnyAttributeNamespaceUri(AttributeName attributeName) {
		setAttributeNamespaceUri(attributeName, "https://test/" + attributeName.getName());
	}

	public static void setAttributeNamespaceUri(AttributeName attributeName, String namespaceUri) {
		if (attributeName.getNamespaceUri() != null) {
			return;
		}
		var attribute = TestAttributeName.of(attributeName);
		attribute.setNamespaceUri(namespaceUri);
		AttributeRegistry.updateAttributeNameFromConfig(attribute);
	}

	public static void signSamlObject(SignableSAMLObject samlObject) {
		var newSignature = givenSignature(false);
		samlObject.setSignature(newSignature);

		SamlUtil.signSamlObject(samlObject, newSignature);
	}

	public static Signature givenSignature(boolean emptyKeyInfo) {
		var signature = OpenSamlUtil.buildSamlObject(Signature.class);
		signature.setSigningCredential(SamlTestBase.dummyCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSchemaLocation("http://www.w3.org/2000/09/xmldsig#");
		if (emptyKeyInfo) {
			var keyInfo = OpenSamlUtil.buildSamlObject(KeyInfo.class);
			var certificate = OpenSamlUtil.buildSamlObject(X509Data.class);
			keyInfo.getXMLObjects().add(certificate);
			signature.setKeyInfo(keyInfo);
		}
		else {
			signature.setKeyInfo(createMockKeyInfo(SamlTestBase.dummyCredential()));
		}
		return signature;
	}

	private static KeyInfo createMockKeyInfo(Credential credential) {
		var secConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
		var namedKeyInfoGeneratorManager = secConfiguration.getDataKeyInfoGeneratorManager();
		if (namedKeyInfoGeneratorManager == null) {
			throw new TechnicalException("NamedKeyInfoGeneratorManager is null");
		}
		var keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		var keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
		if (keyInfoGeneratorFactory == null) {
			throw new TechnicalException("KeyInfoGeneratorFactory is null");
		}
		var keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		try {
			return keyInfoGenerator.generate(credential);
		}
		catch (SecurityException e) {
			throw new TechnicalException("Key generation exception", e);
		}
	}

	public enum Qoa {

		QOA_10("urn:qoa:names:tc:ac:classes:10", 10),

		MOBILE_ONE_FACTOR_UNREGISTERED(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, 10),

		QOA_20("urn:qoa:names:tc:ac:classes:20", 20),

		PASSWORD_PROTECTED_TRANSPORT(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, 20),

		QOA_30("urn:qoa:names:tc:ac:classes:30", 30),

		SOFTWARE_TIME_SYNC_TOKEN(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN, 30),

		NOMAD_TELEPHONY(SamlContextClass.NOMAD_TELEPHONY, 30),

		QOA_40("urn:qoa:names:tc:ac:classes:40", 40),

		KERBEROS(SamlContextClass.KERBEROS, 40),

		QOA_50("urn:qoa:names:tc:ac:classes:50", 50),

		SOFTWARE_PKI(SamlContextClass.SOFTWARE_PKI, 50),

		MOBILE_TWO_FACTOR_CONTACT(SamlContextClass.MOBILE_TWO_FACTOR_CONTACT, 50),

		TIME_SYNC_TOKEN(SamlContextClass.TIME_SYNC_TOKEN, 50),

		QOA_60("urn:qoa:names:tc:ac:classes:60", 60),

		SMART_CARD_PKI(SamlContextClass.SMART_CARD_PKI, 60),

		AUTH_GUEST("urn:names:tc:SAML:2.0:ac:classes:AuthGuest", 10),

		AUTH_WEAK("urn:names:tc:SAML:2.0:ac:classes:AuthWeak", 20),

		AUTH_NORMAL("urn:names:tc:SAML:2.0:ac:classes:AuthNormal", 30),

		AUTH_NORMAL_VERIFIED("urn:names:tc:SAML:2.0:ac:classes:AuthNormalVerified", 40),

		AUTH_STRONG("urn:names:tc:SAML:2.0:ac:classes:AuthStrong", 50),

		AUTH_VERY_STRONG("urn:names:tc:SAML:2.0:ac:classes:AuthVeryStrong", 60),

		STRONGEST_POSSIBLE("urn:names:tc:SAML:2.0:ac:classes:StrongestPossible", -2),

		UNSPECIFIED(SamlContextClass.UNSPECIFIED, -1);

		public static final int STRONGEST_POSSIBLE_LEVEL = STRONGEST_POSSIBLE.level;

		public static final int UNSPECIFIED_LEVEL = UNSPECIFIED.level;

		public static final String CONTEXT_CLASS_PREFIX = "urn:qoa:names:tc:ac:classes:";

		private final String name;

		private final int level;

		Qoa(String name, int level) {
			this.name = name;
			this.level = level;
		}


		public String getName() {
			return this.name;
		}

		public int getLevel() {
			return this.level;
		}
	}

}
