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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.Criterion;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemReader;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;

@SuppressWarnings("java:S1118")
@Slf4j
public class CredentialReader {

	private static final String TYPE_JKS = "jks";

	private static final String TYPE_PKCS12 = "pkcs12";

	private static final String TYPE_PEM = "pem";

	private static final String TYPE_CERTIFICATE = "CERTIFICATE";

	private static final String TYPE_RSAKEY1 = "RSA PRIVATE KEY";

	private static final String TYPE_RSAKEY2 = "ENCRYPTED PRIVATE KEY";

	private static final String JAVA_VERSION = "java.version";

	private static final String PEM_MARKER = "-----BEGIN CERTIFICATE-----";

	private static String invalidKeystoreMessage(String certType, String certPath) {
		return String.format("Unsupported keystore type %s for keystore %s", certType, certPath);
	}

	private static String detectCertType(String certPath, String certType) {
		if (certType != null) {
			return certType;
		}
		if (certPath.endsWith(TYPE_PKCS12) || certPath.endsWith(".p12")) {
			return TYPE_PKCS12;
		}
		if (certPath.endsWith(TYPE_JKS)) {
			return TYPE_JKS;
		}
		if (certPath.endsWith(TYPE_PEM)) {
			return TYPE_PEM;
		}
		throw new TechnicalException(invalidKeystoreMessage(certType, certPath));
	}

	private static boolean isJksOrPkcs12CertType(String certType, String certPath) {
		certType = detectCertType(certPath, certType);
		return certType.equalsIgnoreCase(TYPE_JKS) || certType.equalsIgnoreCase(TYPE_PKCS12);
	}

	private static boolean isPemCertType(String certType, String certPath) {
		certType = detectCertType(certPath, certType);
		return certType.equalsIgnoreCase(TYPE_PEM);
	}

	private static String getPemKeyPath(String keyPath, String certPath) {
		if (keyPath == null || keyPath.isEmpty()) {
			log.debug("No KeyPath specified, falling back to CertPath {} for key", certPath);
			return certPath;
		}
		return keyPath;
	}

	private static List<Credential> extractAllTrustedCerts(KeyStore keystore, String alias, String certPath) {
		var creds = new ArrayList<Credential>();
		try {
			var it = keystore.aliases();
			while (it.hasMoreElements()) {
				var ksAlias = it.nextElement();
				if (alias == null || alias.equals(ksAlias)) {
					creds.add(new BasicX509Credential((X509Certificate) keystore.getCertificate(ksAlias)));
				}
			}
			return creds;
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Cannot load alias=%s from certPath=%s", alias, certPath), ex);
		}
	}

	public static List<Credential> readTrustCredentials(String certPath, String certType, String password, String alias) {
		log.debug("Creating credential from cert file: {}", certPath);
		if (isJksOrPkcs12CertType(certType, certPath)) {
			var keystore = readKeystoreFromFile(certPath, password);
			return extractAllTrustedCerts(keystore, alias, certPath);
		}
		if (isPemCertType(certType, certPath)) {
			return readTrustCertCredentialFromPem(certPath);
		}
		throw new TechnicalException(invalidKeystoreMessage(certType, certPath));
	}

	// checking aliases not supported
	public static void checkKeystore(String certPath, String certType, String password, String keyPath) {
		password = CredentialUtil.processPassword(password);
		if (isJksOrPkcs12CertType(certType, certPath)) {
			readKeystoreFromFile(certPath, password);
			return;
		}
		if (isPemCertType(certType, certPath)) {
			readPemCertificate(certPath);
			keyPath = getPemKeyPath(keyPath, certPath);
			readPemPrivateKey(keyPath, password, true);
			return;
		}
		throw new TechnicalException(invalidKeystoreMessage(certType, certPath));
	}

	public static Credential createCredential(KeystoreProperties keystoreProperties) {
		var ret = CredentialReader.createCredential(
				keystoreProperties.getSignerCert(),
				keystoreProperties.getType(),
				keystoreProperties.getPassword(),
				keystoreProperties.getKeyEntryId(),
				keystoreProperties.getSignerKey()
		);
		log.debug("Created signer={}", keystoreProperties.getSignerCert());
		return ret;
	}

	public static Credential createCredential(String certPath, String certType, String password, String alias, String keyPath) {
		// CI/CD integration: Passphrase for all PKI objects from K8S secret expected here signaled with $PKI_PASSPHRASE
		password = CredentialUtil.processPassword(password);
		// load
		if (isJksOrPkcs12CertType(certType, certPath)) {
			return getJKSorPKCS12Credential(certPath, password, alias);
		}
		if (isPemCertType(certType, certPath)) {
			return getPemCredential(certPath, password, keyPath);
		}
		throw new TechnicalException(invalidKeystoreMessage(certType, certPath));
	}

	private static Credential getPemCredential(String certPath, String password, String keyPath) {

		log.debug("Processing PEM certificate {}", certPath);
		var certificate = readPemCertificate(certPath);

		log.debug("Processing PEM key {}", keyPath);
		keyPath = getPemKeyPath(keyPath, certPath);
		var privateKey = readPemPrivateKey(keyPath, password);

		var credential = new BasicX509Credential((X509Certificate) certificate);
		credential.setPrivateKey(privateKey);
		log.debug("PEM certificate successfully read");
		return credential;
	}
	// read from base64 encoded binary (DER) or PEM, returns X509Credential
	public static Credential getDerOrPemCredential(String certData, String source) {
		if (StringUtils.isEmpty(certData)) {
			throw new TechnicalException(String.format("Reading keystore from source=%s failed: data is null", source));
		}
		Certificate certificate;
		if (certData.startsWith(PEM_MARKER)) {
			certificate = readPemCertificate(new ByteArrayInputStream(certData.getBytes(StandardCharsets.UTF_8)), source);
		}
		else {
			var base64Data = Base64Util.decode(certData);
			certificate = readDerCertificate(new ByteArrayInputStream(base64Data), source);
		}
		return new BasicX509Credential((X509Certificate) certificate);
	}

	// read from PEM encoded stream, returns X509Credential
	public static Credential getPemCredential(InputStream inputStream, String source) {
		var certificate = readPemCertificate(inputStream, source);
		return new BasicX509Credential((X509Certificate) certificate);
	}

	// read from binary stream (DER), returns X509Credential
	public static Credential getDerCredential(InputStream inputStream, String source) {
		var certificate = readDerCertificate(inputStream, source);
		return new BasicX509Credential((X509Certificate) certificate);
	}

	public static PrivateKey readPemPrivateKey(String signerKey, String password) {
		return readPemPrivateKey(signerKey, password, false);
	}

	public static PrivateKey readPemPrivateKey(String signerKey, String password, boolean tryOnly) {
		try {
			PEMKeyPair pair = getKeyPairFromPath(signerKey, password);
			if (pair == null) {
				var msg = String.format("No KeyPair was found for %s", signerKey);
				if (tryOnly) {
					log.debug(msg);
					return null;
				}
				throw new TechnicalException(msg);
			}
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
			return converter.getPrivateKey(pair.getPrivateKeyInfo());
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			var msg = String.format("Exception reading key %s: %s", signerKey, e.getMessage());
			throw new TechnicalException(msg, e);
		}
	}

	private static PEMKeyPair getKeyPairFromPath(String keyPath, String password) throws TechnicalException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		// read using bouncycastle

		try (var inputStream = readFromFileOrClasspath(keyPath, "PEMKeyPair");
				var streamReader = new InputStreamReader(inputStream);
				var parser = new PEMParser(streamReader)) {
			var pwDebug = (password == null ? password : password.substring(0, 1) + "*****");
			Object o;
			PEMKeyPair pair = null;
			while ((o = parser.readObject()) != null) {
				if (o instanceof PEMKeyPair keyPair) {
					pair = keyPair;
				}
				else if (o instanceof PEMEncryptedKeyPair keyPair) {
					pair = decryptPEMKeyPair(keyPath, password, pwDebug, keyPair);
				}
				else if (o instanceof PKCS8EncryptedPrivateKeyInfo pkInfo) {
					PrivateKeyInfo keyInfo = decryptPEMKey(keyPath, password, pwDebug, pkInfo);
					pair = new PEMKeyPair(null, keyInfo);
				}
				else {
					log.debug("Ignoring object of type {} in {}", o.getClass().getName(), keyPath);
				}
			}

			if (pair == null) {
				log.debug("No KeyPair was found in {}", keyPath);
			}

			return pair;
		}
	}

	private static PrivateKeyInfo decryptPEMKey(String keyPath, String password, String pwDebug,
			PKCS8EncryptedPrivateKeyInfo pemEncryptedKey) {
		String provider = null;
		try {
			char[] pw = CredentialUtil.passwordToCharArray(password);
			InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(pw);
			provider = decryptionProv.getClass().getName();
			log.debug("Decrypting {} using algo {}, provider {}, java {}, password {}",
					keyPath, pemEncryptedKey.getEncryptionAlgorithm(), decryptionProv.getClass().getName(),
					System.getProperty(JAVA_VERSION), pwDebug);
			return pemEncryptedKey.decryptPrivateKeyInfo(decryptionProv);
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception ex) {
			var msg = String.format(
					"Decrypting %s using algo %s, provider %s, java %s, password %s failed with %s",
					keyPath, pemEncryptedKey.getEncryptionAlgorithm(), provider,
					System.getProperty(JAVA_VERSION), pwDebug, ex.getMessage());
			throw new TechnicalException(msg, ex);
		}
	}

	private static PEMKeyPair decryptPEMKeyPair(String keyPath, String password, String pwDebug,
			PEMEncryptedKeyPair pemEncryptedKeyPair) {
		String provider = null;
		try {
			char[] pw = CredentialUtil.passwordToCharArray(password);
			PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(pw);
			provider = decryptionProv.getClass().getName();
			log.debug("Decrypting {} using algo {}, provider {}, java {}, password {}",
					keyPath, pemEncryptedKeyPair.getDekAlgName(), decryptionProv.getClass().getName(),
					System.getProperty(JAVA_VERSION), pwDebug);
			return pemEncryptedKeyPair.decryptKeyPair(decryptionProv);
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception ex) {
			var msg = String.format(
					"Decrypting %s using algo %s, provider %s, java %s, password %s failed with %s",
					keyPath, pemEncryptedKeyPair.getDekAlgName(), provider,
					System.getProperty(JAVA_VERSION), pwDebug, ex.getMessage());
			throw new TechnicalException(msg, ex);
		}
	}

	public static Certificate readPemCertificate(String keystorePath) {
		try (var inputStream = readFromFileOrClasspath(keystorePath, "PEM keystore")) {
			return readPemCertificate(inputStream, keystorePath);
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Reading PEM keystore from keystorePath=%s failed: %s",
					keystorePath, e.getMessage()), e);
		}
	}

	public static Certificate readPemCertificate(InputStream inputStream, String source) {
		try {
			var certificateFactory = CertificateFactory.getInstance("X509");
			try (var streamReader = new InputStreamReader(inputStream);
					var reader = new PemReader(streamReader)) {
				final var byteArrayInput = new ByteArrayInputStream(reader.readPemObject().getContent());
				return certificateFactory.generateCertificate(byteArrayInput);
			}
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Reading PEM keystore from source=%s failed: %s",
					source, e.getMessage()), e);
		}
	}

	// read from binary stream (DER)
	public static Certificate readDerCertificate(InputStream inputStream, String source) {
		try {
			var certificateFactory = CertificateFactory.getInstance("X509");
			return certificateFactory.generateCertificate(inputStream);
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Reading DER keystore from source=%s failed: %s",
					source, e.getMessage()), e);
		}
	}

	private static Credential getJKSorPKCS12Credential(String keystorePath, String password, String alias) {
		//!!!!!!!!!PERFORMANCE ISSUE WITH PKCS12 IF IT IS USED FOR EVERY REQUEST
		log.debug("Processing certificate {} looking for alias {}", keystorePath, alias);
		if (alias == null) {
			throw new TechnicalException(String.format(
					"Reading PKCS12/JKS keystore from keystorePath=%s requires a key <Alias> in the configuration",
					keystorePath));
		}
		try {
			Credential credential = null;
			var keystore = readKeystoreFromFile(keystorePath, password);
			Map<String, String> passwordMap = new HashMap<>();
			passwordMap.put(alias, password);
			var resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

			Criterion criterion = new EntityIdCriterion(alias);
			var criteriaSet = new CriteriaSet();
			criteriaSet.add(criterion);

			credential = resolver.resolveSingle(criteriaSet);
			log.debug("{} certificate successfully read", keystorePath);
			return credential;
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Reading PKCS12/JKS keystore from keystorePath=%s failed: %s",
					keystorePath, e.getMessage()), e);
		}
	}

	public static KeyStore readKeystoreFromFile(String keystorePath, String keyStorePassword) {
		keyStorePassword = CredentialUtil.processPassword(keyStorePassword);

		try (var inputStream = readFromFileOrClasspath(keystorePath, "PKCS12")) {
			var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(inputStream, CredentialUtil.passwordToCharArray(keyStorePassword));
			return keystore;
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Reading PKCS12 keystore from keystorePath=%s failed: %s",
					keystorePath, e.getMessage()), e);
		}
	}

	private static InputStream readFromFileOrClasspath(String keystorePath, String keystoreType) throws IOException {
		var file = new File(keystorePath);
		if (file.exists()) {
			return new FileInputStream(file);
		}
		else {
			var stream = CredentialReader.class.getClassLoader().getResourceAsStream(keystorePath);
			if (stream == null) {
				throw new TechnicalException(String.format("Reading %s keystore from keystorePath=%s failed",
						keystoreType, keystorePath));
			}
			return stream;
		}
	}

	public static Credential getCredential(String certPath, String certType, String password, String alias, String keyPath) {
		log.debug("Creating credential from cert/key file: {} {}", certPath, keyPath == null ? "" : keyPath);
		return createCredential(certPath, certType, password, alias, keyPath);
	}

	public static List<Credential> readTrustCertCredentialFromPem(String keystorePath) {
		var objCount = 0;
		try (var inputStream = readFromFileOrClasspath(keystorePath, "certificate");
				var streamReader = new InputStreamReader(inputStream);
				var reader = new PemReader(streamReader)) {
			var certificateFactory = CertificateFactory.getInstance("X509");
			var pemObject = reader.readPemObject();
			List<Credential> credentials = new ArrayList<>();
			while (pemObject != null) {
				objCount++;
				log.debug("Handling pem obj #{} of type {} from {}", objCount, pemObject.getType(), keystorePath);
				final var byteArrayInput = new ByteArrayInputStream(pemObject.getContent());
				if (TYPE_CERTIFICATE.equals(pemObject.getType())) {
					X509Certificate certificate =
							(X509Certificate) certificateFactory.generateCertificate(byteArrayInput);
					var credential = new BasicX509Credential(certificate);
					credentials.add(credential);
				}
				else if (TYPE_RSAKEY1.equals(pemObject.getType()) || TYPE_RSAKEY2.equals(pemObject.getType()) ) {
					log.debug("Ignoring expected {} using keystore as truststore", pemObject.getType());
				}
				else {
					log.warn("Ignoring unexpected '{}' in keystore {}", pemObject.getType(), keystorePath);
				}
				pemObject = reader.readPemObject();
			}
			if (!credentials.isEmpty()) {
				return credentials;
			}
			else {
				throw new TechnicalException(String.format("No certificate found in keystorePath=%s", keystorePath));
			}
		}
		catch (TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Something went wrong reading certificate #%d from keystorePath=%s: %s",
					objCount, keystorePath, e.getMessage()), e);
		}
	}

	public static KeyStore createKeystoreFromPem(KeystoreProperties keystoreProperties) {
		String signerCertPath = keystoreProperties.getSignerCert();
		String signerKeyPath = keystoreProperties.getSignerKey() != null ? keystoreProperties.getSignerKey()
				: keystoreProperties.getSignerCert();
		var certificate = readPemCertificate(signerCertPath);
		String keystorePassword = CredentialUtil.processPassword(keystoreProperties.getPassword());
		var privateKey = readPemPrivateKey(signerKeyPath, keystorePassword);

		try {
			char[] password = CredentialUtil.passwordToCharArray(keystorePassword);
			var keystore = KeyStore.getInstance("JKS");
			keystore.load(null);
			String keyEntryID = keystoreProperties.getKeyEntryId() != null ? keystoreProperties.getKeyEntryId() : "defaultAlias";
			keystore.setCertificateEntry(keyEntryID, certificate);
			keystore.setKeyEntry(keyEntryID, privateKey, password, new Certificate[] { certificate });
			return keystore;
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Creating JKS keystore from signerCertPath=%s signerKeyPath=%s failed: "
							+ "%s",
					signerCertPath, signerKeyPath, e.getMessage()), e);
		}
	}

}
