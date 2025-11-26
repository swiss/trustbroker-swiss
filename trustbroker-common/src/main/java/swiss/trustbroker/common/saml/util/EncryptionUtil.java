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

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import swiss.trustbroker.common.exception.TechnicalException;

public class EncryptionUtil {

	private EncryptionUtil() {
	}

	public static EncryptedAssertion encryptAssertion(Assertion assertion, Credential credential, String dataEncryptALg,
			String keyEncryptAlg, Encrypter.KeyPlacement keyReplacement, String issuer, boolean emitSki) {
		DataEncryptionParameters encParams = new DataEncryptionParameters();
		encParams.setAlgorithm(dataEncryptALg);

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(credential);
		kekParams.setAlgorithm(keyEncryptAlg);
		KeyInfoGeneratorFactory kigf = SamlFactory.getKeyInfoGeneratorFactory(credential, emitSki);
		kekParams.setKeyInfoGenerator(kigf.newInstance());

		Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
		// PEER: Place the EncryptedKey element(s) as a peer to the EncryptedData inside the EncryptedElementType.
		// INLINE: Place the EncryptedKey element(s) within the KeyInfo of the EncryptedData.
		samlEncrypter.setKeyPlacement(keyReplacement);

		try {
			return samlEncrypter.encrypt(assertion);
		}
		catch (EncryptionException e) {
			throw new TechnicalException(String.format("Cannot encrypt Response.Assertion for Request with Issuer=%s "
					+ "message=%s", issuer, e.getMessage()), e);
		}
	}

	public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, List<Credential> credentials, String responseId,
			String issuerId) {

		if (credentials == null || credentials.isEmpty()) {
			throw new TechnicalException(String.format(
					"Cannot decrypt received assertion from response=%s. Invalid or missing "
							+ "Certificates.EncryptionKeystore for=%s : %s", responseId, issuerId,
					OpenSamlUtil.samlObjectToString(encryptedAssertion, true)));
		}

		List<Credential> creds = new ArrayList<>(credentials);
		KeyInfoCredentialResolver kekResolver = new CollectionKeyInfoCredentialResolver(creds);

		List<EncryptedKeyResolver> encryptedKeyResolvers = new ArrayList<>();
		// The EncryptedKey is assumed to be contained within the EncryptedAssertion/EncryptedData/KeyInfo.
		encryptedKeyResolvers.add(new InlineEncryptedKeyResolver());
		// The EncryptedKey is assumed to be contained as a peer of the EncryptedData within the SAML 2 EncryptedElementType
		encryptedKeyResolvers.add(new EncryptedElementTypeEncryptedKeyResolver());
		// The EncryptedKey is assumed to be contained via a RetrievalMethod child of the EncryptedData/KeyInfo,
		// which points via a same-document fragment reference to an EncryptedKey located elsewhere in the document.
		encryptedKeyResolvers.add(new SimpleRetrievalMethodEncryptedKeyResolver());
		encryptedKeyResolvers.add(new SimpleKeyInfoReferenceEncryptedKeyResolver());
		ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(encryptedKeyResolvers);

		Decrypter decrypter = new Decrypter(null, kekResolver, encryptedKeyResolver);
		decrypter.setRootInNewDocument(true);
		try {
			return decrypter.decrypt(encryptedAssertion);
		}
		catch (DecryptionException e) {
			throw new TechnicalException(String.format("DecryptionException=%s in Response.Assertion from Response with ID=%s "
							+ "Issuer=%s : %s", e.getMessage(), responseId, issuerId,
					OpenSamlUtil.samlObjectToString(encryptedAssertion, true)), e);
		}

	}
}
