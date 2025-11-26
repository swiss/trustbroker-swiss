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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.xml.namespace.QName;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.TraceSupport;

@Slf4j
public class SamlUtil {

	public static final String XTB_RELAY_STATE_PREFIX = "XTB";

	public static final String ORIGINAL_ISSUER = "OriginalIssuer";

	public static final String ORIGINAL_ISSUER_SCHEMA = "http://schemas.xmlsoap.org/ws/2009/09/identity/claims";

	public static final String ORIGINAL_ISSUER_NAMESPACE_ALIAS = "a";

	public static final QName ORIGINAL_ISSUER_QNAME = new QName(SamlUtil.ORIGINAL_ISSUER_SCHEMA, SamlUtil.ORIGINAL_ISSUER,
			SamlUtil.ORIGINAL_ISSUER_NAMESPACE_ALIAS);

	public static final String SKI_OID = "2.5.29.14";

	private SamlUtil() {
	}

	public static void prepareSamlObject(SignableXMLObject object, String c14nAlgo, Signature signature,
			String skinnyAssertionNamespaces) {
		try {
			// make C14n valid before marshalling as otherwise dom is discarded again
			SkinnySamlUtil.prepareSAMLSignature(signature, c14nAlgo);

			// opensaml => DOM
			XMLObjectSupport.getMarshaller(object).marshall(object);

			// Discard xsi:type to reduce message size transitively on PEPs as well
			SkinnySamlUtil.prepareSAMLObject(object, skinnyAssertionNamespaces);

			// DOM => patched DOM (introduced for 100% message backwards compatibility but UNUSED at the time being).
			// Controlled via RelyingParty.CanonicalizationAlgorithm entry.
			// Deprecated: We keep this code pattern for other patching we might need to do for incompatible peers.
			SkinnySamlUtil.prepareSAMLObject(object, c14nAlgo);
		}
		catch (MarshallingException e) {
			throw new TechnicalException(String.format("Marshalling Signature exception: %s", e.getMessage()), e);
		}
	}

	// test variant
	public static void signSamlObject(SignableXMLObject object, Signature signature) {
		signSamlObject(object, signature, OpenSamlUtil.SKINNY_ALL); // default namespace handling
	}

	public static void signSamlObject(SignableXMLObject object, Signature signature, String skinnyAssertionNamespaces) {
		try {
			// opensaml => DOM
			prepareSamlObject(object, signature.getCanonicalizationAlgorithm(), signature, skinnyAssertionNamespaces);
			// DOM + signature
			Signer.signObject(signature);
		}
		catch (SignatureException e) {
			throw new TechnicalException(String.format("SignatureException exception: %s", e.getMessage()), e);
		}
	}

	public static String getOriginalIssuerFromAttribute(Attribute attribute) {
		AttributeMap unknownAttributes = attribute.getUnknownAttributes();
		if (unknownAttributes.isEmpty()) {
			return null;
		}
		return unknownAttributes.get(new QName(ORIGINAL_ISSUER_SCHEMA, ORIGINAL_ISSUER, ORIGINAL_ISSUER_NAMESPACE_ALIAS));
	}

	public static String getAttributeValue(Attribute attribute) {
		List<XMLObject> values = attribute.getAttributeValues();
		if (CollectionUtils.isEmpty(values)) {
			log.error("Attribute with name={} has no value(s)", attribute.getName());
			return "";
		}
		var xsString = (XSString) values.get(0);
		return xsString.getValue();
	}

	public static List<String> getAttributeValues(Attribute attribute) {
		List<String> ret = new ArrayList<>();
		for (XMLObject o : attribute.getAttributeValues()) {
			if (o instanceof XSString s) {
				ret.add(s.getValue());
			}
			else if (o instanceof XSBase64Binary bin) {
				ret.add(bin.getValue());
			}
			else if (o instanceof XSBooleanValue bool) {
				ret.add(String.valueOf(bool.getValue()));
			}
			else if (o instanceof XSInteger integer) {
				ret.add(String.valueOf(integer.getValue()));
			}
			else if (o instanceof XSAny any) {
				ret.add(any.getTextContent());
			}
			else {
				throw new TechnicalException("Cannot extract value from type " + o.getClass().getName());
			}
		}
		return ret;
	}

	public static boolean isSignatureValid(Signature signature, List<Credential> credentials) {
		if (credentials == null) {
			return false;
		}
		if (!isSignatureValid(signature, credentials, false)) {
			// no cert match found, re-check with all of them accepting trial warnings
			return isSignatureValid(signature, credentials, true);
		}
		return true;
	}

	private static boolean isSignatureValid(Signature signature, List<Credential> credentials, boolean checkUnknown) {
		return credentials.stream().anyMatch(credential -> {
			try {
				// To get around logging.level.org.apache.xml.security.signature.XMLSignature=ERROR
				// to not have 'WARN: Signature verification failed' we would need to pick the right credential from
				// signature.getSigningCredential returning Credential null so we would need to internalize from KeyInfo.X509Data
				// ourselves handling X509Certificates, X509SKIs and 509IssuerSerials ourselves using complex matcher code...
				if (isSignatureFromCredential(signature, credential) || checkUnknown) {
					SignatureValidator.validate(signature, credential);
					return true;
				}
				return false;
			}
			catch (Exception ex) {
				log.debug("Signature validation failed using signer {}: {}",
						((X509Credential) credential).getEntityCertificate().getSubjectX500Principal(),
						ExceptionUtil.getRootMessage(ex), ex);
				return false;
			}
		});
	}

	public static boolean isRedirectSignatureValid(List<Credential> credentials, String signatureAlgorithm,
			String queryString, byte[] signatureBytes) {
		if (credentials == null) {
			return false;
		}
		var queryStringBytes = queryString.getBytes(StandardCharsets.UTF_8);
		return credentials.stream().anyMatch(credential -> {
			try {
				return validateSignature(credential, signatureAlgorithm, queryStringBytes, signatureBytes);
			}
			catch (TechnicalException ex) {
				log.error("Signature validation failed", ex);
				return false;
			}
		});
	}

	public static boolean validateSignature(Credential credential, String signatureAlgorithm, byte[] queryStringBytes,
			byte[] signatureBytes) {
		try {
			// caller should not pass null here, hence a TechnicalException
			if (signatureAlgorithm == null) {
				throw new TechnicalException("No signature algorithm provided");
			}
			var algorithmId = AlgorithmSupport.getAlgorithmID(signatureAlgorithm);
			if (algorithmId == null) {
				throw new TechnicalException(String.format("Could not find JCE signature algorithm ID for algorithm URI '%s'",
						signatureAlgorithm));
			}
			java.security.Signature sig = java.security.Signature.getInstance(algorithmId);
			sig.initVerify(credential.getPublicKey());
			sig.update(queryStringBytes);
			sig.verify(signatureBytes);
			log.debug("Signature matched for credential {}", credential.getEntityId());
			return true;
		}
		catch (NoSuchAlgorithmException ex) {
			throw new TechnicalException("Unknown signature algorithm", ex);
		}
		catch (InvalidKeyException ex) {
			throw new TechnicalException(
					String.format("Invalid key for signature verification: %s", credential.getEntityId()), ex);
		}
		catch (java.security.SignatureException ex) {
			log.debug("Signature not matched for credential {}", credential.getEntityId());
			return false;
		}
	}

	public static byte[] buildRedirectBindingSignature(Credential credential, String signatureAlgorithm,
			byte[] queryStringBytes) {
		try {
			return XMLSigningUtil.signWithURI(credential, signatureAlgorithm, queryStringBytes);
		}
		catch (SecurityException ex) {
			throw new TechnicalException("SAML redirect signature generation failed", ex);
		}
	}

	public static String encode(XMLObject message) {
		try {
			final var domMessage = marshallMessage(message);
			final var messageXml = SerializeSupport.nodeToString(domMessage);
			return Base64Util.encode(messageXml.getBytes(StandardCharsets.UTF_8), Base64Util.Base64Encoding.UNCHUNKED);
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException(String.format("Message Encoding exception: %s", e.getMessage()), e);
		}
	}

	public static Element marshallMessage(final XMLObject message) throws MessageEncodingException {
		try {
			var marshaller = XMLObjectSupport.getMarshaller(message);
			return marshaller.marshall(message);
		}
		catch (final MarshallingException e) {
			throw new MessageEncodingException("Error marshalling message", e);
		}
	}

	public static void removeNewLinesFromCertificates(Element domDescriptor) {
		NodeList certList = domDescriptor.getElementsByTagName("ds:X509Certificate");
		int nodeListLength = certList.getLength();
		String certValue;
		for (var i = 0; i < nodeListLength; i++) {
			if (certList.item(i).getNodeType() == Node.ELEMENT_NODE) {
				Element cert = (Element) certList.item(i);
				certValue = cert.getTextContent().replace("\n", "");
				cert.setTextContent(certValue);
			}
		}
	}

	public static String getAssertionNameIDFormat(Assertion assertion) {
		if (assertion == null) {
			throw new TechnicalException("Assertion is missing or invalid");
		}
		if (assertion.getSubject() == null) {
			throw new TechnicalException("Assertion has no Subject");
		}
		if (assertion.getSubject().getNameID() == null) {
			throw new TechnicalException("Assertion has no NameId");
		}
		if (assertion.getSubject().getNameID().getFormat() == null) {
			return NameIDType.UNSPECIFIED;
		}
		return assertion.getSubject().getNameID().getFormat();
	}

	public static KeyInfo generateSkiKeyInfo(Credential credential) throws SecurityException {
		var factory = new X509KeyInfoGeneratorFactory();
		factory.setEmitX509SKI(true);
		var generator = factory.newInstance();
		return generator.generate(credential);
	}

	public static boolean isSignatureFromCredential(Signature signature, Credential credential) {
		var ret = true; // let opensaml try it if we cannot find a key/cred match (we get a WARN in the logs only)
		var check = new StringBuilder();
		if (credential instanceof X509Credential x509Credential &&
				signature != null && signature.getKeyInfo() != null
				&& !CollectionUtils.isEmpty(signature.getKeyInfo().getX509Datas())) {
			ret = isSignatureFromCredential(signature, x509Credential, check);
		}
		if (log.isDebugEnabled()) {
			log.debug("Did {}select credential='{}' for signature='{}' based on check='{}'",
					ret ? "" : "NOT ", getKeyInfoHintFromCredential(credential), getKeyInfoHintFromSignature(signature), check);
		}
		return ret;
	}

	private static boolean isSignatureFromCredential(
			Signature signature, X509Credential x509Credential, StringBuilder check) {
		try {
			var x509Datas = signature.getKeyInfo().getX509Datas();
			// we do not expect multiple KeyInfo entries anywhere
			if (!CollectionUtils.isEmpty(x509Datas.get(0).getX509Certificates())) {
				var certificate = getCertificateFromSignature(signature);
				if (certificate != null) { // testing only
					check.append("X509Certificate");
					return x509Credential.getEntityCertificate().equals(certificate);
				}
			}
			if (!CollectionUtils.isEmpty(x509Datas.get(0).getX509SKIs())) {
				var sigSkiEl = x509Datas.get(0).getX509SKIs().get(0);
				if (sigSkiEl != null && sigSkiEl.getValue() != null) {
					var sigSki = Base64.getDecoder().decode(sigSkiEl.getValue().getBytes());
					var certSki = getSkiOid(x509Credential.getEntityCertificate());
					check.append("X509SKI");
					return Arrays.equals(sigSki, certSki);
				}
			}
		}
		catch (Exception ex) {
			check.append(": ").append(ex.getMessage());
		}
		return false; // fail on issuer/serial and subject names
	}

	public static String getKeyInfoHintFromCredential(Credential credential) {
		if (credential instanceof X509Credential cred) {
			return getKeyInfoHintFromCertificate(cred.getEntityCertificate());
		}
		return "CREDENTIAL-EXTRACT-FAILED:No-509Credential";
	}

	// extract SubjectDN of all configured verifier certs
	public static String credentialsToKeyInfo(List<Credential> credentials) {
		if (credentials == null) {
			return "null";
		}
		var sb = new StringBuilder("[");
		var sep = " '";
		for (Credential credential : credentials) {
			sb.append(sep);
			sep = ", '";
			if (credential instanceof X509Credential) {
				sb.append(getKeyInfoHintFromCredential(credential));
			}
			else {
				sb.append(credential.getClass().getName());
			}
			sb.append("'");
		}
		sb.append(" ]");
		return sb.toString();
	}

	// e.g. HexEncode(Base64.decode(signature.getKeyInfo().getX509Datas().get(0).getX509SKIs().get(0)))
	// ...and in the function below the certs need to expose the same information (X509 V.3 SubjectKeyIdentifier)
	// ...and maybe we should only dump the KeyInfo here, the rest of the signature is less interesting.
	public static String getKeyInfoHintFromSignature(Signature signature) {
		// expect key info in the X509 area only
		if (signature == null || signature.getKeyInfo() == null ||
				CollectionUtils.isEmpty(signature.getKeyInfo().getX509Datas())) {
			return null;
		}

		var x509Datas = signature.getKeyInfo().getX509Datas();

		// X509
		if (!CollectionUtils.isEmpty(x509Datas.get(0).getX509Certificates())) {
			// single cert already on the XML-security level so we do not have to PEM decode X509 cert again
			var certificate = getCertificateFromSignature(signature);
			return getKeyInfoHintFromCertificate(certificate);
		}

		// X509SKI
		else if (!CollectionUtils.isEmpty(x509Datas.get(0).getX509SKIs())) {
			var sb = new StringBuilder("[");
			x509Datas.forEach(sd -> sd.getX509SKIs().forEach(ski -> {
				sb.append(Hex.encodeHexString(Base64.getDecoder().decode(ski.getValue().getBytes())));
				sb.append(",");
			}));
			sb.append("]");
			return sb.toString();
		}

		return "KEY-INFO-HINT-UNSUPPORTED";
	}

	private static java.security.cert.X509Certificate getCertificateFromSignature(Signature signature) {
		var signingCredential = signature.getSigningCredential();
		if (signingCredential instanceof X509Credential x509Cred) {
			return x509Cred.getEntityCertificate();
		}
		return null;
	}

	public static String getKeyInfoHintFromCertificate(java.security.cert.X509Certificate certificate) {
		var ret = new StringBuilder("");
		try {
			if (certificate != null) {
				ret.append(certificate.getSubjectX500Principal().toString());
			}
		}
		catch (Exception e) {
			return "SUBJECT-DN-EXTRACT-FAILED: " + e.getMessage();
		}
		ret.append(" SKI=").append(getSkiOidString(certificate));
		if (certificate != null && certificate.getSerialNumber() != null) {
			ret.append(" serial=");
			ret.append(getHexString(certificate.getSerialNumber().toByteArray()));
		}
		return ret.toString();
	}

	public static byte[] getSkiOid(java.security.cert.X509Certificate certificate) {
		var derValue = certificate == null ? null : certificate.getExtensionValue(SKI_OID);
		var ret = new byte[0];
		// We show SKI (Subject Key Identifier and Issuer serial in openssl hex without : separator like in our pems
		// BigInteger.toString(16).toUpperCase() would do here
		final ASN1Primitive ski;
		try {
			if (derValue != null) {
				ski = JcaX509ExtensionUtils.parseExtensionValue(derValue);
				if (ski != null) {
					ret = ((DEROctetString) ski).getOctets();
				}
			}
		}
		catch (Exception e) {
			log.warn("Cannot extract SKI from cert {}", certificate);
		}
		return ret;
	}

	public static String getSkiOidString(java.security.cert.X509Certificate certificate) {
		var ski = getSkiOid(certificate);
		return getHexString(ski);
	}

	public static String getHexString(byte[] input) {
		var hexFormat = HexFormat.ofDelimiter(":").withUpperCase();
		return hexFormat.formatHex(input);
	}

	public static String generateRelayState() {
		// pure random we should use SamlUtil.generateRelayState with randomGenerator.generateIdentifier
		return TraceSupport.getOwnTraceParentForSaml();
	}

	public static List<String> getValuesFromAttribute(Attribute attribute) {
		var values = new ArrayList<String>();
		if (attribute == null || CollectionUtils.isEmpty(attribute.getAttributeValues())) {
			return values;
		}
		for (var attributeValue : attribute.getAttributeValues()) {
			if (attributeValue instanceof XSString xsString) {
				values.add(xsString.getValue());

			}
			if (attributeValue instanceof XSAnyImpl xsAny) {
				values.add(xsAny.getTextContent());
			}
		}
		return values;
	}

	// should not happen, log only an error for now as we do not necessarily use the ID as NcName
	public static boolean validateSessionId(String id, String usage) {
		if (!isValidNcName(id)) {
			log.error("Session ID '{}' ({}) is not a valid NcName!", id, usage);
			return false;
		}
		return true;
	}

	public static boolean isValidNcName(String value) {
		if (StringUtils.isEmpty(value)) {
			return false;
		}
		if (!isValidNcStartingCharacter(value.charAt(0))) {
			return false;
		}
		for (var ii = 1; ii < value.length(); ++ii) {
			if (!isValidNcCharacter(value.charAt(ii))) {
				return false;
			}
		}
		return true;
	}

	// https://www.w3.org/TR/1999/REC-xml-names-19990114/#NT-NCName
	private static boolean isValidNcStartingCharacter(char ch) {
		return Character.isLetter(ch) || ch == '_';
	}

	private static boolean isValidNcCharacter(char ch) {
		// Theoretically an extender is also allowed, but I did not find an easy way to test that in Java (other than checking
		// manually for the characters, which is not maintainable)
		// As we handle IDs here, and only log errors based on this, the chance of hitting that issue is almost zero
		return Character.isLetter(ch) || Character.isDigit(ch) || isValidNcSpecialCharacter(ch) || isCombiningDiacriticMark(ch);
	}

	private static boolean isValidNcSpecialCharacter(char ch) {
		return ch == '.' || ch == '-' || ch == '_';
	}

	private static boolean isCombiningDiacriticMark(char ch) {
		return Character.UnicodeBlock.of(ch).equals(Character.UnicodeBlock.COMBINING_DIACRITICAL_MARKS);
	}

	public static String prependPrefixToRelayState(String relayState) {
		if (!relayState.startsWith(XTB_RELAY_STATE_PREFIX)) {
			relayState = XTB_RELAY_STATE_PREFIX + relayState;
		}
		if (relayState.length() > 80) {
			// opensaml RelayState length limit
			// non-xml-safe identifier is 80 bytes, with the prefix (and _ from XML-safe) we exceed that
			relayState = relayState.substring(0, 80);
		}
		return relayState;
	}

	public static String generateRelayState(String identifier) {
		// XTB prefix to allow recognizing our relay states
		// default is XML-safe (prefixed with _), use that as separator
		var relayState = prependPrefixToRelayState(identifier);
		log.debug("Relay state generated: {}", relayState);
		return relayState;
	}

	// UUIDs can be used as RelayState and we use that again to correlate our session in the StateCache. We therefore have to
	// make sure, we make a valid NCName out of it. This was initially added for the discontinued stealth mode for checking
	// backwards compatibility during migration.
	// For normal processing, this is a bit of an overhead, so we just check for the first char.
	public static String useRelayStateAsSessionId(String relaySate) {
		if (StringUtils.isNotEmpty(relaySate) && !SamlUtil.isValidNcStartingCharacter(relaySate.charAt(0))) {
			relaySate = "FSRS-" + relaySate;
		}
		return relaySate;
	}

	public static void setOriginalIssuerIfMissing(Attribute attribute, String originalIssuer) {
		if (!hasOriginalIssuer(attribute)) {
			setOriginalIssuer(attribute, originalIssuer);
		}
	}

	public static void setOriginalIssuer(Attribute attribute, String originalIssuer) {
		attribute.getUnknownAttributes().put(ORIGINAL_ISSUER_QNAME, originalIssuer);
	}

	public static void removeOriginalIssuer(Attribute attribute) {
		attribute.getUnknownAttributes().remove(ORIGINAL_ISSUER_QNAME);
	}

	public static boolean hasOriginalIssuer(Attribute attribute) {
		return attribute.getUnknownAttributes().containsKey(ORIGINAL_ISSUER_QNAME);
	}

	public static List<Assertion> getResponseAssertions(Response response, List<Credential> decryptionCredentials,
														 boolean requireEncryptedAssertion) {
		List<Assertion> assertions = new ArrayList<>();
		var issuerId = OpenSamlUtil.getMessageIssuerId(response);
		var encryptedAssertions = response.getEncryptedAssertions();
		if (CollectionUtils.isNotEmpty(decryptionCredentials) && CollectionUtils.isEmpty(encryptedAssertions) && requireEncryptedAssertion) {
			throw new TechnicalException(String.format(
					"Decryption of assertions is required for cpIssuer=%s, but the response contains no encrypted assertions: %s",
					issuerId, OpenSamlUtil.samlObjectToString(response)));
		}
		if (CollectionUtils.isNotEmpty(encryptedAssertions)) {
			for (EncryptedAssertion encryptedAssertion : encryptedAssertions) {
				Assertion assertion = EncryptionUtil.decryptAssertion(
						encryptedAssertion, decryptionCredentials, response.getID(), issuerId);
				assertions.add(assertion);
			}
		}
		else {
			assertions = response.getAssertions();
		}
		return assertions;
	}
}
