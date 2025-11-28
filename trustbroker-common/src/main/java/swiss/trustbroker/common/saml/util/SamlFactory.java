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

import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.xml.namespace.QName;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SignatureParameters;

@Slf4j
public class SamlFactory {

	// see santuario-xml-security-java/src/main/resources/security-config.xml for XML-Security definitions

	public static final String XML_SEC_DIGEST_METHOD_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

	public static final String XML_SEC_DIGEST_METHOD_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

	public static final String XML_SEC_DIGEST_METHOD_DEFAULT = XML_SEC_DIGEST_METHOD_SHA256;

	public static final String CLIENT_NAME_TAG = "%clientname%";

	private SamlFactory() {
	}

	public static List<Attribute> filterDuplicatedAttributes(Collection<Attribute> attributes) {
		List<Attribute> result = new ArrayList<>();
		for (Attribute attribute : attributes) {
			if (!attributeInResult(attribute, result)) {
				result.add(attribute);
			}
		}

		return result;
	}

	private static boolean attributeInResult(Attribute attribute, List<Attribute> result) {
		for (Attribute resultAttribute : result) {
			if (resultAttribute.getName().equals(attribute.getName()) && originalAttributeMatch(resultAttribute, attribute) &&
					attributeValueMatch(attribute, resultAttribute)) {
				return true;
			}
		}

		return false;
	}

	private static boolean attributeValueMatch(Attribute attribute, Attribute resultAttribute) {
		List<String> attributeValues = SamlUtil.getAttributeValues(attribute).stream()
				.sorted()
				.toList();
		List<String> resultAttributeValues = SamlUtil.getAttributeValues(resultAttribute).stream()
				.sorted()
				.toList();

		return attributeValues.equals(resultAttributeValues);

	}

	private static boolean originalAttributeMatch(Attribute resultAttribute, Attribute attribute) {
		String originalIssuerFromAttribute = SamlUtil.getOriginalIssuerFromAttribute(attribute);
		String originalIssuerFromResultAttribute = SamlUtil.getOriginalIssuerFromAttribute(resultAttribute);
		if (originalIssuerFromAttribute == null && originalIssuerFromResultAttribute == null) {
			return true;
		}
		else if (originalIssuerFromAttribute == null) {
			return false;
		}
		return originalIssuerFromAttribute.equals(originalIssuerFromResultAttribute);
	}

	public static void signAssertion(Assertion assertion, SignatureParameters signatureParameters) {
		signSignableObject(assertion, signatureParameters);
	}

	public static List<String> attributeValueToStrings(List<XMLObject> attributeValues) {
		if (attributeValues == null || attributeValues.isEmpty()) {
			return Collections.emptyList();
		}
		return attributeValues.stream().map(SamlFactory::xmlObjectToString).toList();
	}

	private static String xmlObjectToString(XMLObject xmlObject) {
		if (xmlObject == null) {
			return null;
		}
		if (xmlObject instanceof XSString xsString) {
			return xsString.getValue();
		}
		log.warn("Object not of type XSString: {}", xmlObject.getClass().getName());
		return OpenSamlUtil.samlObjectToString(xmlObject, true, false);
	}

	public static RequestedAuthnContext createRequestedAuthnContext(Collection<String> contextClasses, String comparison) {
		var requestedAuthnContext = OpenSamlUtil.buildSamlObject(RequestedAuthnContext.class);
		if (contextClasses != null) {
			for (var contextClass : contextClasses) {
				requestedAuthnContext.getAuthnContextClassRefs().add(createAuthnClassRef(contextClass));
			}
		}
		if (comparison != null) {
			requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.valueOf(comparison));
		}
		return requestedAuthnContext;
	}

	// Some recipients care about what we send here, others don't.
	// We also should not pass on what we receive from an IDP but declare our own session state here.
	public static List<AuthnStatement> createAuthnStatements(List<String> classRefs, String sessionIndex,
			Instant sessionNotOnOrAfter, Instant authnInstant) {
		List<AuthnStatement> authnStatements = new ArrayList<>();
		if (classRefs == null) {
			return authnStatements;
		}
		for (var classRef : classRefs) {
			var authnStatement = OpenSamlUtil.buildSamlObject(AuthnStatement.class);
			if (sessionIndex != null) {
				authnStatement.setSessionIndex(sessionIndex);
			}
			// Timestamping this element is required by some recipients.
			authnInstant = (authnInstant == null ? Instant.now() : authnInstant);
			authnStatement.setAuthnInstant(authnInstant);
			authnStatement.setAuthnContext(createAuthnContext(classRef));
			if (sessionNotOnOrAfter != null) {
				authnStatement.setSessionNotOnOrAfter(sessionNotOnOrAfter);
			}
			authnStatements.add(authnStatement);
		}
		return authnStatements;
	}

	public static AuthnContext createAuthnContext(String classRef) {
		var authnContext = OpenSamlUtil.buildSamlObject(AuthnContext.class);
		authnContext.setAuthnContextClassRef(createAuthnClassRef(classRef));
		return authnContext;
	}

	public static AuthnContextClassRef createAuthnClassRef(String classRef) {
		var authnContextClassRef = OpenSamlUtil.buildSamlObject(AuthnContextClassRef.class);
		authnContextClassRef.setURI(classRef);
		return authnContextClassRef;
	}

	public static AttributeStatement createAttributeStatement(Collection<Attribute> attributes) {
		var attributeStatement = OpenSamlUtil.buildSamlObject(AttributeStatement.class);
		attributeStatement.getAttributes().addAll(attributes);
		return attributeStatement;
	}

	public static Attribute createAttribute(String nameUri, String value, String attrOriginIssuer) {
		return createAttribute(nameUri, List.of(value), attrOriginIssuer);
	}

	public static Attribute createAttribute(String nameUri, List<String> values, String attrOriginIssuer) {
		var attribute = OpenSamlUtil.buildSamlObject(Attribute.class);
		attribute.setName(nameUri);
		if (attrOriginIssuer != null) {
			attribute.getUnknownAttributes()
					.put(new QName(
							SamlUtil.ORIGINAL_ISSUER_SCHEMA, SamlUtil.ORIGINAL_ISSUER,
							SamlUtil.ORIGINAL_ISSUER_NAMESPACE_ALIAS), attrOriginIssuer);
		}
		if (values != null) {
			values.forEach(v -> attribute.getAttributeValues().add(createAttributeValue(v)));
		}
		return attribute;
	}

	static XMLObject createAttributeValue(String value) {
		var stringBuilder = new XSStringBuilder();
		var stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		stringValue.setValue(value);
		return stringValue;
	}

	// Namespace was automatically added, and we handle it on Assertion level now
	public static Attribute createResponseAttribute(String name, List<String> values) {
		var attribute = OpenSamlUtil.buildSamlObject(Attribute.class);
		attribute.setName(name); // we use FQ names, we could also use FriendlyName+SchemaLocation (SAML-tracer easier to read)
		attribute.getAttributeValues().addAll(createAttributeValue(values));
		return attribute;
	}

	static List<XMLObject> createAttributeValue(List<String> values) {
		List<XMLObject> xmlObjects = new ArrayList<>();
		for (String value : values) {
			var stringValue = createAttributeValue(value);
			xmlObjects.add(stringValue);
		}
		return xmlObjects;
	}

	public static Conditions createConditions(String audience, long validitySeconds, Instant now) {
		if (now == null) {
			now = Instant.now();
		}
		var conditions = OpenSamlUtil.buildSamlObject(Conditions.class);
		conditions.setNotBefore(now);
		conditions.setNotOnOrAfter(now.plusSeconds(validitySeconds));
		conditions.getAudienceRestrictions().add(createAudienceRestriction(audience));
		return conditions;
	}

	static AudienceRestriction createAudienceRestriction(String audience) {
		var audienceRestriction = OpenSamlUtil.buildSamlObject(AudienceRestriction.class);
		audienceRestriction.getAudiences().add(createAudience(audience));

		return audienceRestriction;
	}

	static Audience createAudience(String aud) {
		var audience = OpenSamlUtil.buildSamlObject(Audience.class);
		audience.setURI(aud);
		return audience;
	}

	public static Subject createSubject(NameID nameId, String authnRequest, String recipient, long validitySeconds, Instant now) {
		var subject = OpenSamlUtil.buildSamlObject(Subject.class);
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(createSubjectConfirmation(authnRequest, recipient, validitySeconds, now));
		return subject;
	}

	static SubjectConfirmation createSubjectConfirmation(String authnRequest, String recipient,
			long validitySeconds, Instant now) {
		var subjectConfirmation = OpenSamlUtil.buildSamlObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		subjectConfirmation.setSubjectConfirmationData(
				createSubjectConfirmationData(authnRequest, recipient, validitySeconds, now));
		return subjectConfirmation;
	}

	static SubjectConfirmationData createSubjectConfirmationData(String authnRequest, String recipient,
			long validitySeconds, Instant now) {
		var subjectConfirmationData = OpenSamlUtil.buildSamlObject(SubjectConfirmationData.class);
		if (authnRequest != null) {
			subjectConfirmationData.setInResponseTo(authnRequest);
		}
		if (now == null) {
			now = Instant.now();
		}
		subjectConfirmationData.setNotOnOrAfter(now.plusSeconds(validitySeconds));
		if (recipient != null) {
			subjectConfirmationData.setRecipient(recipient);
		}
		return subjectConfirmationData;
	}

	public static NameID createNameId(String nameId, String nameIdFormat, String nameQualifier) {
		var nameID = OpenSamlUtil.buildSamlObject(NameID.class);
		nameID.setFormat(nameIdFormat);
		nameID.setValue(nameId);
		if (nameQualifier != null) {
			nameID.setSPNameQualifier(nameQualifier);
		}
		return nameID;
	}

	public static Status createResponseStatus(String statusCodeValue, String message, String nestedStatusCodeValue) {
		var status = OpenSamlUtil.buildSamlObject(Status.class);
		var statusCode = OpenSamlUtil.buildSamlObject(StatusCode.class);
		statusCode.setValue(statusCodeValue);
		status.setStatusCode(statusCode);
		if (message != null) {
			var statusMessage = OpenSamlUtil.buildSamlObject(StatusMessage.class);
			statusMessage.setValue(message);
			status.setStatusMessage(statusMessage);
		}
		if (nestedStatusCodeValue != null) {
			var nestedStatusCode = OpenSamlUtil.buildSamlObject(StatusCode.class);
			nestedStatusCode.setValue(nestedStatusCodeValue);
			statusCode.setStatusCode(nestedStatusCode);
		}
		return status;
	}

	public static Status createResponseStatus(String statusCodeValue) {
		return createResponseStatus(statusCodeValue, null, null);
	}

	private static Signature createSignature(Credential credential,
			String signatureMethodAlgorithm, String canonicalizationAlgo) {
		signatureMethodAlgorithm = signatureMethodAlgorithm != null ? signatureMethodAlgorithm :
				SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		canonicalizationAlgo = canonicalizationAlgo != null ? canonicalizationAlgo :
				SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
		var signature = OpenSamlUtil.buildSamlObject(Signature.class);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(signatureMethodAlgorithm);
		signature.setCanonicalizationAlgorithm(canonicalizationAlgo);
		signature.setSchemaLocation(SignatureConstants.XMLSIG_NS);
		signature.setKeyInfo(createKeyInfo(credential));
		return signature;
	}

	public static void createSignatureReference(SignableSAMLObject xmlObject, Signature signature, String digestMethod) {
		// add support for everything else than the opensaml default http://www.w3.org/2001/04/xmlenc#sha256
		if (digestMethod != null) {
			var signRef = new SAMLObjectContentReference(xmlObject);
			signRef.setDigestAlgorithm(digestMethod);
			signature.getContentReferences().add(signRef);
		}

		// add the reference
		xmlObject.setSignature(signature);
	}

	public static Signature prepareSignableObject(SignableSAMLObject xmlObject, SignatureParameters signatureParameters) {
		return prepareSignableObject(xmlObject, signatureParameters.getCredential(),
				signatureParameters.getSignatureAlgorithm(), signatureParameters.getCanonicalizationAlgorithm(),
				signatureParameters.getDigestMethod());
	}

	public static Signature prepareSignableObject(SignableSAMLObject xmlObject, Credential credential,
			String signatureMethodAlgorithm, String canonicalizationAlgo, String digestMethod) {
		var signature = createSignature(credential, signatureMethodAlgorithm, canonicalizationAlgo);
		createSignatureReference(xmlObject, signature, digestMethod);
		return signature;
	}

	// dig out the keyinfo factory matching the credential
	public static KeyInfo createKeyInfo(Credential credential) {
		try {
			KeyInfoGeneratorFactory keyInfoGeneratorFactory = getKeyInfoGeneratorFactory(credential, false);
			var keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
			return keyInfoGenerator.generate(credential);
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Failed to create KeyInfo with credential=%s: %s",
					(credential != null ? credential.getEntityId() : null), e.getMessage()), e);
		}
	}

	public static KeyInfoGeneratorFactory getKeyInfoGeneratorFactory(Credential credential, boolean emitSki) {
		var secConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
		var namedKeyInfoGeneratorManager = secConfiguration.getDataKeyInfoGeneratorManager();
		if (namedKeyInfoGeneratorManager == null) {
			throw new TechnicalException("KeyInfoGeneratorManager is null");
		}
		var keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		var keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
		if (emitSki) {
			if (keyInfoGeneratorFactory instanceof X509KeyInfoGeneratorFactory x509Factory) {
				x509Factory.setEmitX509SKI(true);
				x509Factory.setEmitEntityCertificate(false);
			}
			else {
				log.info("KeyInfoGeneratorFactory={} is not a X509KeyInfoGeneratorFactory - cannot emit SKI",
						keyInfoGeneratorFactory.getClass().getName());
			}
		}
		return keyInfoGeneratorFactory;
	}

	public static Issuer createIssuer(String spEntity) {
		var issuer = OpenSamlUtil.buildSamlObject(Issuer.class);
		issuer.setValue(spEntity);
		return issuer;
	}

	public static NameIDPolicy createNameIdPolicy(String nameIdFormat) {
		var nameIdPolicy = OpenSamlUtil.buildSamlObject(NameIDPolicy.class);
		nameIdPolicy.setFormat(nameIdFormat);
		nameIdPolicy.setAllowCreate(true);
		return nameIdPolicy;
	}

	public static Scoping createScoping(String requestorId) {
		var scoping = OpenSamlUtil.buildSamlObject(Scoping.class);
		var requester = OpenSamlUtil.buildSamlObject(RequesterID.class);
		requester.setURI(requestorId);
		scoping.getRequesterIDs().add(requester);
		return scoping;
	}

	public static X509Data createX509Certificate(Credential credential) {
		if (credential == null) {
			return null;
		}

		X509Data data = OpenSamlUtil.buildSamlObject(X509Data.class);
		X509Certificate cert = OpenSamlUtil.buildSamlObject(X509Certificate.class);
		String value;
		try {
			BasicX509Credential x509Credential = (BasicX509Credential) credential;
			value = new String(Base64.getEncoder().encode(x509Credential.getEntityCertificate().getEncoded()));
		}
		catch (CertificateEncodingException e) {
			throw new TechnicalException(String.format("Error while encoding the certificate: %s", e.getMessage()), e);
		}
		cert.setValue(value);

		return data;
	}

	public static String replaceClientNameInUri(String nameURI, String clientName) {
		var nameUriLowerCase = nameURI.toLowerCase();
		while (nameUriLowerCase.contains(CLIENT_NAME_TAG)) {
			int start = nameUriLowerCase.indexOf(CLIENT_NAME_TAG);
			int end = start + CLIENT_NAME_TAG.length();
			nameURI = nameURI.substring(0, start) + clientName + nameURI.substring(end);
			nameUriLowerCase = nameURI.toLowerCase();
		}

		return nameURI;
	}

	// StatusResponseType and RequestAbstractType independently define the same accessors hence the duplicated code

	public static <T extends StatusResponseType> T createResponse(Class<T> responseClass, String issuer) {
		var response = OpenSamlUtil.buildSamlObject(responseClass);
		response.setConsent(RequestAbstractType.UNSPECIFIED_CONSENT);
		response.setIssueInstant(Instant.now());
		response.setID(OpenSamlUtil.generateSecureRandomId());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(SamlFactory.createIssuer(issuer));
		return response;
	}

	public static <T extends RequestAbstractType> T createRequest(Class<T> requestClass, String issuer) {
		var response = OpenSamlUtil.buildSamlObject(requestClass);
		response.setConsent(RequestAbstractType.UNSPECIFIED_CONSENT);
		response.setIssueInstant(Instant.now());
		response.setID(OpenSamlUtil.generateSecureRandomId());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(SamlFactory.createIssuer(issuer));
		return response;
	}

	public static LogoutRequest createLogoutRequest(String issuer, String destination, NameID nameId) {
		var logoutRequest = SamlFactory.createRequest(LogoutRequest.class, issuer);
		if (nameId != null) {
			// need to copy as we cannot have add the same object to multiple DOMs
			nameId = SamlFactory.createNameId(nameId.getValue(), nameId.getFormat(), nameId.getSPNameQualifier());
			logoutRequest.setNameID(nameId);
		}
		logoutRequest.setDestination(destination);
		return logoutRequest;
	}

	public static void signSignableObject(SignableSAMLObject signableSAMLObject, SignatureParameters signatureParameters) {
		var signature = prepareSignableObject(signableSAMLObject, signatureParameters);
		SamlUtil.signSamlObject(signableSAMLObject, signature, signatureParameters.getSkinnyAssertionNamespaces());
	}

	public static ArtifactResponse createArtifactResponse(ArtifactResolve artifactResolve, Optional<SAMLObject> message,
			String issuer) {
		var artifactResponse = OpenSamlUtil.buildSamlObject(ArtifactResponse.class);
		artifactResponse.setMessage(message.orElse(null));
		artifactResponse.setDestination(artifactResolve.getIssuer().getValue());
		artifactResponse.setInResponseTo(artifactResolve.getID());
		artifactResponse.setID("_" + UUID.randomUUID());
		artifactResponse.setIssueInstant(Instant.now());
		artifactResponse.setIssuer(SamlFactory.createIssuer(issuer));
		var statusCode = message.isPresent() ? StatusCode.SUCCESS : StatusCode.RESOURCE_NOT_RECOGNIZED;
		artifactResponse.setStatus(SamlFactory.createResponseStatus(statusCode));
		return artifactResponse;
	}

	public static ArtifactResolve createArtifactResolve(Artifact artifact, String issuer, String destination) {
		var artifactResolve = OpenSamlUtil.buildSamlObject(ArtifactResolve.class);
		artifactResolve.setArtifact(artifact);
		artifactResolve.setDestination(destination);
		artifactResolve.setID("_" + UUID.randomUUID());
		artifactResolve.setIssueInstant(Instant.now());
		artifactResolve.setIssuer(SamlFactory.createIssuer(issuer));
		return artifactResolve;
	}

	public static Artifact createArtifact(String artifactId) {
		var artifact = OpenSamlUtil.buildSamlObject(Artifact.class);
		artifact.setValue(artifactId);
		return artifact;
	}
}
