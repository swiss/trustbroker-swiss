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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.net.URLBuilder;
import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPArtifactEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;

@Slf4j
public class SamlIoUtil {

	// separate class for thread-safe lazy init
	private static class DocumentBuilderFactoryHolder {

		private static final DocumentBuilderFactory FACTORY;

		static {
			try {
				var factory = DocumentBuilderFactory.newInstance();
				factory.setNamespaceAware(true);
				// option 1 to disable entity resolving
				factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
				// option 2 to disable entity resolving
				factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
				factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
				// option 3 to disable entity resolving
				factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
				factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
				FACTORY = factory;
			}
			catch (ParserConfigurationException ex) {
				throw new TechnicalException(String.format("Could not create factory message=%s", ex.getMessage()), ex);
			}
		}

	}

	// Subclass to let us use the protected deflateAndBase64Encode
	@SuppressWarnings("java:S110") // cannot avoid the long inheritance chain
	private static class SamlRedirectEncoder extends HTTPRedirectDeflateEncoder {

		public String encodeSamlMessage(final SAMLObject message) throws MessageEncodingException {
			return super.deflateAndBase64Encode(message);
		}

		public String generateRedirectUrl(final MessageContext messageContext, final String message, final String url)
				throws MessageEncodingException {
			return super.buildRedirectURL(messageContext, message, url);
		}
	}

	// Subclass to let us use the protected decodeMessage/unmarshalMessage
	@SuppressWarnings("java:S110") // cannot avoid the long inheritance chain
	private static class SamlRedirectDecoder extends HTTPRedirectDeflateDecoder {

		public XMLObject decodeSamlMessage(final String samlMessageEncoded) {
			try (var in = super.decodeMessage(samlMessageEncoded)) {
				return super.unmarshallMessage(in);
			}
			catch (MessageDecodingException | IOException ex) {
				throw new RequestDeniedException("Cannot decode SAML message", ex);
			}
		}
	}

	// Subclass to let us use the protected buildArtifact
	@SuppressWarnings("java:S110") // owed to deep OpenSAML hierarchy
	private static class SamlArtifactEncoder extends HTTPArtifactEncoder {

		private SamlArtifactEncoder(VelocityEngine velocityEngine, SAMLArtifactMap artifactMap) {
			setVelocityEngine(velocityEngine);
			setArtifactMap(artifactMap);
			setPostEncoding(true);
		}

		public String encodeSamlMessage(SAMLObject message, String relayState, String issuer, String destination,
				ArtifactResolutionParameters artifactResolutionParameters) throws MessageEncodingException {
			var context = OpenSamlUtil.createMessageContext(message, null, destination, relayState);
			OpenSamlUtil.initiateArtifactBindingContext(context, issuer, artifactResolutionParameters);
			var artifact = super.buildArtifact(context);
			return Base64Util.encode(artifact.getArtifactBytes(), Base64Util.Base64Encoding.UNCHUNKED);
		}
	}

	public static final String SAML_REQUEST_NAME = "SAMLRequest";

	public static final String SAML_RESPONSE_NAME = "SAMLResponse";

	public static final String SAML_ARTIFACT_NAME = "SAMLart";

	public static final String SAML_RELAY_STATE = "RelayState";

	public static final String SAML_REDIRECT_SIGNATURE = "Signature";

	public static final String SAML_REDIRECT_SIGNATURE_ALGORITHM = "SigAlg";

	private SamlIoUtil() {
	}

	/**
	 * Unmarshalls a SAML AuthnRequest from stream resource into its SAMLObject. <saml2:AuthnRequest/> should result in
	 * org.opensaml.saml.saml2.core.impl.AssertionImpl
	 */
	public static AuthnRequest unmarshallAuthnRequest(InputStream stream) {
		return (AuthnRequest) getXmlObjectFromStream(stream, null);
	}

	/**
	 * Unmarshalls a SAML Response from stream resource into its SAMLObject. <saml2:Response/> results in
	 * org.opensaml.saml.saml2.core.impl.ResponseImpl
	 */
	public static Response unmarshallResponse(InputStream stream) {
		return (Response) getXmlObjectFromStream(stream, null);
	}

	/**
	 * Unmarshalls a SAML Assertion from stream resource into its SAMLObject. <saml2:Assertion/> results in
	 * org.opensaml.saml.saml2.core.impl.AssertionImpl
	 */
	public static Assertion unmarshallAssertion(InputStream stream) {
		return (Assertion) getXmlObjectFromStream(stream, null);
	}

	/**
	 * Unmarshalls a WSTrust token request from stream resource into its SAMLObject. <saml2:Assertion/> results in
	 * org.opensaml.soap.wstrust.impl.RequestSecurityTokenImpl
	 */
	public static RequestSecurityToken unmarshallRequestSecurityToken(InputStream stream) {
		return (RequestSecurityToken) getXmlObjectFromStream(stream, null);
	}

	public static AuthnRequest unmarshallAuthnRequest(String mappingFile) {
		return (AuthnRequest) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	public static LogoutRequest unmarshallLogoutRequest(String mappingFile) {
		return (LogoutRequest) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	public static RequestAbstractType unmarshallRequest(String mappingFile) {
		return (RequestAbstractType) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	public static Response unmarshallResponse(String mappingFile) {
		return (Response) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	public static LogoutResponse unmarshallLogoutResponse(String mappingFile) {
		return (LogoutResponse) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	public static StatusResponseType unmarshallStatusResponse(String mappingFile) {
		return (StatusResponseType) getXmlObjectFromFileOrClassPath(mappingFile);
	}

	@SuppressWarnings("unchecked")
	public static <T> T unmarshallXmlFile(String mappingFile, InputStream stream) {
		return (T) getXmlObjectFromStream(stream, mappingFile);
	}

	public static XMLObject getXmlObjectFromFileOrClassPath(String fileName) {
		var stream = getInputStreamFromFile(fileName);
		return getXmlObjectFromStream(stream, fileName);
	}

	public static InputStream getInputStreamFromFile(String fileName) {
		try {
			InputStream stream;
			var mappingFile = new File(fileName);
			if (mappingFile.exists()) {
				stream = new FileInputStream(mappingFile);
			}
			else {
				stream = SamlIoUtil.class.getClassLoader().getResourceAsStream(fileName);
			}

			if (stream == null) {
				var workingDir = (new File(".")).getAbsolutePath();
				throw new TechnicalException(String.format("Cannot locate file=%s"
						+ " in filesystem or on classpath, workingDir=%s", fileName, workingDir));
			}
			return stream;
		}
		catch (FileNotFoundException ex) {
			throw new TechnicalException(String.format("Cannot locate file=%s", fileName), ex);
		}
	}

	public static Element getDomElementFromStream(InputStream stream, String sourceName) {
		try {
			// parse
			var docBuilder = DocumentBuilderFactoryHolder.FACTORY.newDocumentBuilder();
			var samlDocument = docBuilder.parse(stream);

			return samlDocument.getDocumentElement();
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Unmarshalling XML stream failed from sourceName=%s", sourceName), ex);
		}
		finally {
			// always close
			try {
				stream.close();
			}
			catch (IOException ex) {
				log.error("Could not close stream for sourceName={}", sourceName);
			}
		}
	}

	public static XMLObject getXmlObjectFromStream(InputStream stream, String sourceName) {
		try {
			var element = getDomElementFromStream(stream, sourceName);

			var unmarshaller = XMLObjectSupport.getUnmarshaller(element);

			if (unmarshaller == null) {
				throw new TechnicalException(String.format("Unmarshaller for XMLObject is null for sourceName=%s", sourceName));
			}

			return unmarshaller.unmarshall(element);
		}
		catch(TechnicalException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Unmarshalling XML stream failed from sourceName=%s", sourceName), ex);
		}
	}

	public static XMLObject decodeSamlPostData(String samlPostData) throws IOException {
		byte[] samlPostBytes = Base64.getDecoder().decode(samlPostData.getBytes(StandardCharsets.UTF_8));
		try (var iostream = new ByteArrayInputStream(samlPostBytes)) {
			// decode
			return getXmlObjectFromStream(iostream, "Controller");
		}
	}

	public static String decodeSamlPostDataToString(String samlPostData, boolean prettyPrint) throws IOException {
		var xmlObject = decodeSamlPostData(samlPostData);
		return xmlObjectToString(xmlObject, prettyPrint);
	}

	public static String decodeSamlRedirectDataToString(String sankRedirectData, boolean prettyPrint) {
		var xmlObject = decodeSamlRedirectData(sankRedirectData);
		return xmlObjectToString(xmlObject, prettyPrint);
	}

	public static String encodeSamlRedirectData(final SAMLObject message) {
		try {
			return new SamlRedirectEncoder().encodeSamlMessage(message);
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException("SAML redirect message encoding failed", e);
		}
	}

	public static XMLObject decodeSamlRedirectData(final String message) {
		return new SamlRedirectDecoder().decodeSamlMessage(message);
	}

	public static String generateRedirectUrl(MessageContext messageContext, String message, String url)
			throws MessageEncodingException {
		return new SamlRedirectEncoder().generateRedirectUrl(messageContext, message, url);
	}

	// RequestAbstractType and StatusResponseType both have destination and issuer, but their common base class
	// SignableSAMLObject
	// does not, hence the duplicate encodeSamlArtifactData (and generic methods do not support 'T extends X | Y')

	public static String encodeSamlArtifactData(VelocityEngine velocityEngine, SAMLArtifactMap artifactMap,
			RequestAbstractType message, ArtifactResolutionParameters artifactResolutionParameters,
			String relayState) {
		return encodeSamlArtifactData(velocityEngine, artifactMap, message, message.getIssuer().getValue(),
				message.getDestination(), artifactResolutionParameters, relayState);
	}

	public static String encodeSamlArtifactData(VelocityEngine velocityEngine, SAMLArtifactMap artifactMap,
			StatusResponseType message, ArtifactResolutionParameters artifactResolutionParameters,
			String relayState) {
		return encodeSamlArtifactData(velocityEngine, artifactMap, message, message.getIssuer().getValue(),
				message.getDestination(), artifactResolutionParameters, relayState);
	}

	private static String encodeSamlArtifactData(VelocityEngine velocityEngine, SAMLArtifactMap artifactMap,
			SAMLObject message, String issuer, String destination,
			ArtifactResolutionParameters artifactResolutionParameters, String relayState) {
		try {
			return new SamlArtifactEncoder(velocityEngine, artifactMap)
					.encodeSamlMessage(message, relayState, issuer, destination, artifactResolutionParameters);
		}
		catch (MessageEncodingException ex) {
			throw new TechnicalException(String.format("Message Encoding exception: %s", ex.getMessage()), ex);
		}
	}

	// serialize to a one-liner for log indexing
	public static String xmlObjectToString(XMLObject xmlObject, boolean prettyPrint) {
		if (prettyPrint) {
			return SerializeSupport.prettyPrintXML(xmlObject.getDOM());
		}
		else {
			var out = new ByteArrayOutputStream();
			writeXmlObjectToSteam(xmlObject, out);
			return new String(out.toByteArray(), StandardCharsets.UTF_8);
		}
	}

	public static void writeXmlObjectToSteam(XMLObject xmlObject, OutputStream out) {
		SerializeSupport.writeNode(xmlObject.getDOM(), out);
	}

	private static XMLObject getXmlObjectFromString(String data, String sourceName) {
		return getXmlObjectFromStream(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), sourceName);
	}

	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T getXmlObjectFromString(Class<? extends T> expected, String data,
			String sourceName) {
		if (data == null) {
			return null;
		}
		var xmlObj = getXmlObjectFromString(data, sourceName);
		if (expected.isAssignableFrom(xmlObj.getClass())) {
			return (T) xmlObj;
		}
		throw new TechnicalException(String.format("Message of class=%s", xmlObj.getClass().getName()));
	}

	public static <T extends XMLObject> String marshalXmlObject(T xmlObject) {
		if (xmlObject == null) {
			return null;
		}
		try {
			var out = new ByteArrayOutputStream();
			XMLObjectSupport.getMarshaller(xmlObject).marshall(xmlObject);
			writeXmlObjectToSteam(xmlObject, out);
			return Base64.getEncoder().encodeToString(out.toByteArray());
		}
		catch (MarshallingException ex) {
			throw new TechnicalException(String.format("Could not marshal xmlObject class=%s message=%s",
					xmlObject.getClass().getName(), ex.getMessage()), ex);
		}
	}

	@SuppressWarnings("java:S108")
	public static String getSamlPostDataFromHttpProtocol(HttpServletRequest request, boolean pretty) {
		var samlData = getSamlDataFromHttpProtocol(request);
		if (samlData != null && pretty) {
			try {
				samlData = decodeSamlPostDataToString(samlData, false).replace("\n", "");
			}
			catch (Exception e) {
				// Decoding samlData failed, error logging data as is
			}
		}
		return samlData;
	}

	public static String getSamlRedirectDataFromHttpProtocol(HttpServletRequest request, boolean pretty) {
		var samlData = getSamlDataFromHttpProtocol(request);
		return xmlObjectToString(decodeSamlRedirectData(samlData), pretty);
	}

	public static String getSamlArtifactDataFromHttpProtocol(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		return request.getParameter(SAML_ARTIFACT_NAME);
	}

	public static String getSamlDataFromHttpProtocol(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		var samlData = request.getParameter(SAML_REQUEST_NAME); // SAMLRequest from SAML GET
		if (samlData == null) {
			samlData = request.getParameter(SAML_RESPONSE_NAME); // SAMLResponse from SAML GET
		}
		return samlData;
	}

	public static String buildSamlRedirectQueryString(String sigAlg, boolean request, String encodedSamlMessage,
			String relayState, String signature) {
		URLBuilder urlBuilder;
		try {
			// URL has to be valid, but is not relevant for this method
			urlBuilder = new URLBuilder("https://localhost");
		}
		catch (final MalformedURLException ex) {
			// does not happen
			throw new RequestDeniedException("Invalid URL", ex);
		}
		var queryParams = urlBuilder.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<>(request ? SAML_REQUEST_NAME : SAML_RESPONSE_NAME, encodedSamlMessage));
		if (relayState != null) {
			queryParams.add(new Pair<>(SAML_RELAY_STATE, relayState));
		}
		if (sigAlg != null) {
			queryParams.add(new Pair<>(SAML_REDIRECT_SIGNATURE_ALGORITHM, sigAlg));
		}
		if (signature != null) {
			queryParams.add(new Pair<>(SAML_REDIRECT_SIGNATURE, signature));
		}
		return urlBuilder.buildQueryString();
	}

	public static String buildSignedSamlRedirectQueryString(SAMLObject message, Credential credential, String sigAlg,
			String relayState) {
		var encodedMessage = encodeSamlRedirectData(message);
		var signatureEncoded = buildEncodedSamlRedirectSignature(message, credential, sigAlg, relayState, encodedMessage);
		return buildSamlRedirectQueryString(sigAlg, true, encodedMessage, relayState, signatureEncoded);
	}

	public static String getSamlRedirectSignatureAlgorithmWithDefault(String sigAlg) {
		if (sigAlg == null) {
			return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		}
		return sigAlg;
	}

	public static String buildEncodedSamlRedirectSignature(SAMLObject message, Credential credential, String sigAlg,
			String relayState, String encodedSamlMessage) {
		var request = message instanceof RequestAbstractType;
		sigAlg = getSamlRedirectSignatureAlgorithmWithDefault(sigAlg);
		var query = buildSamlRedirectQueryString(sigAlg, request, encodedSamlMessage, relayState, null);
		var signatureBytes = SamlUtil.buildRedirectBindingSignature(credential, sigAlg, query.getBytes(StandardCharsets.UTF_8));
		return Base64Util.encode(signatureBytes, Base64Util.Base64Encoding.UNCHUNKED);
	}

	// so far used to work around compatibility issues
	public static void overrideUnmarshaller(QName qname, Unmarshaller unmarshaller) {
		var unmarshallerFactory = ConfigurationService.get(XMLObjectProviderRegistry.class).getUnmarshallerFactory();
		var previous = unmarshallerFactory.getUnmarshaller(qname);
		// if any of these exceptions happens, check if this workaround is still needed and if so adapt the QNAME
		if (previous == null) {
			throw new TechnicalException(String.format("Missing Unmarshaller for qname=%s", qname));
		}
		if (!previous.getClass().isAssignableFrom(unmarshaller.getClass())) {
			throw new TechnicalException(String.format("Unexpected Unmarshaller for qname=%s actual=%s expected superclass of=%s",
					qname, previous.getClass().getName(),
					unmarshaller.getClass().getName()));
		}
		unmarshallerFactory.registerUnmarshaller(qname, unmarshaller);
		log.info("Compatibility workarounds registered: replaced previous={} with unmarshaller={} for qname={}",
				previous, unmarshaller, qname);
	}

}
