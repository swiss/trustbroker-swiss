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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class SoapUtil {

	private static final String MECHANISM_TYPE_DOM = "DOM";

	private SoapUtil() { }

	// standard usage: masked oneliners for errors
	public static String nodeObjectToString(final Node node) {
		return nodeObjectToString(node, true, false);
	}

	public static String nodeObjectToString(final Node node, boolean secure) {
		return nodeObjectToString(node, secure, false);
	}

	// advanced usage allowing to have it human-readable and including secrets e.g. in AuthnRequest
	public static String nodeObjectToString(final Node node, boolean secure, boolean prettyPrint) {
		try {
			if (node == null) {
				return null;
			}
			String xmlString;
			if (prettyPrint) {
				xmlString = SerializeSupport.prettyPrintXML(node);
			}
			else {
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				SerializeSupport.writeNode(node, out);
				xmlString = out.toString(StandardCharsets.UTF_8);
			}
			if (secure) {
				xmlString = OpenSamlUtil.replaceSensitiveData(xmlString);
			}

			return xmlString;
		}
		catch (Exception e) {
			log.error("Transforming Node to string failed on " + node, e);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T unmarshallDomElement(Element samlElement) throws UnmarshallingException {
		Unmarshaller unmarshaller = XMLObjectSupport.getUnmarshaller(samlElement);
		if (unmarshaller == null) {
			throw new UnmarshallingException(String.format("No unmarshaller for element: %s %s ",
					samlElement.getNamespaceURI(), samlElement.getLocalName()));
		}
		return (T)unmarshaller.unmarshall(samlElement);
	}

	public static <T extends SAMLObject> T extractSamlObjectFromEnvelope(InputStream inputStream, Class<T> samlObjectClass) {
		var soapRequest = SamlIoUtil.getXmlObjectFromStream(inputStream, "ARP");
		if (!(soapRequest instanceof Envelope envelope)) {
			throw new TechnicalException(
					String.format("Unexpected request of type=%s", soapRequest.getClass().getName()));
		}
		SamlTracer.logSamlObject(">>>>> Incoming SOAP message", envelope);
		var xmlObjects = envelope.getBody().getUnknownXMLObjects();
		if (xmlObjects.size() != 1) {
			throw new TechnicalException(
					String.format("Unexpected request containing xmlObjects=%i != 1", xmlObjects.size()));

		}
		var xmlObject = xmlObjects.get(0);
		if (!samlObjectClass.isAssignableFrom(xmlObject.getClass())) {
			throw new TechnicalException(String.format("Unexpected request of type=%s expected=%s",
					xmlObject.getClass().getName(), samlObjectClass.getName()));
		}
		return samlObjectClass.cast(xmlObject);
	}

	public static void sendSoap11Response(HttpServletResponse response, SAMLObject samlResponse) {
		try {
			var responseEnvelope = buildSoapEnvelope(samlResponse);
			var marshaller = XMLObjectSupport.getMarshaller(responseEnvelope);
			marshaller.marshall(responseEnvelope);
			SamlTracer.logSamlObject("<<<<< Outgoing SOAP message", responseEnvelope);
			sendEnvelope(response, responseEnvelope);
		}
		catch (MarshallingException|IOException ex) {
			throw new TechnicalException(String.format("Could not send response of type=%s ex=%s",
					samlResponse.getClass().getName(), ex.getMessage()), ex);
		}
	}

	private static void sendEnvelope(HttpServletResponse response, Envelope responseEnvelope) throws IOException {
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.TEXT_XML_VALUE);
		SamlIoUtil.writeXmlObjectToSteam(responseEnvelope, response.getOutputStream());
		response.flushBuffer();
	}

	public static Envelope buildSoapEnvelope(SAMLObject samlResponse) {
		var builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		var envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.<Envelope>ensureBuilder(
				Envelope.DEFAULT_ELEMENT_NAME);
		var bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory.<Body>ensureBuilder(Body.DEFAULT_ELEMENT_NAME);
		var responseEnvelope = envBuilder.buildObject();
		var body = bodyBuilder.buildObject();
		responseEnvelope.setBody(body);
		body.getUnknownXMLObjects().add(samlResponse);
		return responseEnvelope;
	}

	private static XMLSignatureFactory createSignatureFactory() {
		return XMLSignatureFactory.getInstance(MECHANISM_TYPE_DOM);
	}

	public static boolean isSignatureValid(Element element, Node signatureNode, List<Credential> trustCredentials) {
		try {
			if (signatureNode == null) {
				log.debug("No signature for element={}", element.getNodeName());
				return false;
			}
			var sigFactory = createSignatureFactory();
			List<String> failedCredentials = new ArrayList<>();
			for (var trustCredential : trustCredentials) {
				var credential = (BasicX509Credential) trustCredential;
				var publicKey = credential.getPublicKey();

				var valContext = new DOMValidateContext(publicKey, signatureNode);

				var signature = sigFactory.unmarshalXMLSignature(valContext);
				if (signature.validate(valContext)) {
					log.debug("Signature validation succeeded on element={} with credential={}",
							element.getNodeName(), credential.getEntityId());
					return true;
				}
				failedCredentials.add(credential.getEntityId());
			}
			log.info("Signature={} not valid for element={} with credentials={}", signatureNode.getNodeName(),
					element.getNodeName(), failedCredentials);
			return false;
		}
		catch (Exception ex) {
			log.info("Could not validate signature of element={} : {}", element.getNodeName(), ex.getMessage(), ex);
			return false;
		}
	}

}
