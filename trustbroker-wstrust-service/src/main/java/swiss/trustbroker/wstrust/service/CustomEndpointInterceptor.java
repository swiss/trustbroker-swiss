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

package swiss.trustbroker.wstrust.service;

import java.io.StringWriter;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.soap.util.SOAPSupport;
import org.opensaml.soap.wsaddressing.Action;
import org.opensaml.soap.wsaddressing.MessageID;
import org.opensaml.soap.wsaddressing.RelatesTo;
import org.opensaml.soap.wsaddressing.ReplyTo;
import org.opensaml.soap.wsaddressing.To;
import org.opensaml.soap.wsaddressing.WSAddressingConstants;
import org.opensaml.soap.wsaddressing.impl.ActionImpl;
import org.opensaml.soap.wssecurity.BinarySecurityToken;
import org.opensaml.soap.wssecurity.Security;
import org.opensaml.soap.wssecurity.Timestamp;
import org.opensaml.soap.wssecurity.WSSecurityConstants;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.opensaml.xmlsec.signature.Signature;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapHeaderElement;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.soap.server.SoapEndpointInterceptor;
import org.springframework.xml.transform.StringSource;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.util.WsTrustUtil;


/**
 * Interceptor handles the SOAP header and extracts the SAML assertion from it to treat it the SAML POST way.
 * We translate the DOM element into an opensaml representation here which asserts that the DOM stack is consistent i.e.
 * we do not get a mess with these implementation variants:
 * - com.sun.xml.messaging.saaj.soap.impl.ElementImpl
 * - com.sun.org.apache.xerces.internal.dom.ElementNSImpl
 */
@Slf4j
@AllArgsConstructor
public class CustomEndpointInterceptor implements SoapEndpointInterceptor {

	private static final String ADDRESSING_HEADER = WSAddressingConstants.WSA_NS;

	private static final List<String> MUSTUND_LOCAL_PART = List.of(Action.ELEMENT_LOCAL_NAME, To.ELEMENT_LOCAL_NAME,
			Security.ELEMENT_LOCAL_NAME);

	private static final List<String> MUSTUND_NAMESPACEURI = List.of(WSAddressingConstants.WSA_NS, WSSecurityConstants.WSSE_NS);

	private final TrustBrokerProperties trustBrokerProperties;

	private final Transformer transformer;

	@Override
	public boolean understands(SoapHeaderElement header) {
		String namespaceURI = header.getName().getNamespaceURI();
		String localPart = header.getName().getLocalPart();

		boolean mustUnderstand = MUSTUND_NAMESPACEURI.contains(namespaceURI) && MUSTUND_LOCAL_PART.contains(localPart);
		if (!mustUnderstand) {
			log.error("Missing 'mustunderstand' attribute in header {}", localPart);
		}
		return mustUnderstand;
	}

	@Override
	public boolean handleRequest(MessageContext messageContext, Object endpoint) {
		var webServiceMessageRequest = messageContext.getRequest();
		var soapMessage = (SoapMessage) webServiceMessageRequest;
		SamlTracer.logSoapObject(String.format(">>>>> Incoming RST SOAP message soap11action='%s'", soapMessage.getSoapAction()),
				soapMessage.getDocument());

		var headerNode = WsTrustUtil.getNode(soapMessage.getSoapHeader());

		SamlTracer.logSoapObject(">>>>> Incoming RST SOAP header", headerNode);

		var bodyNode = WsTrustUtil.getNode(soapMessage.getSoapBody());

		SamlTracer.logSoapObject(">>>>> Incoming RST SOAP body", bodyNode);

		var requestHeader = getRequestHeaderElements(headerNode);
		requestHeader.setSoapAction(soapMessage.getSoapAction());
		requestHeader.setSoapMessage(soapMessage);
		RequestLocalContextHolder.setRequestContext(requestHeader);

		return true;
	}

	private SoapMessageHeader getRequestHeaderElements(Node headerNode) {
		var requestHeader = new SoapMessageHeader();
		var headerChildNodes = headerNode.getChildNodes();
		for (var index = 0; index < headerChildNodes.getLength(); index++) {
			var xmlObject = getXmlObjectFromNode(headerChildNodes, index);
			if (xmlObject == null) {
				continue;
			}
			if (xmlObject instanceof ActionImpl) {
				requestHeader.setAction((Action) xmlObject);
			}
			else if (xmlObject instanceof MessageID messageID) {
				requestHeader.setMessageId(messageID);
			}
			else if (xmlObject instanceof ReplyTo replyTo) {
				requestHeader.setReplyTo(replyTo);
			}
			else if (xmlObject instanceof To to) {
				requestHeader.setTo(to);
			}
			else if (xmlObject instanceof Security security) {
				processSecurityHeader(security, requestHeader);
			}
			else if (log.isErrorEnabled()) {
				log.error("Unknown header xml object with namespace={}: {}",
						xmlObject.getElementQName(), SoapUtil.nodeObjectToString(headerNode));
			}
		}
		return requestHeader;
	}

	private static void processSecurityHeader(Security securityHeader, SoapMessageHeader requestHeader) {
		log.info("Incoming Security header with namespace uri={}", securityHeader.getElementQName());

		List<XMLObject> orderedChildren = securityHeader.getOrderedChildren();
		if (orderedChildren == null) {
			return;
		}
		for (XMLObject xmlObject : orderedChildren) {
			if (xmlObject instanceof Assertion assertion) {
				log.debug("Assertion id={}", assertion.getID());
				if (requestHeader.getAssertion() != null) {
					log.error("SOAP header contains multiple Assertion objects");
				}
				requestHeader.setAssertion(assertion);
			}
			else if (xmlObject instanceof Timestamp timestamp) {
				log.debug("Timestamp created on={}", timestamp.getCreated() != null ? timestamp.getCreated().getValue() : null);
				requestHeader.setRequestTimestamp(timestamp);
			}
			else if (xmlObject instanceof BinarySecurityToken binarySecurityToken) {
				log.debug("BinarySecurityToken is present in the request header");
				requestHeader.setSecurityToken(binarySecurityToken);
			}
			else if (xmlObject instanceof Signature) {
				// The Signature header is handled by SpringWS if configured
				log.debug("Signature object is present in the request header");
				requestHeader.setSignature(xmlObject);
			}
			else if (xmlObject != null) {
				log.error("Unknown security header xml object with namespace={}: {}",
						xmlObject.getElementQName(), OpenSamlUtil.samlObjectToString(securityHeader));
			}
		}
	}

	private XMLObject getXmlObjectFromNode(NodeList headerChildNodes, int index) {
		var node = headerChildNodes.item(index);
		var nodeLocalName = node.getLocalName();
		if (nodeLocalName == null) {
			log.debug("Empty node");
			return null;
		}

		// Allowlist <wsse:Security> header containing SAML assertion or UsernameToken or whatever...
		// We can only handle SAML assertions in the <wsse:Security> for the time being.
		if (trustBrokerProperties.getWstrust() != null && trustBrokerProperties.getWstrust().getSoapHeadersToConsider() != null
				&& !trustBrokerProperties.getWstrust().getSoapHeadersToConsider().contains(nodeLocalName)) {
			log.debug("Incoming SOAP element node={} ignored", nodeLocalName);
			return null;
		}

		if (node instanceof Element element) {
			return unmarshallElement(element);
		}
		else if (log.isErrorEnabled()) {
			log.error("Unexpected xml object of type={}: {}", node.getNamespaceURI(), SoapUtil.nodeObjectToString(node));
		}

		return null;
	}

	public static XMLObject unmarshallElement(Element samlElement) {
		try {
			var unmarshaller = XMLObjectSupport.getUnmarshaller(samlElement);
			if (unmarshaller == null) {
				throw new TechnicalException("No marshaller for the element: " + samlElement.getNamespaceURI());
			}
			return unmarshaller.unmarshall(samlElement);
		}
		catch (UnmarshallingException e) {
			throw new TechnicalException(String.format(
					"UnmarshallingException for element: %s", samlElement.getNamespaceURI()), e);
		}
	}

	@Override
	public boolean handleResponse(MessageContext messageContext, Object endpoint) throws Exception {
		try {
			var webServiceMessageRequest = messageContext.getResponse();
			var soapMessage = (SoapMessage) webServiceMessageRequest;
			var header = soapMessage.getSoapHeader();

			var marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

			//Action header
			StringSource actionHeaderSource = getHeaderSourceString(marshallerFactory, ADDRESSING_HEADER,
					Action.ELEMENT_LOCAL_NAME, createActionHeader(), true);
			transformer.transform(actionHeaderSource, header.getResult());

			//ReplyTo header
			var envRelatesToHeader = createEnvRelatesToHeader();
			if (envRelatesToHeader != null) {
				StringSource relatesToHeaderSource = getHeaderSourceString(marshallerFactory, ADDRESSING_HEADER,
						RelatesTo.ELEMENT_LOCAL_NAME, envRelatesToHeader, false);
				transformer.transform(relatesToHeaderSource, header.getResult());
			}
		}
		finally {
			RequestLocalContextHolder.destroyRequestContext();
		}
		return false;
	}

	private StringSource getHeaderSourceString(MarshallerFactory marshallerFactory, String namespace, String localName,
			XMLObject xmlObject, boolean hasMustUnderstandAttribute) {
		try {
			if (hasMustUnderstandAttribute) {
				addMustUnderstandAttribute(xmlObject, true);
			}
			var element = getElement(marshallerFactory, namespace, localName, xmlObject);
			var elString = getElString(element);
			if (elString == null) {
				throw new TechnicalException("Could not create string for header element");
			}
			return new StringSource(elString);
		}
		catch (MarshallingException e) {
			throw new TechnicalException(String.format("Header marshaller exception for element: %s", namespace), e);
		}
	}

	private static void addMustUnderstandAttribute(XMLObject soapObject, boolean mustUnderstand) {
		SOAPSupport.addSOAP12MustUnderstandAttribute(soapObject, mustUnderstand);
	}

	private static Element getElement(MarshallerFactory marshallerFactory, String namespace, String localName,
			XMLObject xmlObject) throws MarshallingException {
		var marshaller = marshallerFactory.getMarshaller(new QName(namespace, localName));
		if (marshaller == null) {
			throw new TechnicalException(String.format("Marshaller is null for namespace : %s", namespace));
		}
		return marshaller.marshall(xmlObject);
	}

	private String getElString(Element el) {

		var result = new StreamResult(new StringWriter());
		try {
			transformer.transform(new DOMSource(el), result);
			return result.getWriter().toString();
		}
		catch (TransformerException e) {
			throw new TechnicalException("Transformer exception", e);
		}
	}

	@Override
	public boolean handleFault(MessageContext messageContext, Object endpoint) {
		return false;
	}

	@Override
	public void afterCompletion(MessageContext messageContext, Object endpoint, Exception ex) {
		// nothing to do
	}

	public static Action createActionHeader() {
		var action = (Action) XMLObjectSupport.buildXMLObject(Action.ELEMENT_NAME);
		action.setURI(WSTrustConstants.WSA_ACTION_RSTRC_ISSUE_FINAL);
		return action;
	}

	public static RelatesTo createEnvRelatesToHeader() {
		var relatesTo = (RelatesTo) XMLObjectSupport.buildXMLObject(RelatesTo.ELEMENT_NAME);
		relatesTo.setRelationshipType("");

		SoapMessageHeader requestHeader = RequestLocalContextHolder.getRequestContext();
		if (requestHeader.getMessageId() == null) {
			return null;
		}
		relatesTo.setURI(requestHeader.getMessageId().getURI());
		return relatesTo;
	}

}
