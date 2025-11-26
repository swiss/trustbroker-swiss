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

package swiss.trustbroker.wstrustclient.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPException;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.ParserPool;
import org.apache.commons.collections.CollectionUtils;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wsaddressing.EndpointReference;
import org.opensaml.soap.wspolicy.AppliesTo;
import org.opensaml.soap.wstrust.CanonicalizationAlgorithm;
import org.opensaml.soap.wstrust.Claims;
import org.opensaml.soap.wstrust.EncryptionAlgorithm;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RenewTarget;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.TokenType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.ws.client.core.WebServiceMessageCallback;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.ws.transport.http.AbstractHttpComponents5MessageSender;
import org.springframework.ws.transport.http.HttpComponents5ClientFactory;
import org.springframework.ws.transport.http.SimpleHttpComponents5MessageSender;
import org.springframework.xml.transform.StringSource;
import org.w3c.dom.Element;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.wstrustclient.dto.WsTrustRstRequest;
import swiss.trustbroker.wstrustclient.xml.ClaimType;
import swiss.trustbroker.wstrustclient.xml.ClaimTypeImpl;

@Slf4j
public class WsTrustSoapClientBase extends WebServiceGatewaySupport {

	private static final String TOKEN_TYPE_SAML = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

	@Data
	@RequiredArgsConstructor(staticName = "of")
	protected static class MarshallingInfo {

		private final XMLObject xmlObject;

		private final QName qName;

	}

	private final ParserPool parserPool;

	protected WsTrustSoapClientBase(KeystoreProperties trustStoreProperties, String soapProtocolVersion) {
		parserPool = XMLObjectProviderRegistrySupport.getParserPool();
		if (trustStoreProperties != null && trustStoreProperties.getSignerCert() != null) {
			try {
				// wsTemplate configuration needs to be done on init, not during requests!
				var messageSender = createHttpComponentsMessageSender(trustStoreProperties);
				var wsTemplate = getWebServiceTemplate();
				wsTemplate.setMessageSender(messageSender);
				var msgFactory = MessageFactory.newInstance(soapProtocolVersion);
				var saajSoapMessageFactory = new SaajSoapMessageFactory(msgFactory);
				wsTemplate.setMessageFactory(saajSoapMessageFactory);
				ClaimTypeImpl.registerObjectProvider();
			}
			catch (SOAPException ex) {
				throw new TechnicalException("Could not create MessageFactory", ex);
			}
		}
	}

	public XMLObject sendRequestSecurityToken(String url, RequestSecurityToken requestSecToken,
			WebServiceMessageCallback callback) {
		try {
			log.info("Sending soap request to url={}", url);
			var marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
			var requestSecurityTokenQName = new QName(WSTrustConstants.WST_NS, RequestSecurityToken.ELEMENT_LOCAL_NAME);
			var el = getElement(marshallerFactory, MarshallingInfo.of(requestSecToken, requestSecurityTokenQName), null);
			SamlTracer.logSoapObject("===> Outgoing WSTrust SOAP request", el);

			var xml = getElString(el);
			var source = new StreamSource(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

			var responseStream = new ByteArrayOutputStream();
			var result = new StreamResult(responseStream);

			SamlTracer.logSamlObject("===> Outgoing WSTrust request", requestSecToken);
			log.debug("Sending RST to url={}", url);
			var startMs = System.currentTimeMillis();
			var responseReceived = getWebServiceTemplate().sendSourceAndReceiveToResult(url, source, callback, result);
			log.debug("Response received={} in dT={}ms", responseReceived, System.currentTimeMillis() - startMs);
			if (!responseReceived) {
				throw new TechnicalException(String.format("WSTrust request received no response for url=%s ", url));
			}
			var responseBytes = responseStream.toByteArray();
			if (log.isDebugEnabled()) {
				log.debug("Raw response: {}", new String(responseBytes, StandardCharsets.UTF_8));
			}

			var response = XMLObjectSupport.unmarshallFromInputStream(parserPool, new ByteArrayInputStream(responseBytes));
			SamlTracer.logSamlObject("<=== Incoming WSTrust response", response);
			return response;
		}
		catch (Exception ex) {
			throw new TechnicalException(
					String.format("WSTrust request failed on url=%s with message=%s", url, ex.getMessage()), ex);
		}
	}

	protected static StringSource getHeaderSourceString(MarshallerFactory marshallerFactory, String namespace, String localName,
			XMLObject xmlObject) {
		return getHeaderSourceString(marshallerFactory, MarshallingInfo.of(xmlObject, new QName(namespace, localName)),
				Collections.emptyList());
	}

	protected static StringSource getHeaderSourceString(MarshallerFactory marshallerFactory, MarshallingInfo object) {
		return getHeaderSourceString(marshallerFactory, object,
				Collections.emptyList());
	}

	protected static StringSource getHeaderSourceString(MarshallerFactory marshallerFactory, MarshallingInfo object,
			List<MarshallingInfo> childObjects) {
		try {
			var element = getElement(marshallerFactory, object, null);
			for (var child : childObjects) {
				var childElement = getElement(marshallerFactory, child, element);
				element.appendChild(childElement);
			}
			var elString = getElString(element);
			if (elString == null) {
				throw new TechnicalException("Could not create string for header element");
			}
			return new StringSource(elString);
		}
		catch (MarshallingException e) {
			throw new TechnicalException(String.format("Header marshaller exception: %s", e.getMessage()), e);
		}
	}

	private static Element getElement(MarshallerFactory marshallerFactory, MarshallingInfo object, Element parent)
			throws MarshallingException {
		var marshaller = marshallerFactory.getMarshaller(object.getQName());
		if (marshaller == null) {
			throw new TechnicalException("Marshaller is null");
		}
		if (parent != null) {
			return marshaller.marshall(object.getXmlObject(), parent);
		}
		return marshaller.marshall(object.getXmlObject());
	}

	protected static String getElString(Element el) {

		var result = new StreamResult(new StringWriter());
		try {
			createTransformer().transform(new DOMSource(el), result);
			return result.getWriter().toString();
		}
		catch (TransformerException e) {
			throw new TechnicalException(String.format("TransformerException error: %s", e.getMessage()));
		}
	}

	protected static Transformer createTransformer() throws TransformerConfigurationException {
		var transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return transformerFactory.newTransformer();
	}

	public RequestSecurityToken createRequestSecToken(WsTrustRstRequest rstRequest) {
		var requestSecurityToken =
				(RequestSecurityToken) XMLObjectSupport.buildXMLObject(RequestSecurityToken.ELEMENT_NAME);

		if (rstRequest.getRequestType() == null) {
			throw new TechnicalException("Missing RequestType for RST request");
		}
		var requestType = createRequestType(rstRequest.getRequestType());
		requestSecurityToken.getUnknownXMLObjects().add(requestType);

		var tokenType = createTokenType();
		requestSecurityToken.getUnknownXMLObjects().add(tokenType);

		if (rstRequest.getKeyType() != null) {
			var keyType = createKeyType(rstRequest.getKeyType());
			requestSecurityToken.getUnknownXMLObjects().add(keyType);
		}

		if (rstRequest.getAssertion() != null && RequestType.RENEW.equals(rstRequest.getRequestType())) {
			var renewTarget = createRenewTarget(rstRequest.getAssertion());
			requestSecurityToken.getUnknownXMLObjects().add(renewTarget);
		}

		if (CollectionUtils.isNotEmpty(rstRequest.getClaimTypes())) {
			var claimTypesObj = createClaims(rstRequest.getClaimTypes());
			requestSecurityToken.getUnknownXMLObjects().add(claimTypesObj);
		}

		// who sent the message
		var appliesTo = createAppliesTo(rstRequest.getRstAddress());
		requestSecurityToken.getUnknownXMLObjects().add(appliesTo);

		return requestSecurityToken;
	}

	private static AppliesTo createAppliesTo(String rstAddress) {
		var appliesTo = (AppliesTo) XMLObjectSupport.buildXMLObject(AppliesTo.ELEMENT_NAME);
		appliesTo.getUnknownXMLObjects().add(createEndpointReference(rstAddress));
		return appliesTo;
	}

	private static EndpointReference createEndpointReference(String samlRelyingPartyIssuer) {
		var endPointReference = OpenSamlUtil.buildSamlObject(EndpointReference.class, EndpointReference.ELEMENT_NAME);
		endPointReference.setAddress(createEndpointAddress(samlRelyingPartyIssuer));
		return endPointReference;
	}

	private static Address createEndpointAddress(String samlRelyingPartyIssuer) {
		var address = OpenSamlUtil.buildSamlObject(Address.class, Address.ELEMENT_NAME);
		address.setURI(samlRelyingPartyIssuer);
		return address;
	}

	@SuppressWarnings("java:S1144") // later
	private static EncryptionAlgorithm createEncryptionAlgorithm() {
		var encryptionAlgorithm =
				(EncryptionAlgorithm) XMLObjectSupport.buildXMLObject(EncryptionAlgorithm.ELEMENT_NAME);
		encryptionAlgorithm.setURI("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
		return encryptionAlgorithm;
	}

	@SuppressWarnings("java:S1144") // later
	private static CanonicalizationAlgorithm createCanonicalizationAlgorithm() {
		var canonicalizationAlgorithm =
				(CanonicalizationAlgorithm) XMLObjectSupport.buildXMLObject(CanonicalizationAlgorithm.ELEMENT_NAME);
		canonicalizationAlgorithm.setURI("http://www.w3.org/2001/10/xml-exc-c14n#");
		return canonicalizationAlgorithm;
	}

	private static KeyType createKeyType(String keyTypeStr) {
		var keyType = (KeyType) XMLObjectSupport.buildXMLObject(KeyType.ELEMENT_NAME);
		keyType.setURI(keyTypeStr);
		return keyType;
	}

	private static Claims createClaims(List<String> claimTypes) {
		var claims = (Claims) XMLObjectSupport.buildXMLObject(Claims.ELEMENT_NAME);
		claims.setDialect(ClaimType.IDENTITY_NS);
		for (var claimType : claimTypes) {
			claims.getUnknownXMLObjects()
				  .add(createClaimType(claimType));
		}
		return claims;
	}

	private static XMLObject createClaimType(String claimType) {
		var claim = (ClaimType) XMLObjectSupport.buildXMLObject(ClaimType.ELEMENT_NAME);
		claim.setUri(claimType);
		claim.setOptionalBoolean(true);
		return claim;
	}

	private static TokenType createTokenType() {
		var tokenType = (TokenType) XMLObjectSupport.buildXMLObject(TokenType.ELEMENT_NAME);
		tokenType.setURI(TOKEN_TYPE_SAML);
		return tokenType;
	}

	private static RequestType createRequestType(String requestTypeStr) {
		var requestType = (RequestType) XMLObjectSupport.buildXMLObject(RequestType.ELEMENT_NAME);
		requestType.setURI(requestTypeStr);
		return requestType;
	}

	private static RenewTarget createRenewTarget(Assertion assertion) {
		var renewTarget = (RenewTarget) XMLObjectSupport.buildXMLObject(RenewTarget.ELEMENT_NAME);
		renewTarget.setUnknownXMLObject(assertion);
		return renewTarget;
	}

	private static AbstractHttpComponents5MessageSender createHttpComponentsMessageSender(KeystoreProperties trustStoreProperties) {
		var trustStoreFile = trustStoreProperties.getSignerCert();
		try {
			var password = CredentialUtil.processPassword(trustStoreProperties.getPassword());
			var sslContext = SSLContextBuilder.create().loadTrustMaterial(new File(trustStoreFile),
					CredentialUtil.passwordToCharArray(password)).build();
			var socketFactory = new DefaultClientTlsStrategy(sslContext);
			var connectionManager = PoolingHttpClientConnectionManagerBuilder
					.create()
					.setTlsSocketStrategy(socketFactory)
					.build();

			var httpClient = HttpClientBuilder.create()
											  .setConnectionManager(connectionManager)
											  .addRequestInterceptorFirst(new HttpComponents5ClientFactory.RemoveSoapHeadersInterceptor())
											  .build();

			var httpComponentsMessageSender = new SimpleHttpComponents5MessageSender(httpClient);

			log.info("Using truststore={}", trustStoreFile);

			return httpComponentsMessageSender;
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Could not load truststore=%s: %s", trustStoreFile, ex.getMessage()), ex);
		}
	}

}
