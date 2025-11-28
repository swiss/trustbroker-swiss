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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.Resolver;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.XMLConstants;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.encoder.servlet.AbstractHttpServletResponseMessageEncoder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.common.binding.artifact.impl.BasicSAMLArtifactMap;
import org.opensaml.saml.common.binding.artifact.impl.StorageServiceSAMLArtifactMap;
import org.opensaml.saml.common.messaging.context.SAMLArtifactContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.SAMLArtifactMetadataIndex;
import org.opensaml.saml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPArtifactDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.BaseSAML2MessageEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPArtifactEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Evidentiary;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.soap.client.SOAPClientException;
import org.opensaml.soap.client.http.HttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.storage.StorageService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.CollectionUtils;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.dto.ArtifactPeer;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.common.saml.dto.SignatureValidationParameters;
import swiss.trustbroker.common.util.HttpUtil;

@Slf4j
public class OpenSamlUtil {

	private record EntityIdResolver(QName peerRole, String issuerId) implements Resolver<String, CriteriaSet> {

		// criteria are ignored as this class is only used in the known context

		@Nonnull
		@Override
		public Iterable<String> resolve(@Nullable CriteriaSet criteria) {
			log.debug("Resolve for peerRole={} issuerId={} criteria={}", peerRole, issuerId, criteria);
			return List.of(issuerId);
		}

		@Nullable
		@Override
		public String resolveSingle(@Nullable CriteriaSet criteria) {
			log.debug("Resolve single for peerRole={} issuerId={} criteria={}", peerRole, issuerId, criteria);
			return issuerId;
		}
	}

	private static class StaticMetaDataResolver implements MetadataResolver {

		private final String id;

		private final EntityDescriptor artifactService;

		private StaticMetaDataResolver(String id, String artifactResolutionUrl, int artifactResolutionIndex) {
			this.id = id;
			artifactService = new EntityDescriptorBuilder()
					.buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
			artifactService.setEntityID(id + "Entity");
			artifactService.getRoleDescriptors()
						   .add(buildSpssoDescriptor(artifactResolutionUrl, artifactResolutionIndex));
			artifactService.getRoleDescriptors()
						   .add(buildIdpssoDescriptor(artifactResolutionUrl, artifactResolutionIndex));
		}

		private static IDPSSODescriptor buildIdpssoDescriptor(String artifactResolutionUrl, int artifactResolutionIndex) {
			var idpDescriptor = OpenSamlUtil.buildSamlObject(IDPSSODescriptor.class);
			idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
			idpDescriptor.getArtifactResolutionServices()
						 .add(
								 buildArtifactResolutionService(artifactResolutionUrl, artifactResolutionIndex));
			return idpDescriptor;
		}

		private static SPSSODescriptor buildSpssoDescriptor(String artifactResolutionUrl, int artifactResolutionIndex) {
			var spssoDescriptor = OpenSamlUtil.buildSamlObject(SPSSODescriptor.class);
			spssoDescriptor.setAuthnRequestsSigned(true);
			spssoDescriptor.setWantAssertionsSigned(true);
			spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
			spssoDescriptor.getArtifactResolutionServices()
						   .add(
								   buildArtifactResolutionService(artifactResolutionUrl, artifactResolutionIndex));
			return spssoDescriptor;
		}

		private static ArtifactResolutionService buildArtifactResolutionService(
				String artifactResolutionUrl, int artifactResolutionIndex) {
			var artifactResolutionService = OpenSamlUtil.buildSamlObject(ArtifactResolutionService.class);
			artifactResolutionService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
			artifactResolutionService.setLocation(artifactResolutionUrl);
			artifactResolutionService.setIndex(artifactResolutionIndex);
			return artifactResolutionService;
		}

		@Nullable
		@Override
		public String getType() {
			return this.getClass().getSimpleName(); // for logging
		}

		@Override
		public boolean isRequireValidMetadata() {
			return false;
		}

		@Override
		public void setRequireValidMetadata(boolean requireValidMetadata) {
			// unused
		}

		@Nullable
		@Override
		public MetadataFilter getMetadataFilter() {
			return null;
		}

		@Override
		public void setMetadataFilter(@Nullable MetadataFilter newFilter) {
			// unused

		}

		@Nullable
		@Override
		public String getId() {
			return id;
		}

		// criteria are ignored as this class is only used in the known context

		@Nonnull
		@Override
		public Iterable<EntityDescriptor> resolve(@Nullable CriteriaSet criteria) {
			return List.of(artifactService);
		}

		@Nullable
		@Override
		public EntityDescriptor resolveSingle(@Nullable CriteriaSet criteria) {
			return artifactService;
		}
	}

	// Workarounds for HttpSOAPClient issues - this depends on the OpenSaml version:
	// 1) HTTPArtifactDecoder.dereferenceArtifact reads InboundMessageContext.message which is not populated by HttpSOAPClient
	// 2) HTTPArtifactDecoder.dereferenceArtifact fails with the default ChildContextLookup because of missing SOAP context
	// (can be handled with createContext = true) / missing envelope in SOAP context
	// HttpSOAPClient is deprecated, to be replaced with e.g. PipelineFactoryHttpSOAPClient - this will need some refactoring:
	@SuppressWarnings("deprecation")
	private static class UnwrappingHttpSoapClient extends HttpSOAPClient {

		private final Optional<SignatureParameters> signatureParameters;

		private final SignatureValidationParameters signatureValidationParameters;

		private UnwrappingHttpSoapClient(Optional<SignatureParameters> signatureParameters,
				SignatureValidationParameters signatureValidationParameters) {
			this.signatureParameters = signatureParameters;
			this.signatureValidationParameters = signatureValidationParameters;
		}

		@Override
		protected void processSuccessfulResponse(@Nonnull ClassicHttpResponse httpResponse,
				@Nonnull InOutOperationContext context)
				throws SOAPClientException {
			super.processSuccessfulResponse(httpResponse, context);
			storeBodyContentInContext(context);
		}

		private void storeBodyContentInContext(InOutOperationContext context) {
			var inboundMessageContext = context.getInboundMessageContext();
			var envelope = getEnvelope(inboundMessageContext);
			if (envelope == null) {
				log.debug("Cannot store body content in Context");
				return;
			}
			SamlTracer.logSamlObject(">>>>> Incoming SOAP message", envelope);
			if (inboundMessageContext.getMessage() == null) {
				var body = envelope.getBody();
				if (body != null && !CollectionUtils.isEmpty(body.getUnknownXMLObjects())) {
					var message = body.getUnknownXMLObjects().get(0);
					inboundMessageContext.setMessage(message);
					log.debug("Unwrapped message={} from body", message.getClass().getName());
					if (message instanceof ArtifactResponse artifactResponse) {
						validateArtifactResponseSignature(artifactResponse);
					}
				}
			}
		}

		private Envelope getEnvelope(MessageContext inboundMessageContext) {
			if (inboundMessageContext != null) {
				var subcontext = inboundMessageContext.getSubcontext(SOAP11Context.class);
				if (subcontext != null) {
					return subcontext.getEnvelope();
				}
				else {
					log.debug("Subcontext is null. Cannot get Envelope");
				}
			}
			return null;
		}

		@Override
		public void send(@Nonnull String endpoint, @Nonnull InOutOperationContext context)
				throws SOAPException, SecurityException {
			if (context.getOutboundMessageContext()
					   .getMessage() instanceof ArtifactResolve artifactResolve) {
				ensureArtifactResolveIsSigned(artifactResolve);
			}
			prepareSoapContext(context);
			super.send(endpoint, context);
		}

		private static void prepareSoapContext(InOutOperationContext context) {
			var outboundContext = context.getOutboundMessageContext();
			if (outboundContext != null) {
				var soapContext = outboundContext.ensureSubcontext(SOAP11Context.class);
				if (soapContext.getEnvelope() == null) {
					log.debug("Creating missing SOAP envelope in outboundContext={}", outboundContext);
					try {
						var encoder = new HttpClientRequestSOAP11Encoder();
						encoder.setMessageContext(outboundContext);
						encoder.prepareContext();
					}
					catch (MessageEncodingException ex) {
						throw new TechnicalException(String.format("Cannot encode context=%s ex=%s", context, ex.getMessage()),
								ex);
					}
				}
				SamlTracer.logSamlObject("<<<<< Outgoing SOAP message", soapContext.getEnvelope());
			}
		}

		private void ensureArtifactResolveIsSigned(ArtifactResolve artifactResolve) {
			if (artifactResolve.isSigned()) {
				log.debug("ArtifactResolve is already signed");
				return;
			}
			if (signatureParameters.isEmpty()) {
				log.debug("No signature required for ArtifactResolve");
				return;
			}
			// the message is built in HttpArtifactEncoder.buildArtifactResolveRequestMessage with no option to sign it
			// as it is sent on a back-channel signing is not crucial, mTLS could guarantee authenticity
			SamlFactory.signSignableObject(artifactResolve, signatureParameters.get());
			log.debug("Signed ArtifactResolve messageId={} credential={}", artifactResolve.getID(),
					signatureParameters.get()
									   .getCredential());
		}

		private void validateArtifactResponseSignature(ArtifactResponse artifactResponse) {
			if (log.isDebugEnabled()) {
				log.debug("ArtifactResponse statusCode={} nestedStatusCode={} statusMessage=\"{}\"",
						getStatusCode(artifactResponse), getNestedStatusCode(artifactResponse),
						getStatusMessage(artifactResponse));
			}
			if (artifactResponse.isSigned()) {
				var credentials = signatureValidationParameters.getTrustCredentials();
				if (CollectionUtils.isEmpty(credentials) && !signatureValidationParameters.isRequireSignature()) {
					// For SAML mock / test, in XTB we should always have trust credentials
					log.warn("Accepting signed artifactResponseId={} without signature check due to missing trust credentials",
							artifactResponse.getID());
					return;
				}
				var signature = artifactResponse.getSignature();
				if (!SamlUtil.isSignatureValid(signature, credentials)) {
					throw new RequestDeniedException(String.format(
							"SAML Signature validation failed using signer='%s' using configured verifiers='%s'. Message "
									+ "details: %s",
							SamlUtil.getKeyInfoHintFromSignature(signature),
							SamlUtil.credentialsToKeyInfo(credentials),
							OpenSamlUtil.samlObjectToString(artifactResponse)));
				}
				log.debug("Signature validated on artifactResponseId={}", artifactResponse.getID());
			}
			else if (signatureValidationParameters.isRequireSignature()) {
				throw new RequestDeniedException(String.format("ArtifactResponseId=%s is not signed. Message details: %s",
						artifactResponse.getID(), OpenSamlUtil.samlObjectToString(artifactResponse)));
			}
		}
	}

	public static final String SKINNY_NO_TYPE = "no-type";

	public static final String SKINNY_ALL = "a," + SKINNY_NO_TYPE; // add xsi and remove no-type to be fully opensaml compliant

	private OpenSamlUtil() {
	}

	// Default behavior to have xmlns:xsi and xmlns:a on Assertion
	public static Assertion buildAssertionObject() {
		return buildAssertionObject(SKINNY_ALL);
	}

	public static Assertion buildAssertionObject(String skinnyXmlns) {
		var assertion = buildSamlObject(Assertion.class);
		// Pull up xsi:type and a:OriginalIssuer xmlns definitions to Assertion to save on message size
		if (skinnyXmlns != null) {
			if (skinnyXmlns.contains(XMLConstants.XSI_PREFIX)) {
				assertion.getNamespaceManager()
						 .registerNamespaceDeclaration(
								 new Namespace(XMLConstants.XSI_NS, XMLConstants.XSI_PREFIX));
			}
			if (skinnyXmlns.contains(SamlUtil.ORIGINAL_ISSUER_NAMESPACE_ALIAS)) {
				assertion.getNamespaceManager()
						 .registerNamespaceDeclaration(
								 new Namespace(SamlUtil.ORIGINAL_ISSUER_SCHEMA, SamlUtil.ORIGINAL_ISSUER_NAMESPACE_ALIAS));
			}
		}
		return assertion;
	}

	public static <T> T buildSamlObject(final Class<T> clazz) {
		try {
			var defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME")
												  .get(null);
			return buildSamlObject(clazz, defaultElementName);
		}
		catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}
		catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object, No such a field");
		}
	}

	@SuppressWarnings({ "RSPEC-1172", "unchecked" }) // class is needed to determine the return type
	public static <T> T buildSamlObject(final Class<T> clazz, final QName elementName) {
		var builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		return (T) builderFactory.getBuilder(elementName)
								 .buildObject(elementName);
	}

	public static String getMessageIssuerId(SAMLObject samlObject) {
		if (samlObject instanceof RequestAbstractType request && request.getIssuer() != null) {
			return request.getIssuer().getValue();
		}
		if (samlObject instanceof StatusResponseType response && response.getIssuer() != null) {
			return response.getIssuer().getValue();
		}
		return null;
	}

	public static String generateSecureRandomId() {
		var secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
		return secureRandomIdGenerator.generateIdentifier();
	}

	// standard usage: masked oneliners for errors
	public static String samlObjectToString(final XMLObject object) {
		return samlObjectToString(object, true, false);
	}

	public static String samlObjectToString(final XMLObject object, boolean secure) {
		return samlObjectToString(object, secure, false);
	}

	// advanced usage allowing to have it human-readable and including secrets e.g. in AuthnRequest
	public static String samlObjectToString(final XMLObject object, boolean secure, boolean prettyPrint) {
		try {
			// preprocess
			if (object == null) {
				return null;
			}
			Element element;
			if (object.getDOM() != null) {
				element = object.getDOM();
			}
			else {
				log.debug("Marshalling of SAML object for logging can have side effect on message content");
				var marshaller = XMLObjectSupport.getMarshaller(object);
				marshaller.marshall(object);
				element = object.getDOM();
			}
			return domObjectToString(element, secure, prettyPrint);
		}
		catch (Exception e) {
			log.error("Transforming XMLObject to string failed on " + object, e);
		}
		return null;
	}

	public static String domObjectToString(Element element) {
		return domObjectToString(element, true, false);
	}

	public static String domObjectToString(Element element, boolean secure, boolean prettyPrint) {
		try {
			if (element == null) {
				return null;
			}
			// externalize xml
			String xmlString;
			if (prettyPrint) {
				xmlString = SerializeSupport.prettyPrintXML(element);
			}
			else {
				var out = new ByteArrayOutputStream();
				SerializeSupport.writeNode(element, out);
				xmlString = out.toString(StandardCharsets.UTF_8)
							   .replaceAll("\n\\s*", "");
			}

			// mask out secrets
			if (secure) {
				xmlString = replaceSensitiveData(xmlString);
			}

			return xmlString;
		}
		catch (Exception e) {
			log.error("Transforming Element to string failed on " + element, e);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T findChildObjectByQname(List<XMLObject> childObjects, QName qName) {
		for (XMLObject xmlObject : childObjects) {
			if (xmlObject.getElementQName().equals(qName)) {
				return (T) xmlObject;
			}
		}
		return null;
	}

	public static void encodeSamlPostMessage(HttpServletResponse httpServletResponse, MessageContext context,
			VelocityEngine velocityEngine, HTTPPostEncoder encoder) {
		encoder = configureSamlPostEncoder(httpServletResponse, context, velocityEngine, encoder);
		encodeSamlMessage(encoder);
	}

	public static <T extends BaseSAML2MessageEncoder> void encodeSamlRedirectMessage(HttpServletResponse httpServletResponse,
			MessageContext context, T encoder) {
		encoder = configureSamlRedirectEncoder(httpServletResponse, context, encoder);
		encodeSamlMessage(encoder);
	}

	public static void encodeSamlSoapMessage(HttpServletResponse httpServletResponse, MessageContext context) {
		var encoder = createSamlSoapEncoder(httpServletResponse, context);
		encodeSamlMessage(encoder);
	}

	@SuppressWarnings("unchecked")
	public static <T extends BaseSAML2MessageEncoder> T configureSamlRedirectEncoder(HttpServletResponse httpServletResponse,
			MessageContext context, T encoder) {
		if (encoder == null) {
			encoder = (T) new HTTPRedirectDeflateEncoder();
		}
		encoder.setMessageContext(context);
		encoder.setHttpServletResponseSupplier(() -> httpServletResponse);
		return encoder;
	}

	@SuppressWarnings("unchecked")
	public static <T extends HTTPPostEncoder> T configureSamlPostEncoder(HttpServletResponse httpServletResponse,
			MessageContext context, VelocityEngine velocityEngine, T encoder) {
		if (encoder == null) {
			encoder = (T) new NonFlushingHttpPostEncoder();
		}
		encoder.setMessageContext(context);
		encoder.setHttpServletResponseSupplier(() -> httpServletResponse);
		encoder.setVelocityEngine(velocityEngine);
		return encoder;
	}

	public static HTTPArtifactEncoder createSamlArtifactEncoder(HttpServletResponse httpServletResponse,
			MessageContext context, VelocityEngine velocityEngine,
			SAMLArtifactMap artifactMap) {
		var encoder = new HTTPArtifactEncoder();
		encoder.setPostEncoding(true);
		encoder.setVelocityEngine(velocityEngine);
		encoder.setArtifactMap(artifactMap);
		initEncoder(encoder, httpServletResponse, context);
		return encoder;
	}

	public static HTTPSOAP11Encoder createSamlSoapEncoder(HttpServletResponse httpServletResponse, MessageContext context) {
		var encoder = new HTTPSOAP11Encoder();
		initEncoder(encoder, httpServletResponse, context);
		try {
			encoder.prepareContext();
		}
		catch (MessageEncodingException ex) {
			throw new TechnicalException(String.format("Cannot encode context=%s ex=%s", context, ex.getMessage()), ex);
		}
		return encoder;
	}

	private static void initEncoder(AbstractHttpServletResponseMessageEncoder encoder, HttpServletResponse httpServletResponse,
			MessageContext context) {
		encoder.setHttpServletResponseSupplier(() -> httpServletResponse);
		encoder.setMessageContext(context);
	}

	public static void initAndEncodeSamlArtifactMessage(HttpServletResponse httpServletResponse,
			MessageContext context, String issuerId, VelocityEngine velocityEngine,
			ArtifactResolutionParameters artifactResolutionParameters, SAMLArtifactMap artifactMap) {
		initiateArtifactBindingContext(context, issuerId, artifactResolutionParameters);
		encodeSamlArtifactMessage(httpServletResponse, context, velocityEngine, artifactMap);
	}

	public static void encodeSamlArtifactMessage(HttpServletResponse httpServletResponse,
			MessageContext context, VelocityEngine velocityEngine, SAMLArtifactMap artifactMap) {
		var encoder = createSamlArtifactEncoder(httpServletResponse, context, velocityEngine, artifactMap);
		// Content type is not set by the artifact encoder, if the status is OK after encode, it must have produced an HTML page.
		// But we have to set it in advance, after encode as the status may already have been flushed to the client.
		httpServletResponse.setContentType(MediaType.TEXT_HTML_VALUE);
		encodeSamlMessage(encoder);
	}

	private static void encodeSamlMessage(AbstractHttpServletResponseMessageEncoder encoder) {
		try {
			encoder.initialize();
			encoder.encode();
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException(String.format("Message Encoding exception: %s", e.getMessage()), e);
		}
		catch (ComponentInitializationException e) {
			throw new TechnicalException(String.format("Encoder init exception: %s", e.getMessage()), e);
		}
	}

	public static boolean isSamlArtifactRequest(HttpServletRequest httpServletRequest) {
		return SamlIoUtil.getSamlArtifactDataFromHttpProtocol(httpServletRequest) != null;
	}

	public static boolean isSamlRedirectRequest(HttpServletRequest httpServletRequest) {
		return httpServletRequest.getMethod().equals(HttpMethod.GET.name()) &&
				SamlIoUtil.getSamlDataFromHttpProtocol(httpServletRequest) != null;
	}

	public static boolean isSamlPostRequest(HttpServletRequest httpServletRequest) {
		return httpServletRequest.getMethod().equals(HttpMethod.POST.name()) &&
			SamlIoUtil.getSamlDataFromHttpProtocol(httpServletRequest) != null;
	}

	// De-marshal SAML POST message
	public static MessageContext decodeSamlPostMessage(HttpServletRequest request) {
		try {
			var decoder = new HTTPPostDecoder();
			return decodeSamlMessage(request, decoder);
		}
		catch (Exception e) {
			// Keep in mind CVE-2021-42550 (aka LOGBACK-1591) as we actually log potential attack data to logback here.
			// In the end it's integration friendliness versus security and the attack could have already happened in opensaml.
			throw new RequestDeniedException(String.format(
					"SAML POST message decoding failed with exceptionMessage='%s' samlPostData='%s'",
					ExceptionUtil.getRootMessage(e), SamlIoUtil.getSamlPostDataFromHttpProtocol(request, true)), e);
		}
	}

	// De-marshal SAML Redirect message
	public static MessageContext decodeSamlRedirectMessage(HttpServletRequest request) {
		try {
			var decoder = new HTTPRedirectDeflateDecoder();
			return decodeSamlMessage(request, decoder);
		}
		catch (Exception e) {
			// Keep in mind CVE-2021-42550 (aka LOGBACK-1591) as we actually log potential attack data to logback here.
			// In the end it's integration friendliness versus security and the attack could have already happened in opensaml.
			throw new RequestDeniedException(String.format(
					"SAML redirect message decoding failed with exceptionMessage='%s' samlPostData='%s'",
					ExceptionUtil.getRootMessage(e), SamlIoUtil.getSamlRedirectDataFromHttpProtocol(request, true)), e);
		}
	}

	// De-marshal SAML SOAP message
	public static MessageContext decodeSamlSoapMessage(HttpServletRequest request) {
		try {
			var decoder = new HTTPSOAP11Decoder();
			return decodeSamlMessage(request, decoder);
		}
		catch (Exception e) {
			// Keep in mind CVE-2021-42550 (aka LOGBACK-1591) as we actually log potential attack data to logback here.
			// In the end it's integration friendliness versus security and the attack could have already happened in opensaml.
			throw new RequestDeniedException(String.format(
					"SAML SOAP message decoding failed with exceptionMessage='%s' samlPostData='%s'",
					ExceptionUtil.getRootMessage(e), SamlIoUtil.getSamlPostDataFromHttpProtocol(request, true)), e);
		}
	}

	public static MessageContext decodeSamlArtifactMessage(HttpServletRequest request, String issuerId, ArtifactPeer peer,
			Optional<SignatureParameters> signatureParameters,
			SignatureValidationParameters signatureValidationParameters,
			Optional<HttpClient> httpClientOpt) {
		try {
			if (httpClientOpt.isPresent()) {
				return decodeSamlArtifactMessage(request, httpClientOpt.get(), issuerId, peer,
						signatureParameters, signatureValidationParameters);
			}
			try (var httpClient = HttpUtil.createApacheHttpClient(getPeerArtifactUri(peer).getScheme(),
					peer.getArtifactResolutionTruststore(), peer.getArtifactResolutionKeystore(), peer.getKeystoreBasePath(),
					peer.getProxyUrl(), peer.getConnectTimeout())) {
				return decodeSamlArtifactMessage(request, httpClient, issuerId, peer,
						signatureParameters, signatureValidationParameters);
			}
		}
		catch (Exception ex) {
			if (ex.getCause() instanceof TrustBrokerException tex) {
				// log this for reference, the important information will be in the TrustBrokerException internalMessage
				log.info("Unwrapping exception={} message={} caused by TrustBrokerException",
						ex.getClass()
						  .getName(), ex.getMessage());
				throw tex;
			}
			throw new TechnicalException(String.format(
					"SAML artifact message decoding failed with exceptionMessage='%s' samlArtData='%s'"
							+ " artifactPeer=%s",
					ExceptionUtil.getRootMessage(ex), SamlIoUtil.getSamlArtifactDataFromHttpProtocol(request), peer), ex);
		}
	}

	// get either Artifact resolution or Metadata URL for initializing the HttpClient, assuming they are both either HTTPS or
	// HTTP
	private static URI getPeerArtifactUri(ArtifactPeer peer) {
		try {
			var uri = peer.getArtifactResolutionUrl();
			if (uri == null) {
				uri = peer.getMetadataUrl();
			}
			return new URI(uri);
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException("Invalid ArtifactResolution / Metadata URL for peer", ex);
		}
	}

	public static String extractSourceIdFromArtifactMessage(HttpServletRequest request) {
		return extractSourceIdFromArtifactId(request.getParameter(SamlIoUtil.SAML_ARTIFACT_NAME));
	}

	// ARP source ID is hex encoded SHA-1 of the ARP issuer ID
	@SuppressWarnings("java:S4790")
	public static String calculateArtifactSourceIdFromIssuerId(String issuerId) {
		try {
			var sha1Digester = MessageDigest.getInstance(JCAConstants.DIGEST_SHA1);
			var digest = sha1Digester.digest(issuerId.getBytes(StandardCharsets.UTF_8));
			return Hex.encodeHexString(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new TechnicalException("No SHA-1 digest");
		}
	}

	public static String extractSourceIdFromArtifactId(String artifactId) {
		try {
			artifactId = StringUtils.trim(artifactId);
			if (StringUtils.isEmpty(artifactId)) {
				// should not be called without artifact ID
				throw new TechnicalException(SamlIoUtil.SAML_ARTIFACT_NAME + " is null or empty");
			}
			var artifactBytes = Base64Util.decode(artifactId);
			var artifact = SAML2ArtifactType0004.parseArtifact(artifactBytes);
			if (log.isDebugEnabled()) {
				log.debug("Decoded artifactId={} to type={} sourceId={} endpointIndex={}",
						artifactId, Hex.encodeHexString(artifact.getTypeCode()),
						Hex.encodeHexString(artifact.getSourceID()), Hex.encodeHexString(artifact.getEndpointIndex()));
			}
			return Hex.encodeHexString(artifact.getSourceID());
		}
		catch (IllegalArgumentException ex) {
			log.info("Cannot decode as type 0004 artifact={} ex={}", artifactId, ex.getMessage());
			// for other types we cannot determine the peer based on the source ID
			return "";
		}
	}

	// De-marshal SAML Artifact message
	private static MessageContext decodeSamlArtifactMessage(HttpServletRequest request, HttpClient httpClient,
			String issuerId, ArtifactPeer peer, Optional<SignatureParameters> signatureParameters,
			SignatureValidationParameters signatureValidationParameters)
			throws ComponentInitializationException, MessageDecodingException {
		var decoder = buildHttpArtifactDecoder(httpClient, issuerId, peer,
				signatureParameters, signatureValidationParameters);
		return decodeSamlMessage(request, decoder);
	}

	private static HTTPArtifactDecoder buildHttpArtifactDecoder(HttpClient httpClient, String issuerId, ArtifactPeer peer,
			Optional<SignatureParameters> signatureParameters,
			SignatureValidationParameters signatureValidationParameters) {
		if (peer.getPeerRole() == null) {
			throw new TechnicalException(String.format("Missing peerRole for peer=%s", peer));
		}
		try {
			var decoder = new HTTPArtifactDecoder();
			decoder.setPeerEntityRole(peer.getPeerRole());
			decoder.setSelfEntityIDResolver(new EntityIdResolver(peer.getPeerRole(), issuerId));
			var metaDataResolver = buildMetaDataResolver(peer, httpClient);
			var roleDescriptorResolver = new PredicateRoleDescriptorResolver(metaDataResolver);
			roleDescriptorResolver.initialize();
			decoder.setRoleDescriptorResolver(roleDescriptorResolver);

			var soapClient = new UnwrappingHttpSoapClient(signatureParameters, signatureValidationParameters);
			soapClient.setHttpClient(httpClient);
			soapClient.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
			soapClient.initialize();
			decoder.setSOAPClient(soapClient);
			return decoder;
		}
		catch (ResolverException | ComponentInitializationException e) {
			// Keep in mind CVE-2021-42550 (aka LOGBACK-1591) as we actually log potential attack data to logback here.
			// In the end it's integration friendliness versus security and the attack could have already happened in opensaml.
			throw new RequestDeniedException(String.format(
					"Initialization of HTTPArtifactDecoder failed with exceptionMessage='%s'",
					ExceptionUtil.getRootMessage(e)), e);
		}
	}

	private static MetadataResolver buildMetaDataResolver(ArtifactPeer peer, HttpClient httpClient) throws
			ResolverException, ComponentInitializationException {
		if (peer.getArtifactResolutionUrl() != null) {
			var metaDataResolver = new StaticMetaDataResolver("XTBStaticMetadataResolver",
					peer.getArtifactResolutionUrl(), peer.getArtifactResolutionIndex());
			log.debug("Resolving artifact metadata from artifactResolutionUrl={}", peer.getArtifactResolutionUrl());
			return metaDataResolver;
		}
		if (peer.getMetadataUrl() != null) {
			var metaDataResolver = new HTTPMetadataResolver(httpClient, peer.getMetadataUrl());
			// ID does not have any semantics
			metaDataResolver.setId("XTBMetadataResolver");
			metaDataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
			var index = new SAMLArtifactMetadataIndex();
			Set<MetadataIndex> indexes = Set.of(index);
			metaDataResolver.setIndexes(indexes);
			metaDataResolver.initialize();
			log.debug("Resolving artifact metadata from metadataUrl={}", peer.getMetadataUrl());
			return metaDataResolver;
		}
		throw new TechnicalException(String.format("Missing metadataUrl and artifactResolutionUrl for peer=%s", peer));
	}

	// De-marshal SAML message
	private static MessageContext decodeSamlMessage(HttpServletRequest request,
			BaseHttpServletRequestXMLMessageDecoder decoder) throws ComponentInitializationException, MessageDecodingException {
		decoder.setHttpServletRequestSupplier(() -> request);
		decoder.initialize();
		decoder.decode();
		return decoder.getMessageContext();
	}

	public static void setIssuer(MessageContext context, String issuer) {
		var selfEntityContext = context.ensureSubcontext(SAMLSelfEntityContext.class);
		selfEntityContext.setEntityId(issuer);
	}

	// memory-backed map with default cleanup
	public static SAMLArtifactMap createArtifactMap() {
		return createArtifactMap(Optional.empty(), Duration.ZERO, Duration.ZERO);
	}

	// map based on storage
	public static SAMLArtifactMap createArtifactMap(Optional<StorageService> storageService, Duration artifactLifetime,
			Duration cleanupInterval) {
		try {
			if (storageService.isPresent()) {
				var map = new StorageServiceSAMLArtifactMap();
				map.setStorageService(storageService.get());
				if (!artifactLifetime.isZero()) {
					map.setArtifactLifetime(artifactLifetime);
				}
				map.initialize();
				log.debug("Created SAMLArtifactMap backed with storageService={}", storageService.getClass()
																								 .getName());
				return map;
			}
			var map = new BasicSAMLArtifactMap();
			if (!artifactLifetime.isZero()) {
				map.setArtifactLifetime(artifactLifetime);
			}
			if (!cleanupInterval.isZero()) {
				map.setCleanupInterval(cleanupInterval);
			}
			map.initialize();
			log.debug("Created in-memory BasicSAMLArtifactMap");
			return map;
		}
		catch (ComponentInitializationException ex) {
			throw new TechnicalException("Could not create SAML Artifact map", ex);
		}
	}

	public static void setEndpoint(MessageContext context, Endpoint endpoint) {
		var endpointContext = getEndpointContext(context);
		if (endpointContext != null) {
			endpointContext.setEndpoint(endpoint);
		}
	}

	public static void setEndpoint(MessageContext context, String idpSsoDestination) {
		setEndpoint(context, createEndpoint(idpSsoDestination));
	}

	public static Endpoint getEndpoint(MessageContext context) {
		var endpointContext = getEndpointContext(context);
		return endpointContext != null ? endpointContext.getEndpoint() : null;
	}

	private static SAMLEndpointContext getEndpointContext(MessageContext context) {
		try {
			var peerEntityContext = context.ensureSubcontext(SAMLPeerEntityContext.class);
			return peerEntityContext.ensureSubcontext(SAMLEndpointContext.class);
		}
		catch (IllegalStateException e) {
			return null;
		}
	}

	private static Endpoint createEndpoint(String destinationUrl) {
		SingleSignOnService endpoint = buildSamlObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(destinationUrl);
		return endpoint;
	}

	public static String replaceSensitiveData(String xmlString) {
		return replaceSensitiveData(xmlString, defaultXmlTagsToReplace());
	}

	// Drop most of the security-sensitive value in <ds:SignatureValue>...</ds:SignatureValue> and friends
	// ...but ignore <SignatureValue/> as with that we would lose relevant parts of the SAML message.
	public static String replaceSensitiveData(String xmlString, List<String> xmlTags) {
		for (String xmlTag : xmlTags) {
			var secureString = new StringBuilder();
			var matcher = getXmlTagPattern(xmlTag).matcher(xmlString);
			var start = 0;
			// find opening tag
			while (matcher.find()) {
				if (isClosingTag(xmlString, matcher.start())) {
					// should not happen for properly generated XML - unclear where the secret ends - just skip the rest
					log.warn("Unexpected closing tag for xmlTag={} at {}..{}", xmlTag, matcher.start(), matcher.end());
					start = xmlString.length();
					break;
				}
				secureString.append(xmlString, start, matcher.end());
				start = matcher.end();
				if (isEmptyTag(xmlString, matcher.end())) {
					log.debug("Empty xmlTag={} at {}..{} - no secret", xmlTag, matcher.start(), matcher.end());
				}
				// find closing tag
				else if (matcher.find() && isClosingTag(xmlString, matcher.start())) {
					maskSecret(xmlString, secureString, start, matcher.start());
					start = matcher.start();
				}
				else {
					// should not happen for properly generated XML - unclear where the secret ends - just skip the rest
					log.warn("Missing closing tag for xmlTag={} at {}..{}", xmlTag, matcher.start(), matcher.end());
					start = xmlString.length();
				}
			}
			secureString.append(xmlString, start, xmlString.length());
			xmlString = secureString.toString();
		}

		return xmlString;
	}

	static Pattern getXmlTagPattern(String xmlTag) {
		// we run this pattern in valid XML after parsing - for simplicity, it accepts also invalid XML like </x/>
		return Pattern.compile("</?([^:>\\s]+:)?" + xmlTag + "(\\s+[^:>\\s]+:?[^:>\\s]+\\s*=\\s*\"[^\"]*\")*\\s*/?>");
	}

	private static boolean isClosingTag(String xmlString, int start) {
		// </
		return xmlString.charAt(start + 1) == '/';
	}

	private static boolean isEmptyTag(String xmlString, int end) {
		// />
		return xmlString.charAt(end - 2) == '/';
	}

	private static void maskSecret(String xmlString, StringBuilder secureString, int start, int startClosingTag) {
		// keep first characters of secret in plain unless it is the whole secret
		var endPlainData = start + 10;
		if (startClosingTag > endPlainData) {
			secureString.append(xmlString, start, endPlainData);
		}
		secureString.append("**********");
	}

	public static List<String> defaultXmlTagsToReplace() {
		List<String> tagsToBeReplaced = new ArrayList<>();
		tagsToBeReplaced.add("SignatureValue");
		tagsToBeReplaced.add("X509Certificate");
		tagsToBeReplaced.add("BinarySecret");
		tagsToBeReplaced.add("DigestValue");
		tagsToBeReplaced.add("CipherValue");
		return tagsToBeReplaced;
	}

	public static void checkAssertionsLimitations(List<Assertion> assertions, List<EncryptedAssertion> encryptedAssertions,
			String purpose) {
		var assertionCount = (assertions != null ? assertions.size() : 0) +
				(encryptedAssertions != null ? encryptedAssertions.size() : 0);
		if (assertionCount == 0) {
			throw new RequestDeniedException(String.format("No assertion or encryptedAssertion received for %s", purpose));
		}
		if (assertionCount > 1) {
			logMultipleAssertions(assertions, "unencrypted", purpose);
			logMultipleAssertions(encryptedAssertions, "encrypted", purpose);
			throw new RequestDeniedException(String.format("Received multiple assertions for %s", purpose));
		}
	}

	private static void logMultipleAssertions(List<? extends Evidentiary> assertions, String type, String purpose) {
		if (assertions != null && log.isErrorEnabled()) {
			for (var assertion : assertions) {
				log.error("Received multiple assertions for {} - {}: {}", purpose, type, samlObjectToString(assertion));
			}
		}
	}

	static void checkExtensions(StatusResponseType response, String purpose) {
		if (response != null && response.getExtensions() != null) {
			if (log.isErrorEnabled()) {
				for (var extension : response.getExtensions()
											 .getUnknownXMLObjects()) {
					log.error("Received extensions for {}: {}", purpose, samlObjectToString(extension));
				}
			}
			throw new RequestDeniedException(String.format("Received responseId=%s with %n extensions for %s",
					response.getID(), purpose));
		}
	}

	public static void checkResponsePresent(Response response, String purpose) {
		if (response == null) {
			throw new RequestDeniedException(String.format("CP SAML Response context is missing for %s", purpose));
		}
	}

	public static void checkResponseLimitations(Response response, String purpose) {
		checkResponsePresent(response, purpose);
		checkAssertionsLimitations(response.getAssertions(), response.getEncryptedAssertions(), purpose);
		checkExtensions(response, purpose);
	}

	public static List<String> extractAuthnRequestContextClasses(AuthnRequest authnRequest, Boolean replaceInbound,
																 Optional<List<String>> confClasses) {
		var requestedAuthnContext = authnRequest.getRequestedAuthnContext();

		if (confClasses.isPresent() && (Boolean.TRUE.equals(replaceInbound) || requestedAuthnContext == null)) {
			var value = authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : "UNKNOWN";
			log.info("Replacing incoming authn request from={} context classes={} replaced with={}", value,
					requestedAuthnContext, confClasses.get());
			return confClasses.get();
		}

		return extractAuthnRequestContextClasses(authnRequest);
	}

	public static List<String> extractAuthnRequestContextClasses(AuthnRequest authnRequest) {
		var requestedAuthnContext = authnRequest.getRequestedAuthnContext();
		if (requestedAuthnContext == null) {
			return Collections.emptyList();
		}
		var authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();

		return authnContextClassRefs.stream()
				.map(AuthnContextClassRef::getURI)
				.toList();
	}

	public static AuthnContextComparisonTypeEnumeration extractAuthnRequestComparison(AuthnRequest authnRequest) {
		var requestedAuthnContext = authnRequest.getRequestedAuthnContext();
		if (requestedAuthnContext == null || requestedAuthnContext.getComparison() == null) {
			return null;
		}
		return requestedAuthnContext.getComparison();
	}

	public static String extractAuthnStatementContextClass(AuthnStatement authnStatement) {
		AuthnContext authnContext = authnStatement.getAuthnContext();
		if (authnContext == null || authnContext.getAuthnContextClassRef() == null ||
				authnContext.getAuthnContextClassRef().getURI() == null) {
			return null;
		}
		return authnContext.getAuthnContextClassRef().getURI();
	}

	// forceAuthn=true triggers CP AuthnRequest in any case
	public static boolean isForceAuthnRequest(AuthnRequest authnRequest) {
		var forceAuthnXSBoolean = authnRequest.isForceAuthnXSBoolean();
		return forceAuthnXSBoolean != null && Boolean.TRUE.equals(authnRequest.isForceAuthn());
	}

	// this long parameter list should be reduced using a parameter object that is re-usable for different methods:
	@SuppressWarnings("java:S107")
	public static <T extends RequestAbstractType> void sendSamlRequest(VelocityEngine velocityEngine,
			SAMLArtifactMap artifactMap,
			SamlBinding binding,
			ArtifactResolutionParameters artifactResolutionParameters,
			T samlRequest, HttpServletResponse httpServletResponse,
			Credential credential, String endpoint, String relayState, String destinationAlias) {
		var context = createMessageContext(samlRequest, credential, endpoint, relayState);
		switch (binding) {
			case ARTIFACT:
				initAndEncodeSamlArtifactMessage(httpServletResponse, context, samlRequest.getIssuer().getValue(),
						velocityEngine, artifactResolutionParameters, artifactMap);
				break;
			case REDIRECT:
				sendSamlRedirectMessage(context, samlRequest, httpServletResponse, destinationAlias);
				break;
			case POST:
				sendSamlPostMessage(velocityEngine, context, samlRequest, httpServletResponse, destinationAlias);
				break;
			case SOAP:
				sendSamlSoapMessage(context, samlRequest, httpServletResponse, destinationAlias);
		}
	}

	private static <T extends SAMLObject> void sendSamlPostMessage(VelocityEngine velocityEngine, MessageContext context,
			T samlObject, HttpServletResponse httpServletResponse, String destinationAlias) {
			var encoder = configureSamlPostEncoder(httpServletResponse, context, velocityEngine, null);
			sendSamlMessage(encoder, samlObject, destinationAlias);
	}

	private static <T extends SAMLObject> void sendSamlRedirectMessage(MessageContext context,
			T samlObject, HttpServletResponse httpServletResponse, String destinationAlias) {
			var encoder = configureSamlRedirectEncoder(httpServletResponse, context, null);
			sendSamlMessage(encoder, samlObject, destinationAlias);
	}

	public static <T extends SAMLObject> void sendSamlSoapMessage(MessageContext context,
			T samlObject, HttpServletResponse httpServletResponse, String destinationAlias) {
		var encoder = createSamlSoapEncoder(httpServletResponse, context);
		sendSamlMessage(encoder, samlObject, destinationAlias);
	}

	private static <E extends AbstractHttpServletResponseMessageEncoder, T extends SAMLObject> void sendSamlMessage(
			E encoder, T samlObject, String destinationAlias) {
		encodeSamlMessage(encoder);
		SamlTracer.logSamlObject("<<<<< Redirect SAML " + samlObject.getClass().getName()
					+ " to " + destinationAlias, samlObject);
	}

	public static <T extends SAMLObject> MessageContext createMessageContext(T samlObject, Credential credential,
			String endpoint,
			String relayState) {
		var context = new MessageContext();
		context.setMessage(samlObject);

		setEndpoint(context, endpoint);
		if (credential != null) {
			setSignatureParameter(context, credential);
		}

		SAMLBindingSupport.setRelayState(context, relayState);
		return context;
	}

	public static void initiateArtifactBindingContext(
			MessageContext context, String issuerId, ArtifactResolutionParameters artifactResolutionParameters) {
		setIssuer(context, issuerId);
		var artifactContext = context.ensureSubcontext(SAMLArtifactContext.class);
		artifactContext.setSourceArtifactResolutionServiceEndpointIndex(artifactResolutionParameters.getEndpointIndex());
		artifactContext.setSourceEntityId(artifactResolutionParameters.getEntityId());
		// endpoint is from config
		artifactContext.setSourceArtifactResolutionServiceEndpointURL(artifactResolutionParameters.getEndpointUrl());
	}

	public static void setSignatureParameter(MessageContext context, Credential credential) {
		try {
			Objects.requireNonNull(context.ensureSubcontext(SecurityParametersContext.class))
				   .setSignatureSigningParameters(createSignatureParameter(credential));
		}
		catch (IllegalStateException e) {
			throw new RequestDeniedException("AuthnRequest subcontext is missing!");
		}
	}

	private static SignatureSigningParameters createSignatureParameter(Credential credential) {
		var signatureSigningParameters = new SignatureSigningParameters();
		signatureSigningParameters.setSigningCredential(credential);
		signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		return signatureSigningParameters;
	}

	public static VelocityEngine createVelocityEngine(String velocityTemplatePath) {
		var velocityEngine = new VelocityEngine();
		// https://velocity.apache.org/engine/devel/configuration-property-changes-in-2.1.html
		velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, StandardCharsets.UTF_8);
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "classpath");
		velocityEngine.setProperty("resource.loader.classpath.class",
				"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		if (StringUtils.isNotEmpty(velocityTemplatePath)) {
			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
			velocityEngine.setProperty("resource.loader.file.class",
					"org.apache.velocity.runtime.resource.loader.FileResourceLoader");
			velocityEngine.setProperty(RuntimeConstants.FILE_RESOURCE_LOADER_PATH,
					velocityTemplatePath);
		}
		velocityEngine.init();
		return velocityEngine;
	}

	public static String extractRelayStateAsSessionId(MessageContext messageContext) {
		var relayState = SAMLBindingSupport.getRelayState(messageContext);
		return SamlUtil.useRelayStateAsSessionId(relayState);
	}

	public static String getStatusMessage(StatusResponseType response) {
		return response != null && response.getStatus() != null && response.getStatus()
																		   .getStatusMessage() != null ?
				response.getStatus()
						.getStatusMessage()
						.getValue() : null;
	}

	public static String getStatusCode(StatusResponseType response) {
		return response != null && response.getStatus() != null && response.getStatus()
																		   .getStatusCode() != null ?
				response.getStatus()
						.getStatusCode()
						.getValue() : null;
	}

	public static String getNestedStatusCode(StatusResponseType response) {
		return response != null && response.getStatus() != null && response.getStatus()
																		   .getStatusCode() != null &&
				response.getStatus()
						.getStatusCode()
						.getStatusCode() != null ?
				response.getStatus()
						.getStatusCode()
						.getStatusCode()
						.getValue() : null;
	}

	public static Scoping constructIdpScoping(String idpId) {
		var idpEntry = OpenSamlUtil.buildSamlObject(IDPEntry.class);
		idpEntry.setProviderID(idpId);
		var idpList = OpenSamlUtil.buildSamlObject(IDPList.class);
		idpList.getIDPEntrys().add(idpEntry);
		var scoping = OpenSamlUtil.buildSamlObject(Scoping.class);
		scoping.setIDPList(idpList);
		return scoping;
	}

	public static String extractIdpScoping(AuthnRequest authnRequest) {
		var scoping = authnRequest.getScoping();
		if (scoping == null || scoping.getIDPList() == null || scoping.getIDPList().getIDPEntrys().isEmpty()) {
			return null;
		}
		return scoping.getIDPList().getIDPEntrys().get(0).getProviderID();
	}

}
