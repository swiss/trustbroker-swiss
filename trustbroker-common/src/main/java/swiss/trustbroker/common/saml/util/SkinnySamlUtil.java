/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.NamespaceSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Skinny SAML messages handling requires rewriting the opensaml output DOM.
 * It's recommended to use the cleaner opensaml representation but large SAML messages might be blocked on peers.
 * <ul>
 * <li>The fun of SAML XML-Sec C14N:
 *     <a href="https://groups.google.com/g/opensaml-users/c/fJOZqT08UXs">AttributeValue of type XSString or XSInteger causing signature validation to fail</a>
 * </li>
 * <li>AD connect requirements:
 *     <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-saml-idp">Use a SAML IdP for SSO</a>
 *     <a href="https://login.microsoftonline.com/federationmetadata/saml20/federationmetadata.xml">Federation Metadata</a>
 * </li>
 * <li>ADFS interop:
 *     <a href="https://www-public.imtbs-tsp.eu/~procacci/dok/lib/exe/fetch.php?media=docpublic:systemes:shibboleth:azuread-sso-shibboleth-idp-20180607-2.docx">Shibboleth IDP</a>
 * </li>
 * <li>This manipulation is configured in XB using CanonicalizationMethod:
 *    <code>http://www.w3.org/2001/10/xml-exc-c14n#WithSkinnyPatches</code>
 * </li>
 * <li>Standards this is based on:
 *     <a href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">XML Canonicalization</a>
 * </li>
 * </ul>
 * Limitations:
 * UTF-8 character hex code encoding might be required as we remove the XML encoding header below, so AttributeValue should
 * not contain any non-7-bit ASCII characters.
 */
@Slf4j
public class SkinnySamlUtil {

	public static final String ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES =
			SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS + "WithSkinnyPatches";

	private static final String SAML20P_PREFIX_SKINNY_STYLE = "samlp";

	private SkinnySamlUtil() {
	}

	public static void prepareSAMLSignature(Signature signature, String c14nAlgo) {
		if (ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES.equals(c14nAlgo) && signature != null) {
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		}
	}

	public static void prepareSAMLObject(SignableXMLObject object, String c14nAlgo) {
		if (ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES.equals(c14nAlgo)) {
			patchDomForSkinnyMessages(object);
		}
		// Drop the xsi:type="xs:string" required by opensaml as well ending up in AttributeValue being of type any instead
		if (object instanceof Assertion assertion && c14nAlgo != null && c14nAlgo.contains(OpenSamlUtil.SKINNY_NO_TYPE)) {
			discardTypeInfoOnAttributeValues(assertion);
		}
	}

	private static Node extractNodeWithChild(Node node, String localName) {
		if (node != null && node.hasChildNodes()) {
			var nodeList = node.getChildNodes();
			for (var i = 0; i < nodeList.getLength(); i++) {
				var cnode = nodeList.item(i);
				if (localName.equals(cnode.getLocalName()) && cnode.getFirstChild() != null) {
					return cnode;
				}
			}
		}
		return null;
	}

	private static void discardTypeInfoOnAttributeValue(XMLObject val, String typeAttr) {
		if (!val.getDOM().getAttribute(typeAttr).isEmpty()) {
			val.getDOM().getAttributes().removeNamedItem(typeAttr);
		}
	}

	private static void discardTypeInfoOnAttributeValues(Assertion assertion) {
		// get rid of XML-Schema typing
		discardTypeInfoOnAttributeValue(assertion, "xmlns:xsd");
		eliminateInclusiveNamespace(assertion);
		for (var attrstmt : assertion.getAttributeStatements()) {
			for (var attr : attrstmt.getAttributes()) {
				for (var val : attr.getAttributeValues()) {
					discardTypeInfoOnAttributeValue(val, "xmlns:xsi");
					discardTypeInfoOnAttributeValue(val, "xsi:type");
				}
			}
		}
	}

	private static void replaceSaml2Namespace(Node node, String namespaceUri, String prefix, String prefixReplace,
			boolean dochilds) {
		if (prefix.equals(node.getPrefix())) {
			node.setPrefix(prefixReplace);
		}
		if (namespaceUri.equals(node.getNamespaceURI())) {
			var xmlnsDecl = "xmlns:" + prefix;
			var attr = node.getAttributes().getNamedItem(xmlnsDecl);
			if (attr != null) {
				node.getAttributes().removeNamedItem(xmlnsDecl);
				NamespaceSupport.appendNamespaceDeclaration((Element)node, namespaceUri, prefixReplace);
			}
		}
		if (node.hasChildNodes() && dochilds) {
			var nodeList = node.getChildNodes();
			for (var i = 0; i < nodeList.getLength(); i++) {
				var cnode = nodeList.item(i);
				replaceSaml2Namespace(cnode, namespaceUri, prefix, prefixReplace, dochilds);
			}
		}
	}

	public static void eliminateCertWhitespace(Element element) {
		var certList = element.getElementsByTagName("ds:X509Certificate");
		var nodeListLength = certList.getLength();
		for (var i = 0; i < nodeListLength; i++) {
			if (certList.item(i).getNodeType() == Node.ELEMENT_NODE) {
				eliminateCertWhitespace(certList.item(i));
			}
		}
	}

	private static void eliminateCertWhitespace(Node x509Cert) {
		if (x509Cert != null) {
			var cert = x509Cert.getFirstChild();
			var cleaned = eliminateCertWhitespace(cert.getNodeValue());
			cert.setNodeValue(cleaned);
		}
	}

	public static void eliminateCertWhitespace(KeyInfo keyInfo) {
		for (var x509Data : keyInfo.getX509Datas()) {
			eliminateCertWhitespace(x509Data);
		}
	}

	private static void eliminateCertWhitespace(X509Data x509Data) {
		for (var x509Cert : x509Data.getX509Certificates()) {
			eliminateCertWhitespace(x509Cert);
		}
	}

	private static void eliminateCertWhitespace(X509Certificate x509Cert) {
		if (x509Cert != null) {
			var cert = x509Cert.getValue();
			var cleaned = eliminateCertWhitespace(cert);
			x509Cert.setValue(cleaned);
		}
	}

	private static String eliminateCertWhitespace(String data) {
		if (data == null) {
			return null;
		}
		return data.replaceAll("\\s", "");
	}

	private static void eliminateInclusiveNamespace(Assertion assertion) {
		// get rid of exclusive elements triggered by
		// org.opensaml.saml.common.SAMLObjectContentReference.processExclusiveTransform
		// when using http://www.w3.org/2001/10/xml-exc-c14n#
		var signInfo = extractNodeWithChild(assertion.getSignature().getDOM(), "SignedInfo");
		if (signInfo == null) {
			return;
		}
		var reference = extractNodeWithChild(signInfo, "Reference");
		if (reference == null) {
			return;
		}
		var transforms = extractNodeWithChild(reference, "Transforms");
		if (transforms == null) {
			return;
		}
		var transform = extractNodeWithChild(transforms, "Transform");
		if (transform == null) {
			return;
		}
		// as we have removed the xsd types we also have to get rid of the canonicalization namespace prefixes
		if (transform.getFirstChild().getLocalName().equals("InclusiveNamespaces")) {
			transform.removeChild(transform.getFirstChild());
		}
	}

	private static void eliminateKeyInfoPrefix(Assertion assertion) {
		var keyInfo = extractNodeWithChild(assertion.getSignature().getDOM(), "KeyInfo");
		if (keyInfo != null) {
			keyInfo.setPrefix(null);
		}
	}

	public static boolean isPatchedResponse(XMLObject message) {
		if (message instanceof Response response) {
			return SAML20P_PREFIX_SKINNY_STYLE.equals(response.getDOM().getPrefix());
		}
		return false;
	}

	public static String discardXmlDocHeader(String messageXml) {
		var header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		if (!messageXml.startsWith(header)) {
			throw new TechnicalException("Unexpected skinny patching condition on: " + messageXml);
		}
		return messageXml.replace(header, "");
	}

	static void patchDomForSkinnyMessages(SignableXMLObject object) {
		switch (object) {
			case Assertion assertion -> {
				log.debug("Applying skinny assertion patches triggered by {}", ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES);
				discardTypeInfoOnAttributeValues(assertion);
				eliminateCertWhitespace(assertion.getSignature().getDOM());
				eliminateInclusiveNamespace(assertion);
				// prefixReplace="saml" transforms saml2 to saml, null eliminated the prefix
				replaceSaml2Namespace(object.getDOM(), SAMLConstants.SAML20_NS, SAMLConstants.SAML20_PREFIX, null, true);
				// KeyInfo also has some funny NS issue
				eliminateKeyInfoPrefix(assertion);
			}
			case Response response -> {
				replaceSaml2Namespace(response.getIssuer().getDOM(), SAMLConstants.SAML20_NS,
						SAMLConstants.SAML20_PREFIX, null, false);
				replaceSaml2Namespace(object.getDOM(), SAMLConstants.SAML20P_NS, SAMLConstants.SAML20P_PREFIX,
						SAML20P_PREFIX_SKINNY_STYLE, true);
			}
			default -> log.info("Skipping skinny Assertion patches on class={} triggered by {}",
					object.getClass().getName(), ALGO_ID_C14N_EXCL_WITH_SKINNY_PATCHES);
		}
	}

}
