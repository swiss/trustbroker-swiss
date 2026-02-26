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

package swiss.trustbroker.wstrust.util;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.xml.namespace.QName;
import javax.xml.transform.dom.DOMSource;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.soap.wsaddressing.EndpointReference;
import org.opensaml.soap.wsfed.Address;
import org.opensaml.soap.wsfed.EndPointReference;
import org.opensaml.soap.wspolicy.AppliesTo;
import org.opensaml.soap.wssecurity.Created;
import org.opensaml.soap.wssecurity.Expires;
import org.opensaml.soap.wssecurity.KeyIdentifier;
import org.opensaml.soap.wssecurity.SecurityTokenReference;
import org.opensaml.soap.wssecurity.Timestamp;
import org.opensaml.soap.wssecurity.WSSecurityConstants;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.Lifetime;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponse;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.RequestedAttachedReference;
import org.opensaml.soap.wstrust.RequestedSecurityToken;
import org.opensaml.soap.wstrust.RequestedUnattachedReference;
import org.opensaml.soap.wstrust.TokenType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.ws.soap.SoapElement;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class WsTrustUtil {

	public static final Logger OP_LOG = LoggerFactory.getLogger("swiss.trustbroker.op.wstrust");

	private WsTrustUtil() {
	}

	public static Lifetime createLifeTime(Instant createTime, Instant expiresTime) {
		Lifetime lifetime = (Lifetime) XMLObjectSupport.buildXMLObject(Lifetime.ELEMENT_NAME);
		lifetime.setCreated(createCreated(createTime));
		lifetime.setExpires(createExpires(expiresTime));
		return lifetime;
	}

	public static Timestamp createTimestamp(Instant createTime, Instant expiresTime) {
		Timestamp timestamp = (Timestamp) XMLObjectSupport.buildXMLObject(Timestamp.ELEMENT_NAME);
		timestamp.setCreated(createCreated(createTime));
		timestamp.setExpires(createExpires(expiresTime));
		return timestamp;
	}

	public static Expires createExpires(Instant expiresDate) {
		Expires expires = (Expires) XMLObjectSupport.buildXMLObject(Expires.ELEMENT_NAME);
		expires.setDateTime(expiresDate);
		return expires;
	}

	public static Created createCreated(Instant createTime) {
		Created created = (Created) XMLObjectSupport.buildXMLObject(Created.ELEMENT_NAME);
		created.setDateTime(createTime);
		return created;
	}

	public static AppliesTo createResponseAppliesTo(String subjectCondition) {
		AppliesTo appliesTo = (AppliesTo) XMLObjectSupport.buildXMLObject(AppliesTo.ELEMENT_NAME);
		appliesTo.getUnknownXMLObjects().add(createResponseEndpointReference(subjectCondition));
		return appliesTo;
	}

	public static EndPointReference createResponseEndpointReference(String subjectCondition) {
		EndPointReference endPointReference = OpenSamlUtil.buildSamlObject(EndPointReference.class);
		endPointReference.setAddress(createEndpointRefAddress(subjectCondition));
		return endPointReference;
	}

	public static Address createEndpointRefAddress(String subjectCondition) {
		Address address = OpenSamlUtil.buildSamlObject(Address.class);
		address.setValue(subjectCondition);

		return address;
	}

	public static KeyType createKeyType(String keyTypeValue) {
		KeyType keyType = (KeyType) XMLObjectSupport.buildXMLObject(KeyType.ELEMENT_NAME);
		keyType.setURI(keyTypeValue);
		return keyType;
	}

	public static TokenType createTokenType() {
		TokenType tokenType = (TokenType) XMLObjectSupport.buildXMLObject(TokenType.ELEMENT_NAME);
		tokenType.setURI("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		return tokenType;
	}

	public static RequestType createRequestType(String typeValue) {
		RequestType requestType = (RequestType) XMLObjectSupport.buildXMLObject(RequestType.ELEMENT_NAME);
		requestType.setURI(typeValue);

		return requestType;
	}

	public static RequestedUnattachedReference createRequestUnattachedRef(String assertionId) {
		RequestedUnattachedReference requestedUnattachedReference =
				(RequestedUnattachedReference) XMLObjectSupport.buildXMLObject(RequestedUnattachedReference.ELEMENT_NAME);
		requestedUnattachedReference.setSecurityTokenReference(createSecurityTokenReference(assertionId));

		return requestedUnattachedReference;
	}

	public static RequestedAttachedReference createRequestedAttachedRef(String assertionId) {
		RequestedAttachedReference requestedAttachedReference =
				(RequestedAttachedReference) XMLObjectSupport.buildXMLObject(RequestedAttachedReference.ELEMENT_NAME);
		requestedAttachedReference.setSecurityTokenReference(createSecurityTokenReference(assertionId));

		return requestedAttachedReference;
	}

	public static SecurityTokenReference createSecurityTokenReference(String assertionId) {
		SecurityTokenReference securityTokenReference =
				(SecurityTokenReference) XMLObjectSupport.buildXMLObject(SecurityTokenReference.ELEMENT_NAME);
		securityTokenReference.getUnknownAttributes().put(createTokenTypeAttribute(), createTokenTypeAttributeValue());
		securityTokenReference.getUnknownXMLObjects().add(createKeyIdentifier(assertionId));
		return securityTokenReference;
	}

	public static KeyIdentifier createKeyIdentifier(String assertionId) {
		KeyIdentifier keyIdentifier = (KeyIdentifier) XMLObjectSupport.buildXMLObject(KeyIdentifier.ELEMENT_NAME);
		keyIdentifier.setValue(assertionId);
		keyIdentifier.setValueType(WSSConstants.WSS_SAML2_KI_VALUE_TYPE);
		return keyIdentifier;
	}

	public static QName createTokenTypeAttribute() {
		return new QName(WSSecurityConstants.WSSE11_NS, TokenType.ELEMENT_LOCAL_NAME, "b");
	}

	public static QName createTokenTypeAttributeValue() {
		return new QName(WSSecurityConstants.WSSE11_NS, WSSConstants.WSS_SAML2_TOKEN_TYPE);
	}

	public static RequestedSecurityToken createRequestedSecurityToken(Assertion assertion) {
		var requestedSecurityToken =
				(RequestedSecurityToken) XMLObjectSupport.buildXMLObject(RequestedSecurityToken.ELEMENT_NAME);

		requestedSecurityToken.setUnknownXMLObject(assertion);

		return requestedSecurityToken;
	}

	public static RequestSecurityTokenResponse createSecurityTokenResponse(RequestedSecurityToken requestedSecurityToken) {
		var requestSecurityTokenResponse =
				(RequestSecurityTokenResponse) XMLObjectSupport.buildXMLObject(RequestSecurityTokenResponse.ELEMENT_NAME);

		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedSecurityToken);

		return requestSecurityTokenResponse;
	}

	public static String getKeyTypeFromRequest(RequestSecurityToken requestSecurityToken) {
		var childObjects = requestSecurityToken.getUnknownXMLObjects();
		var keyTypeQname = new QName(WSTrustConstants.WST_NS, KeyType.ELEMENT_LOCAL_NAME);
		KeyType keyType = OpenSamlUtil.findChildObjectByQname(childObjects, keyTypeQname);
		if (keyType == null) {
			throw new RequestDeniedException("Missing KeyType in RSTR");
		}
		return keyType.getURI();
	}

	public static String getAddressFromRequest(RequestSecurityToken requestSecurityToken) {
		Objects.requireNonNull(requestSecurityToken);
		Objects.requireNonNull(requestSecurityToken.getDOM());

		var addressFromRequest = getElementValueByTagName(
				"Address", "wsa:Address", requestSecurityToken.getDOM());

		if (addressFromRequest == null) {
			throw new RequestDeniedException("Missing Address in RST");
		}

		return addressFromRequest;
	}

	public static String getElementValueByTagName(String tagName, String tagNameWithNamespace, Element element) {
		var list = element.getElementsByTagName(tagName);
		if (list == null || list.getLength() == 0) {
			list = element.getElementsByTagName(tagNameWithNamespace);
		}
		if (list != null && list.getLength() > 0) {
			var subList = list.item(0).getChildNodes();

			if (subList != null && subList.getLength() > 0) {
				return subList.item(0).getNodeValue();
			}
		}

		var msg = String.format("Could not extract %s or %s from request", tagName, tagNameWithNamespace);
		throw new RequestDeniedException(msg);
	}

	public static boolean validatePeriod(String periodType, Created created, Expires expires, Instant now,
			long notBeforeToleranceSec, long notOnOrAfterToleranceSec) {
		var nowWithBeforeTolerance = now.minusSeconds(notBeforeToleranceSec); // tolerance is negative
		var createdOk = (created != null) && nowWithBeforeTolerance.isAfter(created.getDateTime());
		if (!createdOk) {
			log.error("Invalid {}.Created={} in the future now={} notOnOrAfterToleranceSec={}",
					periodType, (created != null) ? created.getDateTime() : null, now, notOnOrAfterToleranceSec);
		}
		var nowWithAfterTolerance = now.minusSeconds(notOnOrAfterToleranceSec + 1); // tolerance is positive
		var expiresOk = (expires != null) && nowWithAfterTolerance.isBefore(expires.getDateTime());
		if (!expiresOk) {
			log.error("Invalid {}.Expires={} in the past now={} notBeforeToleranceSec={}",
					periodType, (expires != null) ? expires.getDateTime() : null, now, notBeforeToleranceSec);
		}
		return createdOk && expiresOk;
	}

	public static Node getNode(SoapElement soapMessage) {
		var source = soapMessage.getSource();
		var domSource = (DOMSource) source;
		return domSource.getNode();
	}

	public static boolean isNetworkAllowed(List<String> allowedNetworks, boolean enforceClientNetwork,
			HttpServletRequest request, NetworkConfig network) {
		if (CollectionUtils.isEmpty(allowedNetworks)) {
			return true;
		}
		if (request == null) {
			log.error("Missing HttpServletRequest, cannot restrict WS-Trust to allowedNetworks={}", allowedNetworks);
			return true;
		}
		var clientNetwork = WebSupport.getClientNetwork(request, network);
		if (clientNetwork == null) {
			log.error("Client network not known, cannot restrict WS-Trust to allowedNetworks={}", allowedNetworks);
			return true;
		}
		var allowedNetwork = allowedNetworks.contains(clientNetwork);
		if (allowedNetwork) {
			log.debug("Access to WS-Trust allowed from clientNetwork={} for allowedNetworks={}", clientNetwork, allowedNetworks);
			return true;
		}
		if (enforceClientNetwork) {
			log.error("Access to WS-Trust blocked from clientNetwork={} for allowedNetworks={}", clientNetwork, allowedNetworks);
			return false;
		}
		log.warn("Access to WS-Trust allowed from clientNetwork={} despite allowedNetworks={}", clientNetwork, allowedNetworks);
		return true;
	}

	public static boolean isClientIpAllowed(String clientIpRegex, boolean enforceClientIp, String clientIp) {
		if (!StringUtils.hasLength(clientIpRegex)) {
			return true;
		}
		if (clientIp == null) {
			log.error("Missing clientIp, cannot restrict WS-Trust to allowedClientIpRegex={}", clientIpRegex);
			return true;
		}
		var allowedIp = clientIp.matches(clientIpRegex);
		if (allowedIp) {
			log.debug("Access to WS-Trust allowed from clientIp={} for allowedClientIpRegex={}", clientIp, clientIpRegex);
			return true;
		}
		if (enforceClientIp) {
			log.error("Access to WS-Trust blocked from clientIp={} for allowedClientIpRegex={}", clientIp, clientIpRegex);
			return false;
		}
		log.warn("Access to WS-Trust allowed from clientIp={} despite allowedClientIpRegex={}", clientIp, clientIpRegex);
		return true;
	}

	public static NameID getNameID(Assertion assertion) {
		Subject subject = assertion.getSubject();
		if (subject == null) {
			throw new TechnicalException(String.format("Missing Assertion.Subject from RST with id=%s", assertion.getID()));
		}
		return subject.getNameID();
	}

	public static List<String> getAuthnContextClasses(Assertion requestHeaderAssertion) {
		List<String> contextClasses = Collections.emptyList();
		if (requestHeaderAssertion == null || requestHeaderAssertion.getAuthnStatements().isEmpty()) {
			return contextClasses;
		}
		var authnContext = requestHeaderAssertion.getAuthnStatements().get(0).getAuthnContext();
		if (authnContext != null && authnContext.getAuthnContextClassRef() != null &&
				authnContext.getAuthnContextClassRef().getURI() != null) {
			var authnContextClassRef = authnContext.getAuthnContextClassRef().getURI();
			contextClasses = List.of(authnContextClassRef);
		}
		return contextClasses;
	}

	// rpIssuerId for ISSUE - see also CompatEndPointReferenceUnmarshaller
	public static String getEndpointReferenceAddress(RequestSecurityToken requestSecurityToken) {
		for (var child : requestSecurityToken.getUnknownXMLObjects()) {
			if (child instanceof AppliesTo appliesTo) {
				for (var appliesChild : appliesTo.getUnknownXMLObjects()) {
					if (appliesChild instanceof EndPointReference endpointReference && endpointReference.getAddress() != null) {
						var address = endpointReference.getAddress().getValue();
						log.debug("wsfed EndPointReference address=={}", address);
						return address;
					}
					else if (appliesChild instanceof EndpointReference endpointReference && endpointReference.getAddress() != null) {
						var address = endpointReference.getAddress().getURI();
						log.debug("wsadressing EndpointReference address={}", address);
						return address;
					}
				}
			}
		}
		log.warn("Missing AppliesTo with EndPointReference.Address in RST");
		return null;
	}

	// cpIssuerId for ISSUE
	public static String getIssuerId(Assertion assertion) {
		if (assertion == null || assertion.getIssuer() == null || assertion.getIssuer().getValue() == null) {
			throw new RequestDeniedException(String.format(
					"Assertion in RSTR with assertionID='%s' missing Issuer",
					assertion != null ? assertion.getID() : null));
		}
		return assertion.getIssuer().getValue();
	}
}
