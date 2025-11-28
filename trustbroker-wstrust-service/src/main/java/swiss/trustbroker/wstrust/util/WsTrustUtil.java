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

package swiss.trustbroker.wstrust.util;

import java.time.Instant;
import java.util.Objects;
import javax.xml.namespace.QName;
import javax.xml.transform.dom.DOMSource;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.util.XMLObjectSupport;
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
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.RequestedAttachedReference;
import org.opensaml.soap.wstrust.RequestedUnattachedReference;
import org.opensaml.soap.wstrust.TokenType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.ws.soap.SoapElement;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WSSConstants;

@Slf4j
public class WsTrustUtil {

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
			throw new RequestDeniedException("Missing Address in RSTR");
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
}
