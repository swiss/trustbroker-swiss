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
import java.util.UUID;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.soap.wsaddressing.Action;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wsaddressing.EndpointReference;
import org.opensaml.soap.wsaddressing.MessageID;
import org.opensaml.soap.wsaddressing.ReplyTo;
import org.opensaml.soap.wsaddressing.To;
import org.opensaml.soap.wsfed.EndPointReference;
import org.opensaml.soap.wspolicy.AppliesTo;
import org.opensaml.soap.wstrust.RenewTarget;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

public class WsTrustTestUtil {

	public static final String TEST_TO = WsTrustTestUtil.class.getName();

	public static final String SSO_SESSION_ID = SsoSessionIdPolicy.SSO_PREFIX + "1";

	public static final String RP_ISSUER_ID = "rp1";

	public static final String ASSERTION_ID = "assertion1";

	public static final String XTB_ISSUER_ID = "xtb:issuer";

	public static final Instant NOW = Instant.ofEpochMilli(1000000L);

	public static final int SUBJECT_VALID_SECS = 10;

	public static final int CONDITION_VALID_SECS = 20;

	public static final String NAME_ID = "subj1";

	public static final String CONTEXT_CLASS = "qoa1";

	private static To givenTo(String toValue) {
		To to = (To) XMLObjectSupport.buildXMLObject(To.ELEMENT_NAME);
		to.setURI(toValue);
		return to;
	}

	private static Address givenWsaAddress(String addressValue) {
		Address address = (Address) XMLObjectSupport.buildXMLObject(Address.ELEMENT_NAME);
		address.setURI(addressValue);
		return address;
	}

	private static org.opensaml.soap.wsfed.Address givenWsFedAddress(String addressValue) {
		org.opensaml.soap.wsfed.Address address = (org.opensaml.soap.wsfed.Address)
				XMLObjectSupport.buildXMLObject(org.opensaml.soap.wsfed.Address.DEFAULT_ELEMENT_NAME);
		address.setValue(addressValue);
		return address;
	}

	private static ReplyTo givenReplyTo() {
		return (ReplyTo) XMLObjectSupport.buildXMLObject(ReplyTo.ELEMENT_NAME);
	}

	private static MessageID givenMessageId(String messageIdValue) {
		MessageID messageID = (MessageID) XMLObjectSupport.buildXMLObject(MessageID.ELEMENT_NAME);
		messageID.setURI(messageIdValue);
		return messageID;
	}

	private static Action givenAction(String actionValue) {
		Action action = (Action) XMLObjectSupport.buildXMLObject(Action.ELEMENT_NAME);
		action.setURI(actionValue);
		return action;
	}

	public static SoapMessageHeader givenRequestHeader() {
		return givenRequestHeader(null);
	}

	public static SoapMessageHeader givenRequestHeader(Assertion assertion) {
		SoapMessageHeader requestHeader = new SoapMessageHeader();
		requestHeader.setAction(givenAction(WSTrustConstants.WSA_ACTION_RST_ISSUE));
		requestHeader.setMessageId(givenMessageId(UUID.randomUUID().toString()));
		requestHeader.setReplyTo(givenReplyToAddress(givenReplyTo(), givenWsaAddress(Address.ANONYMOUS)));
		requestHeader.setTo(givenTo(TEST_TO));
		if (assertion != null) {
			requestHeader.setAssertion(assertion);
		}
		return requestHeader;
	}

	private static ReplyTo givenReplyToAddress(ReplyTo replyTo, Address address) {
		if (replyTo == null) {
			return null;
		}
		replyTo.setAddress(address);
		return replyTo;
	}

	public static RequestSecurityToken givenRst(String type, String address, boolean wsa) {
		RequestSecurityToken request = (RequestSecurityToken) XMLObjectSupport.buildXMLObject(RequestSecurityToken.ELEMENT_NAME);
		if (type != null) {
			request.getUnknownXMLObjects().add(givenType(type));
		}
		if (address != null) {
			request.getUnknownXMLObjects().add(givenAppliesTo(address, wsa));

		}
		return request;
	}

	private static RequestType givenType(String type) {
		RequestType requestType = (RequestType) XMLObjectSupport.buildXMLObject(RequestType.ELEMENT_NAME);
		requestType.setURI(type);
		return requestType;
	}

	private static AppliesTo givenAppliesTo(String address, boolean wsa) {
		AppliesTo appliesTo = (AppliesTo) XMLObjectSupport.buildXMLObject(AppliesTo.ELEMENT_NAME);
		var endpointReference = wsa ? givenWsaEndpointReference(address) : givenWsFedEndpointReference(address);
		appliesTo.getUnknownXMLObjects().add(endpointReference);
		return appliesTo;
	}

	private static EndPointReference givenWsFedEndpointReference(String address) {
		EndPointReference endpointReference = (EndPointReference) XMLObjectSupport.buildXMLObject(EndPointReference.DEFAULT_ELEMENT_NAME);
		endpointReference.setAddress(givenWsFedAddress(address));
		return endpointReference;
	}

	private static EndpointReference givenWsaEndpointReference(String address) {
		EndpointReference endpointReference = (EndpointReference) XMLObjectSupport.buildXMLObject(EndpointReference.ELEMENT_NAME);
		endpointReference.setAddress(givenWsaAddress(address));
		return endpointReference;
	}

	public static Assertion givenAssertion() {
		var assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(ASSERTION_ID);
		assertion.setIssuer(SamlFactory.createIssuer(XTB_ISSUER_ID));
		assertion.setSubject(SamlFactory.createSubject(
				SamlFactory.createNameId(NAME_ID, null, null), "req1", RP_ISSUER_ID, SUBJECT_VALID_SECS, NOW)
		);
		var conditions = SamlFactory.createConditions(
				RP_ISSUER_ID, CONDITION_VALID_SECS, NOW);
		assertion.setConditions(conditions);
		assertion.setIssueInstant(NOW);
		var authnStatement = OpenSamlUtil.buildSamlObject(AuthnStatement.class);
		authnStatement.setSessionIndex(SSO_SESSION_ID);
		assertion.getAuthnStatements().add(authnStatement);
		var authnContext = SamlFactory.createAuthnContext(CONTEXT_CLASS);
		authnStatement.setAuthnContext(authnContext);
		return assertion;
	}

	public static RequestSecurityToken givenRenewRstRequest(Assertion assertion) {
		var rst = (RequestSecurityToken) XMLObjectSupport.buildXMLObject(RequestSecurityToken.ELEMENT_NAME);
		rst.getUnknownXMLObjects().add(givenType(WSTrustConstants.WSA_ACTION_RST_RENEW));
		var renewTarget = (RenewTarget) XMLObjectSupport.buildXMLObject(RenewTarget.ELEMENT_NAME);
		renewTarget.setUnknownXMLObject(assertion);
		rst.getUnknownXMLObjects().add(renewTarget);
		return rst;
	}

	public static RequestSecurityToken givenIssueRstRequest() {
		var rst = (RequestSecurityToken) XMLObjectSupport.buildXMLObject(RequestSecurityToken.ELEMENT_NAME);
		rst.getUnknownXMLObjects().add(givenType(WSTrustConstants.WSA_ACTION_RST_RENEW));
		rst.getUnknownXMLObjects().add(givenWsFedEndpointReference(RP_ISSUER_ID));
		return rst;
	}
}
