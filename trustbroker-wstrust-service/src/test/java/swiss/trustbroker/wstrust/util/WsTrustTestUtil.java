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

import java.util.UUID;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wsaddressing.Action;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wsaddressing.MessageID;
import org.opensaml.soap.wsaddressing.ReplyTo;
import org.opensaml.soap.wsaddressing.To;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

public class WsTrustTestUtil {

	public static final String TEST_TO = WsTrustTestUtil.class.getName();

	private static To givenTo(String toValue) {
		To to = (To) XMLObjectSupport.buildXMLObject(To.ELEMENT_NAME);
		to.setURI(toValue);
		return to;
	}

	private static Address givenAddress(String addressValue) {
		Address address = (Address) XMLObjectSupport.buildXMLObject(Address.ELEMENT_NAME);
		address.setURI(addressValue);
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
		SoapMessageHeader requestHeader = new SoapMessageHeader();
		requestHeader.setAction(givenAction(WSTrustConstants.WSA_ACTION_RST_ISSUE));
		requestHeader.setMessageId(givenMessageId(UUID.randomUUID().toString()));
		requestHeader.setReplyTo(givenReplyToAddress(givenReplyTo(), givenAddress(Address.ANONYMOUS)));
		requestHeader.setTo(givenTo(TEST_TO));
		return requestHeader;
	}

	private static ReplyTo givenReplyToAddress(ReplyTo replyTo, Address address) {
		if (replyTo == null) {
			return null;
		}
		replyTo.setAddress(address);
		return replyTo;
	}

}
