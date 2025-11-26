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

package swiss.trustbroker.wstrust.validator;

import java.time.Instant;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

@Slf4j
public class WsTrustHeaderValidator {

	private WsTrustHeaderValidator() {
	}

	// Strict SOAP/SAML protocol checking from observation
	public static void validateHeaderElements(SoapMessageHeader requestHeader, String issuer) {
		log.debug("Validate WSTrust SOAP headers....");

		ensurePresent(requestHeader);
		var soapAction = getSoapAction(requestHeader);
		if (soapAction == null || !soapAction.equals(WSTrustConstants.WSA_ACTION_RST_ISSUE)) {
			throw new RequestDeniedException(String.format(
					"Action missing or invalid in SOAP header, action='%s' expected='%s'",
					StringUtil.clean(soapAction), WSTrustConstants.WSA_ACTION_RST_ISSUE));
		}

		var messageId = requestHeader.getMessageId();
		if (messageId == null || StringUtils.isBlank(messageId.getURI())) {
			throw new RequestDeniedException("MessageId missing in SOAP header");
		}

		var replyTo = requestHeader.getReplyTo();
		if (replyTo == null) {
			throw new RequestDeniedException("ReplyTo missing in SOAP header");
		}

		// see https://www.w3.org/TR/2006/REC-ws-addr-core-20060509/ for the check below
		var address = replyTo.getAddress();
		if (address == null || StringUtils.isBlank(address.getURI()) || !address.getURI().equals(Address.ANONYMOUS)) {
			throw new RequestDeniedException(String.format(
					"Address missing or invalid in ReplyTo SOAP header, value='%s' accepted='%s'",
					address == null ? address : address.getURI(), Address.ANONYMOUS));
		}

		var to = requestHeader.getTo();
		if (to != null && to.getURI() != null && !toMatchWithIssuer(to.getURI(), issuer)) {
			log.warn("To missing or invalid in SOAP header, value='{}' accepted='{}'", to.getURI(), issuer);
		}
	}

	private static void ensurePresent(SoapMessageHeader requestHeader) {
		if (requestHeader == null) {
			throw new RequestDeniedException("SOAP request header missing");
		}
	}

	private static boolean toMatchWithIssuer(String to, String issuer) {
		var firstDelimiter = "://";
		var lastDelimiter = "/";

		var toHost = "";
		var issuerHost = "";

		if (to.contains(firstDelimiter)) {
			toHost = to.substring(to.indexOf(firstDelimiter) + firstDelimiter.length());
		}
		if (issuer.contains(firstDelimiter)) {
			issuerHost = issuer.substring(issuer.indexOf(firstDelimiter) + firstDelimiter.length());
		}

		if (toHost.contains(lastDelimiter)) {
			toHost = toHost.substring(0, toHost.indexOf(lastDelimiter));
		}

		if (issuerHost.contains(lastDelimiter)) {
			issuerHost = issuerHost.substring(0, issuerHost.indexOf(lastDelimiter));
		}

		return toHost.equals(issuerHost);
	}

	public static void validateTimestamp(SoapMessageHeader requestHeader, Instant now, SecurityChecks securityChecks) {
		ensurePresent(requestHeader);
		var timestamp = requestHeader.getRequestTimestamp();
		if (timestamp == null) {
			throw new RequestDeniedException("SOAP request header Timestamp missing");
		}
		if (!WsTrustUtil.validatePeriod("Timestamp", timestamp.getCreated(), timestamp.getExpires(),
				now, securityChecks.getNotBeforeToleranceSec(), securityChecks.getNotOnOrAfterToleranceSec())) {
			throw new RequestDeniedException("SOAP request header Timestamp invalid"); // details logged in validatePeriod
		}
	}

	public static String getSoapAction(SoapMessageHeader requestHeader) {
		var action = requestHeader.getAction();
		var soapAction = action != null ? action.getURI() : null;
		if (soapAction == null) {
			soapAction = requestHeader.getSoapAction();
		}
		// SOAP 1.1: evaluated as '""'
		if (StringUtils.isBlank(soapAction) || soapAction.equals("\"\"")) {
			soapAction = null;
		}
		log.debug("SOAP action={}", soapAction);
		return soapAction;
	}

}
