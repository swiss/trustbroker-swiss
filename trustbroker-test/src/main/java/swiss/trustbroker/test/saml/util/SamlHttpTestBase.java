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

package swiss.trustbroker.test.saml.util;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;

public interface SamlHttpTestBase {

	static String extractHtmlFormValue(String bodyStr, String formFieldName) {
		// hidden form field with name="SAMLRequest" value="base64" hopefully nobody changes the order
		// otherwise we need jsoup to parse HTML properly because this is really a bit crude
		int startNV = bodyStr.indexOf(formFieldName);
		if (startNV >= 0) {
			var valueArea = bodyStr.substring(startNV);
			var startElement = "value=\"";
			var startV = valueArea.indexOf(startElement);
			if (startV == -1) {
				// bodyStr would be interesting but contains full SAML assertion encoded (so replaceSensitiveData won't work)
				throw new IllegalArgumentException(
						String.format("Cannot extract value of form field %s from body - %s not found",
								formFieldName, startElement));
			}
			var value = valueArea.substring(startV + startElement.length());
			var endV = value.indexOf('"');
			if (endV == -1) {
				throw new IllegalArgumentException(
						String.format("Cannot extract value of form field %s from body - closing \" not found", formFieldName));
			}
			value = value.substring(0, endV);
			return value;
		}
		throw new IllegalArgumentException(String.format("No %s from field in HTML found, ignoring content", formFieldName));
	}

	default MessageContext extractSamlPostMessage(String samlB64) {
		// simulate a SAML POST on the servlet API as appController offers the functionality directly using opensaml
		Map<String, String[]> parameters = new HashMap<>();
		parameters.put(SamlIoUtil.SAML_REQUEST_NAME, new String[] { samlB64 });
		var request = buildHttpRequestForSamlString("POST", "https://localhost:3443/api/v1/saml", parameters);

		// extract SAML structure
		return OpenSamlUtil.decodeSamlPostMessage(request);
	}

	default RequestAbstractType extractSamlPostRequest(String bodyStr) {
		return extractSamlPostMessage(bodyStr, SamlIoUtil.SAML_REQUEST_NAME, RequestAbstractType.class);
	}

	default StatusResponseType extractSamlPostResponse(String bodyStr) {
		return extractSamlPostMessage(bodyStr, SamlIoUtil.SAML_RESPONSE_NAME, StatusResponseType.class);
	}

	default String extractSamlArtifactValue(String bodyStr) {
		return extractHtmlFormValue(bodyStr, SamlIoUtil.SAML_ARTIFACT_NAME);
	}

	@SuppressWarnings("unchecked")
	private <T extends SAMLObject> T extractSamlPostMessage(String bodyStr, String field, Class<T> type) {
		var samlB64 = extractHtmlFormValue(bodyStr, field);
		var messageContext = extractSamlPostMessage(samlB64);
		var message = messageContext.getMessage();
		if (!type.isAssignableFrom(message.getClass())) {
			throw new IllegalArgumentException(String.format("Message is of type %s expected %s",
					message.getClass().getName(), type.getName()));
		}
		return (T) message;
	}

	// this is abstract as the simple implementation uses MockHttpServletRequest from spring-mock,
	// and we don't want a mock dependency in the common project
	HttpServletRequest buildHttpRequestForSamlString(String httpMethod, String requestUri, Map<String, String[]> parameters);

}
