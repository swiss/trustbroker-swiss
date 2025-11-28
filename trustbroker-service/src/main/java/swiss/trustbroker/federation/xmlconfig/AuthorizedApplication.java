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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.Optional;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;

/**
 * This class describes the configuration of an application to be authorized by AccessRequest.
 */
@XmlRootElement(name = "AuthorizedApplication")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizedApplication implements Serializable {

	// application

	/**
	 * Required application name (usually corresponding to IDM).
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * 	If an RP contains multiple OIDC clients and AccessRequest configurations and the OIDC client_id or the
	 * 	applicationName (provided viy AuthnRequest.ProviderName) does not match the 'name', this attribute can be used
	 * 	to establish the relation.
	 */
	@XmlAttribute(name = "clientId")
	private String clientId;

	/**
	 * The application can be selected via HTTP Referer matching by configuring the Origin URL in this attribute.
	 */
	@XmlAttribute(name = "url")
	private String url;

	/**
	 * If configured the value is sent as appUrl instead of sending app=name in the INTERACTIVE AccessRequest.
	 *
	 * @since 1.12.0
	 */
	@XmlAttribute(name = "applUrl")
	private String applUrl;

	/**
	 * Matched against minimum QOA from SAML AuthnContextClassRef.
	 * When an RP has multiple applications, and they cannot be differentiated via HTTP Referer,
	 * the minimum AuthnContextClassRef in the AuthnRequest can be used to select the application.
	 * <br/>
	 * Optional, not recommended.
 	 */
	@XmlAttribute(name = "minQoa")
	private Integer minQoa;

	// silent and interactive AR
	// (interactive AR refers to a mode with user interaction, silent to one without)

	/**
	 * Mode to be used for the AccessRequest, depending on the implementation.
	 */
	@XmlAttribute(name = "mode")
	private String mode;

	/**
	 * 	AccessRequest can be triggered by calling application.
 	 */
	@XmlAttribute(name = "enableTrigger")
	private Boolean enableTrigger;

	/**
	 * When the given role is missing after the IDM lookup phase (and before the profile selection phase) the
	 * access-request handling is initiated.
	 */
	@XmlAttribute(name = "triggerRole")
	private String triggerRole;

	/**
	 * Service URL to be called by AccessRequest.
	 */
	@XmlAttribute(name = "serviceUrl")
	private String serviceUrl;

	/**
	 * Overrides the global AccessRequest recipientId. Fallback to serviceUrl.
 	 */
	@XmlAttribute(name = "recipient")
	private String recipient;

	/**
	 * Overrides the global issuer.
 	 */
	@XmlAttribute(name = "issuerId")
	private String issuerId;

	// interactive AR

	/**
	 * Optional request parameter added to URLs.
	 */
	@XmlAttribute(name = "centralCICD")
	private String centralCICD;

	// silent AR

	/**
	 * Overrides the RP ID in requests sent by the AccessRequest.
	 */
	@XmlAttribute(name = "endpointReferenceAddress")
	private String endpointReferenceAddress;

	/**
	 * Validate assertions in responses to requests sent by the AccessRequest.
	 * <br/>
	 * Default: false
 	 */
	@XmlAttribute(name = "validateAssertion")
	private Boolean validateAssertion;

	/**
	 * URL to be redirected to after AccessRequest.
	 */
	@XmlAttribute(name = "redirectUrl")
	private String redirectUrl;

	boolean checkUrl() {
		return StringUtils.isNotEmpty(url);
	}

	boolean urlMatching(String referrer) {
		return referrer != null && referrer.contains(url);
	}

	boolean checkQoa() {
		return minQoa != null;
	}

	boolean qoaMatching(Optional<Integer> requestMinQoa) {
		return requestMinQoa.isPresent() && minQoa.equals(requestMinQoa.get());
	}

	/**
	 * @return true if referrer and QOA are present and matching if they need to, false if none is required (default application)
	 */
	public boolean matchUrlAndQoa(String referrer, Optional<Integer> requestMinQoa) {
		if (!checkUrl() && !checkQoa()) {
			return false;
		}
		return (!checkUrl() || urlMatching(referrer)) && (!checkQoa() || qoaMatching(requestMinQoa));
	}

	public boolean matchName(String applicationName) {
		if (applicationName == null) {
			return false;
		}
		return applicationName.equals(name);
	}

	public boolean matchClientId(String clientId) {
		if (clientId == null) {
			return false;
		}
		return clientId.equals(this.clientId) || clientId.equals(name);
	}

	public boolean isDefaultApplication() {
		return !checkUrl() && !checkQoa() && (clientId == null) && (name == null);
	}

	/**
	 * @return true if referrer, QOA, and oidClientId are either missing or do not need to match (if clientId is not set
	 * it is a valid default application, even though name could match the input clientId)
	 */
	public boolean noCheckOrEmpty(String referrer, Optional<Integer> requestMinQoa, String clientId, String applicationName) {
		return (referrer == null || !checkUrl()) && (requestMinQoa.isEmpty() || !checkQoa()) &&
				(clientId == null || this.clientId == null) && (applicationName == null || name == null);
	}

}
