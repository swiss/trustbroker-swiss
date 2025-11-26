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
import java.util.Objects;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.common.saml.dto.SamlBinding;

/**
 * Single logout (SLO) configurations for an RP.
 */
@XmlRootElement(name = "SloResponse")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SloResponse implements Serializable {

	/**
	 * The mode of this entry.
	 * <br/>
	 * Default: RESPONSE
	 */
	@XmlAttribute(name = "mode")
	@Builder.Default
	private SloMode mode = SloMode.RESPONSE;

	/**
	 * The protocol for which this entry applies.
	 * <br/>
	 * Default: SAML2
	 */
	@XmlAttribute(name = "protocol")
	@Builder.Default
	private SloProtocol protocol = SloProtocol.SAML2;

	/**
	 * The protocol binding for which this entry applies.
	 * <br/>
	 * Default: POST (ignored for OIDC)
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "binding")
	@Builder.Default
	private SamlBinding binding = SamlBinding.POST;

	/**
	 * Issuer for SAML LogoutResponse.
	 * <br/>
	 * Overrides the globally configured issuer.
	 */
	@XmlAttribute(name = "issuer")
	private String issuer;

	/**
	 * Enables OIDC <pre>frontchannel_logout_session_required</pre>.
	 * <br/>
	 * Default: false
	 *
	 * @see <a href="https://openid.net/specs/openid-connect-frontchannel-1_0.html">OpenID Connect Front-Channel Logout</a>
 	 */
	@XmlAttribute(name = "sessionRequired")
	@Builder.Default
	private Boolean sessionRequired = Boolean.FALSE;

	/**
	 * Use notification cross-protocol (i.e. use protocol=OIDC even if RP is a SAML SSO session participant and vice versa).
	 * <br/>
	 * Note: protocol HTTP is always used crossProtocol.
	 * <br/>
	 * Default: false
 	 */
	@XmlAttribute(name = "crossProtocol")
	@Builder.Default
	private Boolean crossProtocol = Boolean.FALSE;

	/**
	 * Valid settings are:
	 * <ul>
	 *     <li>An absolute URL (used as is)</li>
	 *     <li>A relative URL (path) that is appended to the HTTP referrer or ACUrl URL</li>
	 * </ul>
	 */
	@XmlAttribute(name = "url")
	private String url;

	/**
	 * Perform ACUrl matching for absolute url, prefix with ACUrl scheme/host/port for relative URL.
	 * <br/>
	 * Defaults to false: use this URL regardless of what ACUrls were used for the RP in the current SSO session.
 	 */
	@XmlAttribute(name = "matchAcUrl")
	@Builder.Default
	private Boolean matchAcUrl = Boolean.FALSE;

	/**
	 * 	Override RPs signer for SAML2 LogoutRequest notifications(the LogoutResponse is always signed with RPs signer).
 	 */
	@XmlElement(name = "SignerKeystore")
	private SignerKeystore signerKeystore;

	private transient Credential sloSigner;

	// XmlTransient not allowed on transient field (the Javadoc does not say transient is considered XmlTransient)
	@XmlTransient
	public Credential getSloSigner() {
		return sloSigner;
	}

	public boolean hasSloUrlForResponse(SloProtocol protocol) {
		return isResponse(protocol) && StringUtils.isNotEmpty(url);
	}

	public boolean hasIssuerForResponse(SloProtocol protocol) {
		return isResponse(protocol) && StringUtils.isNotEmpty(issuer);
	}

	public boolean isResponse(SloProtocol protocol) {
		return mode.isResponse() && this.protocol == protocol;
	}

	public boolean isNotification(SloProtocol protocol) {
		return mode.isNotification() && (this.protocol == protocol || useCrossProtocol());
	}

	private boolean useCrossProtocol() {
		return Boolean.TRUE.equals(crossProtocol) || this.protocol.isCrossProtocol();
	}

	public boolean matchAcUrl() { return Boolean.TRUE.equals(matchAcUrl); }

	public boolean isOidcSessionRequired() {
		return protocol == SloProtocol.OIDC && Boolean.TRUE.equals(sessionRequired);
	}

	// used to determine if the definition is a duplicate (same protocol just with different mode)
	// ignores mode and derived sloSigner
	public boolean isSameExceptMode(SloResponse response) {
		return response != null &&
			Objects.equals(protocol, response.protocol) &&
				Objects.equals(issuer, response.issuer) &&
				Objects.equals(sessionRequired, response.sessionRequired) &&
				Objects.equals(url, response.url) &&
				Objects.equals(matchAcUrl, response.matchAcUrl) &&
				Objects.equals(crossProtocol, response.crossProtocol) &&
				Objects.equals(signerKeystore, response.signerKeystore);
	}

}
