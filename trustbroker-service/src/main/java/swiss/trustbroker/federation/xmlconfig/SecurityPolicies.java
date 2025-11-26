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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This class allows configuring policies per CP/RP as opposed to SecurityChecks on a global level.
 *
 * Breaking changes:
 * <ul>
 *     <li>Specification alignment: With 1.10.0 <code>requireSignedLogoutRequest</code> is applied to incoming LogoutRequests as
 *     specified (instead of <code>requireSignedAuthnRequest</code> used in previous releases).<br/>
 *     The new <code>requireSignedLogoutNotificationRequest</code> now controls outbound LogoutRequests sent as SLO
 *     notifications (instead of <code>requireSignedLogoutRequest</code> used in previous releases).</li>
 * </ul>
 */
@XmlRootElement(name = "SecurityPolicies")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityPolicies implements Serializable {

	/**
	 * Allow to disable signature check for incoming SAML AuthnRequests.
	 * <br/>
	 * Default: true
	 */
	@XmlAttribute(name = "requireSignedAuthnRequest")
	@Builder.Default
	private Boolean requireSignedAuthnRequest = Boolean.TRUE;

	/**
	 * Allow to disable signature check for incoming LogoutRequests.
	 * <br/>
	 * Default: true
	 */
	@XmlAttribute(name = "requireSignedLogoutRequest")
	@Builder.Default
	private Boolean requireSignedLogoutRequest = Boolean.TRUE;

	/**
	 * Allow to disable signature check for outgoing SLO notification LogoutRequests.
	 * <br/>
	 * Default: true
	 *
	 * @see SloResponse
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "requireSignedLogoutNotificationRequest")
	@Builder.Default
	private Boolean requireSignedLogoutNotificationRequest = Boolean.TRUE;

	/**
	 * Flag allows to enforce signed SAML responses from CP required for maximum security to assert integrity of the incoming
	 * message and assertion. There is no requireSignedAssertion yet as this data structure is the actual data to trust.
	 * The check can therefore not be disabled for security reasons.
	 * <br/>
	 * Overrides global SecurityChecks
	 */
	@XmlAttribute(name = "requireSignedResponse")
	private Boolean requireSignedResponse;

	/**
	 * Allow to disable required encrypted Assertion when the EncryptionKeystore is configured.
	 * <br/>
	 * Default: true
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "requireEncryptedAssertion")
	@Builder.Default
	private Boolean requireEncryptedAssertion = Boolean.TRUE;

	/**
	 * Flag allows to enforce signed SAML artifact responses from CP required for maximum security to assert integrity of the
	 * incoming artifact response message.
	 * <br/>
	 * Overrides global SecurityChecks
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "requireSignedArtifactResponse")
	private Boolean requireSignedArtifactResponse;

	/**
	 * Flag allows to sign outbound SAML artifact resolve messages for maximum security.
	 * <br/>
	 * Overrides global SecurityChecks
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "doSignArtifactResolve")
	private Boolean doSignArtifactResolve;

	/**
	 * Overrides global SecurityChecks
 	 */
	@XmlAttribute(name = "requireAudienceRestriction")
	private Boolean requireAudienceRestriction;

	/**
	 * Require signed SAML AuthnRequests to join an SSO session. If not set, falls back to <code>requireSignedAuthnRequest</code>.
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "requireSignedAuthnRequestForSsoJoin")
	private Boolean requireSignedAuthnRequestForSsoJoin;

	/**
	 * Overrides the global <code>tokenLifetimeSec</code> for CP response AuthnInstant checks.
	 * <br/>
	 * Defaults to 60 minutes, override if needed.
	 * This is quite long time to transfer a SAML token from the issuer to its consumer to establish a relation between a user and
	 * the consuming RP. Tje problem is that some components cache the token and transfer it later.
	 */
	@XmlAttribute(name = "notOnOrAfterSeconds")
	@Builder.Default
	private Integer notOnOrAfterSeconds = 3600;

	/**
	 * Overrides the global <code>notOnOrAfterSeconds</code> for conditions <code>notOnOrAfter</code> if greater than zero.
	 */
	@XmlAttribute(name = "audienceNotOnOrAfterSeconds")
	private Integer audienceNotOnOrAfterSeconds;

	/**
	 * If CP returns AuthnContext of value less than that, no SSO session is created.
	 */
	@XmlAttribute(name = "ssoMinQoaLevel")
	private Integer ssoMinQoaLevel;

	/**
	 * Some claims providers are not sending well-formed valid XML and therefore are blocked by XTB. The schema check can be
	 * disabled lowering the security barrier and let OpenSAML deal with the data directly.
	 * <br/>
	 * Default: true
	 */
	@XmlAttribute(name = "validateXmlSchema")
	@Builder.Default
	private Boolean validateXmlSchema = Boolean.TRUE;

	/**
	 * Validate HTTP request headers. Currently <code>referer</code> and <code>origin</code> can be validated against the
	 * AcWhitelist of an RP.
	 * @since 1.12.0
	 */
	@XmlAttribute(name = "validateHttpHeaders")
	private Boolean validateHttpHeaders;

	/**
	 * Control CP AuthnRequest scopes and RP Attribute OriginalIssuer.
	 * Defaults to null as RP and CP side default behavior differs
	 */
	@XmlAttribute(name = "delegateOrigin")
	private Boolean delegateOrigin;

	/**
	 * Always enforce re-authentication on this CP/on all CPs configured for this RP.
	 * <br/>
	 * Overrides the global <code>forceCpAuthentication</code>.
	 * <br/>
	 * Default: false (only enforced if RP requests it)
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "forceAuthn")
	private Boolean forceAuthn;

}
