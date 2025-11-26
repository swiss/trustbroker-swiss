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

package swiss.trustbroker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.common.util.WSSConstants;

/**
 * Class controls various security checks on a global level.
 * Global checks enabled per default.
 * During development or integration it might be necessary to have a temporary bail-out.
 * Some of the security checks should be done per RP or CP in which case they need to be configured in the corresponding XML.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityChecks {

	public static final long LIFETIME_MESSAGE_SEC = 480;

	public static final long LIFETIME_TOKEN_SEC = 3600;

	public static final long TOLERANCE_NOT_BEFORE_SEC = -5;

	public static final long TOLERANCE_NOT_AFTER_SEC = 480; // use notOnOrAfter timestamp _tolerance_ only

	public static final long RENEW_TOLERANCE_NOT_AFTER_SEC = 7200; // notOnOrAfter timestamp _tolerance_ for assertion RENEW

	/**
	 * Reject unsigned AuthnRequest?
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean requireSignedAuthnRequest = true;

	/**
	 * Reject unsigned ArtifactResolve?
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean requireSignedArtifactResolve = true;

	/**
	 * Reject unsigned ArtifactResponse?
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean requireSignedArtifactResponse = true;

	/**
	 * Reject unsigned Response?
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean requireSignedResponse = true;

	/**
	 * Reject unsigned Assertions?
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean requireSignedAssertion = true;

	/**
	 * Check incoming AuthnRequest at all.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateAuthnRequest = true;

	/**
	 * Reject request without getAuthnContextClassRef or Qoa configuration
	 * <br/>
	 * Default: false
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean enforceQoaIfMissing = false;

	/**
	 * Check incoming WSTrust SecurityTokenRequest on WSS4J level.
	 * <br/>
	 * Default: <code>false</code>
 	 */
	@Builder.Default
	private boolean validateSecurityTokenRequest = false;

	/**
	 * Check incoming WSTrust SecurityTokenRequest on XTB validator level.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateSecurityTokenRequestAssertion = true;

	/**
	 * WSS4J checks according to WSS4J actions.
	 * <br/>
	 * Default: Timestamp. Signature, SAMLTokenSigned
	 *
	 * @see <a href="https://ws.apache.org/wss4j/config.html">wss4j</a>
 	 */
	@Builder.Default
	private String wss4jChecks = WSSConstants.TIMESTAMP + " "
			+ WSSConstants.SIGNATURE + " " + WSSConstants.SAML_TOKEN_SIGNED;

	/**
	 * Check XML schema.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateXmlSchema = true;

	/**
	 * Validate HTTP request headers. Currently <code>referer</code> and <code>origin</code> can be validated against the
	 * AcWhitelist of an RP.
	 * <br/>
	 * Default: true
	 * @since 1.12.0
	 */
	@Builder.Default
	private boolean validateHttpHeaders = true;

	/**
	 * Check assertion consumer URL or HTTP Referer against configured whitelist.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateAcs = true;

	/**
	 * Relay must exist otherwise the SAML processing is stopped, if false response matching is done via SAML message.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateRelayState = true;

	/**
	 * Check audience restriction against issuer.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateAudience = true;

	/**
	 * Shall message contain an audience restriction? Very optional feature according to SAML2 spec.
	 * <br/>
	 * Default: false
 	 */
	@Builder.Default
	private boolean requireAudienceRestriction = false;

	/**
	 * Check issuer in the CP response to match what the user has selected as a homeRealm in HRD.
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean validateResponseIssuer = true;

	/**
	 * In WS-Trust RST case we per default require a valid subject confirmation.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean requireSubjectConfirmation = true;

	/**
	 * Check subject confirmation timestamp.
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean validateSubjectConfirmationTimestamp = true;

	/**
	 * Check subject confirmation inResponseTo.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateSubjectConfirmationInResponseTo = true;

	/**
	 * Check subject confirmation recipient.
	 * <br/>
	 * Default: true
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean validateSubjectConfirmationRecipient = true;

	/**
	 * Validate OID Logout request.
	 * <br/>
	 * Default: false
	 */
	@Builder.Default
	private boolean validateLogoutRequest = false;

	/**
	 * Any timestamp tolerance NTP drift tolerance.
	 * <br/>
	 * Default: -5
 	 */
	@Builder.Default
	private long notBeforeToleranceSec = TOLERANCE_NOT_BEFORE_SEC;

	/**
	 * Any timestamp clock/transfer tolerance.
	 * <br/>
	 * Default: 480 (a lot, might be reduced to 5)
	 */
	@Builder.Default
	private long notOnOrAfterToleranceSec = TOLERANCE_NOT_AFTER_SEC;

	/**
	 * Duration after expiration of an assertion for which RENEW request is accepted.
	 * <br/>
	 * Default: 2h
	 * @since 1.11.0
	 */
	@Builder.Default
	private long renewNotOnOrAfterToleranceRenewSec = RENEW_TOLERANCE_NOT_AFTER_SEC;

	/**
	 * IssueInstant timestamp check should accept Assertion.Condition.NotValidOnOrAfter over WS-Trust.
	 * <br/>
	 * Default: 480
 	 */
	@Builder.Default
	private long messageLifetimeSec = LIFETIME_MESSAGE_SEC;

	/**
	 * Used for Condition.notOnOrAfterSeconds and SubjectConfirmationData.notOnOrAfterSeconds.
	 * Override per RP using SecurityPolicies.notOnOrAfterSeconds.
	 * <br/>
	 * Default: 3600
 	 */
	@Builder.Default
	private long tokenLifetimeSec = LIFETIME_TOKEN_SEC;

	/**
	 * 	Acceptable subject confirmation methods. Comma separated list.
	 * 	<br/>
	 * 	Default: urn:oasis:names:tc:SAML:2.0:cm:holder-of-key,urn:oasis:names:tc:SAML:2.0:cm:bearer
 	 */
	@Builder.Default
	private String acceptSubjectConfirmationMethods
			= "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key,urn:oasis:names:tc:SAML:2.0:cm:bearer";

	/**
	 * Register state in DB even when validation fails.
	 * (Was used for discontinued stealth mode processing only.)
	 * <br/>
	 * Default: false
 	 */
	@Builder.Default
	private boolean saveStateOnValidationFailure = false;

	/**
	 * Sign Assertion in outgoing messages.
	 * <br/>
	 * Default: true
	 */

	@Builder.Default
	private boolean doSignAssertions = true;

	/**
	 * Sign outgoing Response messages with success state.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean doSignSuccessResponse = true;

	/**
	 * Sign outgoing Response messages with failure state.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean doSignFailureResponse = true;

	/**
	 * Sign outgoing ArtifactResolve messages.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean doSignArtifactResolve = true;

	/**
	 * Sign outgoing ArtifactResponse messages.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean doSignArtifactResponse = true;

	/**
	 * Enforce CP authentication via corresponding OIDC/SAML flags.
	 * <br/>
	 * Default: true (since 1.10.0 the hard coded default was true, before it was false)
	 * @since 1.11.0
	 */
	@Builder.Default
	private boolean forceCpAuthentication = true;

	/**
	 * Check IssueInstant attribute in AuthnRequest
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateRequestIssueInstant = true;

	/**
	 * Check Condition attribute in AuthnRequest
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateRequestCondition = true;

	/**
	 * Check IssueInstant attribute in Response
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateResponseIssueInstant = true;

	/**
	 * Check IssueInstant attribute in Assertion
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean validateAssertionIssueInstant = true;

	/**
	 * Check IssueInstant attribute in AuthnStatement
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean validateAuthnStatementIssueInstant = true;

}
