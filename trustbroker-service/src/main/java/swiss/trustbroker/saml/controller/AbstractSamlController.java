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

package swiss.trustbroker.saml.controller;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.saml.util.PolicyDecider;
import swiss.trustbroker.util.SamlValidator;

public abstract class AbstractSamlController {

	protected final TrustBrokerProperties trustBrokerProperties;

	protected final SamlValidator samlValidator;

	protected AbstractSamlController(
			TrustBrokerProperties trustBrokerProperties,
			SamlValidator samlValidator) {
		this.trustBrokerProperties = trustBrokerProperties;
		this.samlValidator = samlValidator;
	}

	protected SAMLObject decodeSamlMessage(MessageContext messageContext) {
		SAMLObject message = (SAMLObject)messageContext.getMessage();

		// debugging
		SamlTracer.logSamlObject(">>>>> Incoming SAML message", message);

		return message;
	}

	protected void validateSamlMessage(SAMLObject message, SecurityPolicies policies) {
		validateSamlSchema(message, policies);
		validateSamlIssuer(message);
	}

	protected void validateSamlSchema(SAMLObject message, SecurityPolicies policies) {
		if (PolicyDecider.isSchemaValidationEnabled(policies, trustBrokerProperties)) {
			samlValidator.validateSamlSchema(message);
		}
	}

	// SAML Issuer is treated as mandatory even though it's optional in the protocol
	protected void validateSamlIssuer(SAMLObject message) {
		String issuerId = OpenSamlUtil.getMessageIssuerId(message);
		if (issuerId == null) {
			throw new RequestDeniedException(String.format("Peer sends SAML message without an issuer: %s",
					OpenSamlUtil.samlObjectToString(message)));
		}
	}

	protected void handleUnsupportedMessage(SAMLObject message) {
		throw new RequestDeniedException(String.format("Message type of incoming request is not supported: %s",
				message.getClass().getSimpleName()));
	}

}
