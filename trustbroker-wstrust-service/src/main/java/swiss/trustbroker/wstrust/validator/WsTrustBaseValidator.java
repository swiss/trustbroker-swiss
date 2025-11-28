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

import java.time.Clock;
import java.util.List;
import java.util.Optional;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.security.credential.Credential;
import org.springframework.util.CollectionUtils;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

/**
 * Base class for WS-Trust request validators.
 */
@AllArgsConstructor
@Slf4j
public abstract class WsTrustBaseValidator implements WsTrustValidator {

	@Getter(AccessLevel.PROTECTED)
	private final TrustBrokerProperties trustBrokerProperties;

	@Getter(AccessLevel.PROTECTED)
	private final RelyingPartySetupService relyingPartySetupService;

	@Getter(AccessLevel.PROTECTED)
	private final Clock clock;

	/**
	 * @return true if credentials present and the assertion has a signature that was successfully validated
	 */
	protected AssertionValidator.MessageValidationResult validateAssertion(Assertion assertion,
			AssertionValidator.ExpectedAssertionValues expectedValues, Optional<List<Credential>> credentials) {
		// Validate the assertion on XTB level only per default. The wss4j layer doing the same is deprecated and can be dropped.
		if (trustBrokerProperties.getSecurity().isValidateSecurityTokenRequestAssertion()) {
			return AssertionValidator.validateRstAssertion(
					assertion, trustBrokerProperties, null, null, clock.instant(), expectedValues, credentials);
		}
		log.warn("trustbroker.config.security.validateSecurityTokenRequestAssertion=false, XTB validation disabled!!!");
		return AssertionValidator.MessageValidationResult.unvalidated();
	}

	protected RelyingParty getRecipientRelyingParty(Assertion assertion) {
		if (assertion == null || assertion.getConditions() == null ||
				CollectionUtils.isEmpty(assertion.getConditions().getAudienceRestrictions())) {
			throw new RequestDeniedException(String.format(
					"Assertion in RSTR with assertionID='%s' missing Conditions",
					assertion != null ? assertion.getID() : null));
		}
		var audiences = assertion.getConditions().getAudienceRestrictions().stream()
								 .flatMap(restrictions -> restrictions.getAudiences().stream())
								 .map(Audience::getURI)
								 .toList();
		// Assertion issued by XTB - there must be one audience
		if (audiences.size() != 1) {
			throw new RequestDeniedException(String.format(
					"Assertion in RSTR with assertionID='%s' expected to have a single audience but has audiences='%s'",
					assertion.getID(), audiences));
		}
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(audiences.get(0), null);
		if (CollectionUtils.isEmpty(relyingParty.getRpTrustCredentials())) {
			throw new RequestDeniedException(String.format(
					"Assertion in RSTR with assertionID='%s' audience rpIssuerId='%s' has no SignerTruststore",
					assertion.getID(), relyingParty.getId()));
		}
		log.debug("Assertion in RSTR with assertionID='{}' has audience rpIssuerId='{}'", assertion.getID(), relyingParty.getId());
		return relyingParty;
	}

	protected void validateSignature(SoapMessageHeader soapMessageHeader, boolean requireSignature,
			List<Credential> trustCredentials) {
		if (!requireSignature && soapMessageHeader.getSoapMessage() == null) {
			log.warn("Missing SOAP message"); // occurs in tests only
			return;
		}
		log.info("Validating SOAP signature");
		var node = WsTrustUtil.getNode(soapMessageHeader.getSoapMessage().getEnvelope());
		if (!(node instanceof Element element)) {
			throw new TechnicalException(String.format("XML node=%s is not an Element", node.getNodeName()));
		}
		var signature = soapMessageHeader.getSignature();
		var signatureElement = signature != null ? signature.getDOM() : null;
		if (!SoapUtil.isSignatureValid(element, signatureElement, trustCredentials)) {
			if (requireSignature) {
				throw new RequestDeniedException(
						String.format("Signature validation failed for element=%s", element.getNodeName()));
			}
			else if (signature != null) {
				log.warn("Accepting invalid signature={} on element={}", signatureElement.getNodeName(), element.getNodeName());
			}
		}
	}


}
