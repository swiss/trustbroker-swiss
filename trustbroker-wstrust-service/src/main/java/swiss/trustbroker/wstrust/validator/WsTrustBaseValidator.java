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

package swiss.trustbroker.wstrust.validator;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.springframework.util.CollectionUtils;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
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
			AssertionValidator.ExpectedAssertionValues expectedValues, Optional<List<Credential>> credentials,
			boolean requireSignedAssertion, RequestSecurityToken request, ClaimsParty claimsParty, RelyingParty relyingParty) {
		// Validate the assertion on XTB level only per default. The wss4j layer doing the same is deprecated and can be dropped.
		if (trustBrokerProperties.getSecurity().isValidateSecurityTokenRequestAssertion()) {
			try {
				return validateAssertionWithCorrection(assertion, expectedValues, credentials,
						request, claimsParty, relyingParty);
			}
			catch (RequestDeniedException ex) {
				if (requireSignedAssertion || ex.getErrorCode() != StandardErrorCode.SIGNATURE_NOT_OK) {
					throw ex;
				}
				log.warn("Assertion validation failed requireSignedAssertion=false message={}", ex.getInternalMessage());
				return AssertionValidator.MessageValidationResult.unvalidated();
			}
		}
		log.warn("trustbroker.config.security.validateSecurityTokenRequestAssertion=false, XTB validation disabled!!!"
				+ " requireSignedAssertion={}", requireSignedAssertion);
		return AssertionValidator.MessageValidationResult.unvalidated();
	}

	private AssertionValidator.MessageValidationResult validateAssertionWithCorrection(Assertion assertion,
			AssertionValidator.ExpectedAssertionValues expectedValues, Optional<List<Credential>> credentials,
			RequestSecurityToken request, ClaimsParty claimsParty, RelyingParty relyingParty) {
		try {
			return AssertionValidator.validateRstAssertion(
					assertion, trustBrokerProperties, null, null, clock.instant(), expectedValues, credentials);
		}
		catch (RequestDeniedException ex) {
			if (assertion == null || ex.getErrorCode() != StandardErrorCode.SIGNATURE_NOT_OK) {
				throw ex;
			}
			List<Assertion> assertions = new ArrayList<>(1);
			assertions.add(assertion);
			if (!correctAssertionForSignatureValidation(assertions, request, claimsParty, relyingParty)) {
				throw ex;
			}
			if (assertions.isEmpty()) {
				log.warn("Ignoring assertion validation exception error={}", ex.getInternalMessage());
				return AssertionValidator.MessageValidationResult.unvalidated();
			}
			if (assertions.size() > 1) {
				throw new TechnicalException("Contract violation - multiple assertions returned by correction call");
			}
			log.info("Retrying assertion validation with patched assertion after exception error={}", ex.getInternalMessage());
			return AssertionValidator.validateRstAssertion(
					assertions.get(0), trustBrokerProperties, null, null, clock.instant(), expectedValues, credentials);
		}
	}

	/**
	 * Transitional: Called if signature validation fails on the Assertion.
	 * @param singletonListWithAssertion
	 * 	Modifiable list with exactly one assertion that can be modified or replaced.
	 *  If the list is empty at the end, the failing validation is accepted - unless a valid signature is required.
	 *  Else the validation is retried with the assertion.
	 *  May throw RequestDeniedException.
	 * @param request passed down from validateAssertion
	 * @param claimsParty passed down from validateAssertion
	 * @param relyingParty passed down from validateAssertion
	 * @return false no correction performed (default), true correction performed, check singletonListWithAssertion again
	 */
	protected boolean correctAssertionForSignatureValidation(List<Assertion> singletonListWithAssertion,
			RequestSecurityToken request, ClaimsParty claimsParty, RelyingParty relyingParty) {
		return false;
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

	protected RelyingParty getRstRelyingParty(RequestSecurityToken requestSecurityToken) {
		String endpointReferenceAddress = null;
		try {
			endpointReferenceAddress = WsTrustUtil.getAddressFromRequest(requestSecurityToken);
		}
		catch (RuntimeException ex) {
			log.warn("Missing Address in RST: {}", ex.getMessage());
		}
		if (endpointReferenceAddress == null) {
			endpointReferenceAddress = WsTrustUtil.getEndpointReferenceAddress(requestSecurityToken);
		}
		if (endpointReferenceAddress == null) {
			log.error("RST missing AppliesTo.EndpointReference.Address");
			return null;
		}
		// if we have an address, the config must exist
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(endpointReferenceAddress, null);
		if (CollectionUtils.isEmpty(relyingParty.getRpTrustCredentials())) {
			throw new RequestDeniedException(String.format(
					"RST with EndpointReferenceAddress rpIssuerId='%s' has no SignerTruststore", relyingParty.getId()));
		}
		log.debug("RST has EndpointReferenceAddress rpIssuerId='{}'", relyingParty.getId());
		return relyingParty;
	}

	protected ClaimsParty getIssuingClaimsParty(Assertion assertion) {
		var issuerId = WsTrustUtil.getIssuerId(assertion);
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(issuerId, null);
		if (CollectionUtils.isEmpty(claimsParty.getCpTrustCredential())) {
			throw new RequestDeniedException(String.format(
					"Assertion in RSTR with assertionID='%s' issuer cpIssuerId='%s' has no SignerTruststore",
					assertion.getID(), claimsParty.getId()));
		}
		log.debug("Assertion in RSTR with assertionID='{}' has issuer cpIssuerId='{}'", assertion.getID(), claimsParty.getId());
		return claimsParty;
	}

	protected void validateSignature(SoapMessageHeader soapMessageHeader, boolean requireSignature,
			List<Credential> trustCredentials) {
		if (!requireSignature && soapMessageHeader.getSoapMessage() == null) {
			log.warn("Missing SOAP message"); // occurs in tests only
			return;
		}
		log.debug("Validating SOAP signature");
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
			else {
				log.info("Missing signature on element={}", element.getNodeName());
			}
		}
	}


}
