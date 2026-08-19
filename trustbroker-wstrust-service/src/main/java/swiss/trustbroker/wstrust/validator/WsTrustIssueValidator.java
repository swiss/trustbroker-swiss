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
import java.util.function.BiFunction;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.WsTrustBinding;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

/**
 * Validator for WS-Trust ISSUE requests.
 */
@Component
@Slf4j
public class WsTrustIssueValidator extends WsTrustBaseValidator {

	private static final String REQUEST_TYPE = RequestType.ISSUE;

	private final ScriptService scriptService;

	public WsTrustIssueValidator(
			TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService,
			ScriptService scriptService, Clock clock) {
		super(trustBrokerProperties, relyingPartySetupService, clock);
		this.scriptService = scriptService;
	}

	@Override
	public boolean applies(RequestType requestType) {
		if (!REQUEST_TYPE.equals(requestType.getURI())) {
			return false;
		}
		if (!enabled()) {
			log.error("RequestType in RSTR requestType='{}' but ISSUE disabled in configuration", requestType.getURI());
			return false;
		}
		return true;
	}

	@Override
	protected WsTrustBinding getBinding() {
		return WsTrustBinding.ISSUE;
	}

	@Override
	public WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader) {
		var relyingParty = getRstRelyingParty(requestSecurityToken);
		var headerAssertion = requestHeader.getAssertion();
		var claimsParty = getIssuingClaimsParty(headerAssertion);
		validateHeaderElements(requestHeader, relyingParty, claimsParty);
		log.debug("RSTR ISSUE request - assertion is in header");
		if (requestHeader.getSecurityToken() != null) {
			log.info("RSTR with requestType='{}' ignoring header security token", REQUEST_TYPE);
		}
		// each side can provide the WsTrust config default for the other:
		validateProtocolRestrictions(claimsParty, relyingParty);
		validateProtocolRestrictions(relyingParty, claimsParty);
		var requireSignedRequest = calculateProperty(claimsParty, relyingParty,
				getTrustBrokerProperties().getWstrust().isIssueRequireSignedRequests(),
				CounterParty::wsTrustIssueRequireSignedRequest,
				"requireSignedRequest");
		List<Credential> messageTrustCredentials = getMessageSignerCredentials(relyingParty, claimsParty);
		validateSignature(requestHeader, requireSignedRequest, messageTrustCredentials);
		var requireSignedAssertion = calculateProperty(claimsParty, relyingParty,
				getTrustBrokerProperties().getWstrust().isIssueRequireSignedAssertions(),
				CounterParty::wsTrustIssueRequireSignedAssertion, "requireSignedAssertion");
		validateAssertion(headerAssertion, null, Optional.of(claimsParty.getCpTrustCredential()),
				getAllowedSignatureAlgorithms(claimsParty), requireSignedAssertion, requestSecurityToken,
				claimsParty, relyingParty);

		var keyType = WsTrustUtil.getKeyTypeFromRequest(requestSecurityToken);
		if (!KeyType.BEARER.equals(keyType)) {
			throw new RequestDeniedException(String.format(
					"Wrong KeyType in RSTR with assertionID='%s' keyType='%s' expectedKeyType='%s'",
					headerAssertion != null ? headerAssertion.getID() : null, keyType, KeyType.BEARER));
		}

		return WsTrustValidationResult.builder()
									  .requestType(REQUEST_TYPE)
									  .validatedAssertion(headerAssertion)
									  .recomputeAttributes(true)
									  .issuerId(relyingParty.getId())
									  .recipientId(null) // not set
									  .useAssertionLifetime(false)
									  .createResponseCollection(true)
									  .build();
	}

	private void validateHeaderElements(SoapMessageHeader requestHeader, RelyingParty relyingParty, ClaimsParty claimsParty) {
		var requireTimestamp = calculateProperty(claimsParty, relyingParty,
				getTrustBrokerProperties().getWstrust().isIssueRequireTimestamp(), CounterParty::wsTrustIssueRequireTimestamp,
				"requireTimestamp");
		var notBeforeToleranceSec = calculateProperty(claimsParty, relyingParty,
				getTrustBrokerProperties().getSecurity().getNotBeforeToleranceSec(),
				CounterParty::getWsTrustIssueNotBeforeToleranceSec, "notBeforeToleranceSec");
		var notOnOrAfterToleranceSec = calculateProperty(claimsParty, relyingParty,
				getTrustBrokerProperties().getSecurity().getNotOnOrAfterToleranceSec(),
				CounterParty::getWsTrustIssueNotOnOrAfterToleranceSec, "notOnOrAfterToleranceSec");
		log.debug("Validate WSTrust ISSUE SOAP headers for rpIssuerId={} cpIssuerId={}",
				relyingParty.getId(), claimsParty.getId());
		WsTrustHeaderValidator.validateTimestamp(requestHeader, getClock().instant(),
				notBeforeToleranceSec, notOnOrAfterToleranceSec, requireTimestamp, relyingParty.getId(), claimsParty.getId());
		WsTrustHeaderValidator.validateHeaderElements(requestHeader, getTrustBrokerProperties().getIssuer());
	}

	// sender and signer of SOAP can be CP or RP
	private static List<Credential> getMessageSignerCredentials(RelyingParty relyingParty, ClaimsParty claimsParty) {
		if (CollectionUtils.isEmpty(relyingParty.getRpTrustCredentials())) {
			return claimsParty.getCpTrustCredential();
		}
		List<Credential> messageTrustCredentials = new ArrayList<>(claimsParty.getCpTrustCredential());
		messageTrustCredentials.addAll(relyingParty.getRpTrustCredentials());
		return messageTrustCredentials;
	}

	@Override
	protected boolean correctAssertionForSignatureValidation(List<Assertion> singletonListWithAssertion,
			RequestSecurityToken request, ClaimsParty claimsParty, RelyingParty relyingParty) {
		var result = false; // true if any script was run
		if (claimsParty != null) {
			result |= scriptService.processCpWsTrustOnAssertion(request, singletonListWithAssertion, claimsParty.getId(), null);
		}
		if (relyingParty != null) {
			result |= scriptService.processRpWsTrustOnAssertion(request, singletonListWithAssertion, relyingParty.getId(), null);
		}
		return result;
	}

	static <T> T calculateProperty(ClaimsParty claimsParty, RelyingParty relyingParty, T defaultValue,
			BiFunction<CounterParty, T, T> property, String propertyName) {
		// Explicit CP config value overrides global default:
		var propertyValue = calculateProperty(claimsParty, defaultValue, property);
		// Explicit RP config value overrides CP:
		propertyValue = calculateProperty(relyingParty, propertyValue, property);
		log.info("Enforcing {}={} for cpIssuerId={} rpIssuerId={}",
				propertyName, propertyValue, claimsParty.getId(), relyingParty != null ? relyingParty.getId() : null);
		return propertyValue;
	}

	private static <T> T calculateProperty(CounterParty counterParty, T defaultValue, BiFunction<CounterParty, T, T> property) {
		if (counterParty == null) {
			log.debug("Using default requireSignedRequest={} for missing counterParty", defaultValue);
			return defaultValue;
		}
		if (counterParty.getSecurityPolicies() == null) {
			log.debug("Using default requireSignedRequest={} for counterParty={}", defaultValue, counterParty.getId());
			return defaultValue;
		}
		var result = property.apply(counterParty, defaultValue);
		log.debug("Using configured requireSignedRequest={} for counterParty={}", result, counterParty.getId());
		return result;
	}
}
