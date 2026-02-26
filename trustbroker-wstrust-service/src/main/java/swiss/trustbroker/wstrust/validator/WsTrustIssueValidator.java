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
import java.util.List;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
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

	private boolean enabled() {
		var properties = getTrustBrokerProperties();
		return properties.getWstrust() != null && properties.getWstrust().isIssueEnabled();
	}

	@Override
	public WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, SoapMessageHeader requestHeader) {
		WsTrustHeaderValidator.validateHeaderElements(requestHeader, getTrustBrokerProperties().getIssuer());

		log.debug("RSTR ISSUE request - assertion is in header");
		if (requestHeader.getSecurityToken() != null) {
			log.info("RSTR with requestType='{}' ignoring header security token", REQUEST_TYPE);
		}
		var headerAssertion = requestHeader.getAssertion();
		var claimsParty = getIssuingClaimsParty(headerAssertion);
		var relyingParty = getRstRelyingParty(requestSecurityToken);
		var requireSignedRequest = requireSignedRequest(claimsParty, relyingParty, getTrustBrokerProperties().getWstrust());
		List<Credential> rpTrustCredentials = relyingParty != null ? relyingParty.getRpTrustCredentials() : null;
		validateSignature(requestHeader, requireSignedRequest, rpTrustCredentials);
		var requireSignedAssertion = requireSignedAssertion(claimsParty, relyingParty, getTrustBrokerProperties().getWstrust());
		validateAssertion(headerAssertion, null, Optional.of(claimsParty.getCpTrustCredential()), requireSignedAssertion,
				requestSecurityToken, claimsParty, relyingParty);

		var keyType = WsTrustUtil.getKeyTypeFromRequest(requestSecurityToken);
		if (!KeyType.BEARER.equals(keyType)) {
			throw new RequestDeniedException(String.format(
					"Wrong KeyType in RSTR with assertionID='%s' keyType='%s' expectedKeyType='%s'",
					headerAssertion != null ? headerAssertion.getID() : null, keyType, KeyType.BEARER));
		}
		var addressFromRequest = WsTrustUtil.getAddressFromRequest(requestSecurityToken);

		return WsTrustValidationResult.builder()
									  .requestType(REQUEST_TYPE)
									  .validatedAssertion(headerAssertion)
									  .recomputeAttributes(true)
									  .issuerId(addressFromRequest)
									  .recipientId(null) // not set
									  .useAssertionLifetime(false)
									  .createResponseCollection(true)
									  .build();
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

	static boolean requireSignedRequest(ClaimsParty claimsParty, RelyingParty relyingParty, WsTrustConfig config) {
		// Explicit CP config value overrides global default:
		var requireSignedRequest = requireSignedRequest(claimsParty, config.isIssueRequireSignedRequests());
		// Explicit RP config value overrides CP:
		requireSignedRequest = requireSignedRequest(relyingParty, requireSignedRequest);
		log.info("Enforcing requireSignedRequest={} for cpIssuerId={} rpIssuerId={}",
				requireSignedRequest, claimsParty.getId(), relyingParty != null ? relyingParty.getId() : null);
		return requireSignedRequest;
	}

	private static boolean requireSignedRequest(CounterParty counterParty, boolean defaultValue) {
		if (counterParty == null) {
			log.debug("Using default requireSignedRequest={} for missing counterParty", defaultValue);
			return defaultValue;
		}
		if (counterParty.getSecurityPolicies() == null) {
			log.debug("Using default requireSignedRequest={} for counterParty={}", defaultValue, counterParty.getId());
			return defaultValue;
		}
		var result = counterParty.getSecurityPolicies().isWsTrustIssueRequireSignedRequest(defaultValue);
		log.debug("Using configured requireSignedRequest={} for counterParty={}", result, counterParty.getId());
		return result;
	}

	static boolean requireSignedAssertion(ClaimsParty claimsParty, RelyingParty relyingParty, WsTrustConfig config) {
		// Explicit CP config value overrides global default of true:
		var requireSignedAssertion = requireSignedAssertion(claimsParty, config.isIssueRequireSignedAssertions());
		// RP overrides CP if set
		requireSignedAssertion = requireSignedAssertion(relyingParty, requireSignedAssertion);
		log.info("Enforcing requireSignedAssertion={} for cpIssuerId={} rpIssuerId={}",
				requireSignedAssertion, claimsParty.getId(), relyingParty != null ? relyingParty.getId() : null);
		return requireSignedAssertion;
	}

	private static boolean requireSignedAssertion(CounterParty counterParty, boolean defaultValue) {
		if (counterParty == null) {
			log.debug("Using default requireSignedAssertion={} for missing counterParty", defaultValue);
			return defaultValue;
		}
		if (counterParty.getSecurityPolicies() == null) {
			log.debug("Using default requireSignedAssertion={} for counterParty={}", defaultValue, counterParty.getId());
			return defaultValue;
		}
		var result = counterParty.getSecurityPolicies().isWsTrustIssueRequireSignedAssertion(defaultValue);
		log.debug("Using configured requireSignedAssertion={} for counterParty={}", result, counterParty.getId());
		return result;
	}
}
