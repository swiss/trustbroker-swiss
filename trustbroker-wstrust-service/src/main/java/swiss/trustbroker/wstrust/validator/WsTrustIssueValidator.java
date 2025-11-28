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
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
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

	public WsTrustIssueValidator(
			TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService, Clock clock) {
		super(trustBrokerProperties, relyingPartySetupService, clock);
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
		validateAssertion(headerAssertion, null, Optional.empty());

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
}
