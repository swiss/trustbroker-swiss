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

package swiss.trustbroker.saml.service;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.StatusPolicy;
import swiss.trustbroker.saml.dto.CpResponse;

@Slf4j
@Service
public class UnknownUserPolicyService {

	boolean blockUnknownUserResponse(CpResponse cpResponse, ClaimsParty claimsParty) {
		var userDetailsFromIdm = cpResponse.getOriginalUserDetailsCount();
		if (userDetailsFromIdm > 0) {
			return false;
		}
		var rpStatusPolicy = getIdmUnknownUserStatusPolicy(cpResponse);
		var cpStatusPolicy = claimsParty.getStatusPolicy();
		if (StatusPolicy.ALLOW_UNKNOWN_USER.equals(cpStatusPolicy)) {
			return false;
		}
		if (StatusPolicy.BLOCK_UNKNOWN_USER.equals(cpStatusPolicy)) {
			if (hasNoQueries(cpResponse)) {
				return false;
			}
			if (rpStatusPolicy == null || StatusPolicy.BLOCK_UNKNOWN_USER.equals(rpStatusPolicy)) {
				return true;
			}
			if (StatusPolicy.ALLOW_UNKNOWN_USER.equals(rpStatusPolicy)) {
				return false;
			}
		}
		return cpStatusPolicy == null && StatusPolicy.BLOCK_UNKNOWN_USER.equals(rpStatusPolicy);
	}

	public void applyUnknownUserPolicy(CpResponse cpResponse, ClaimsParty claimsParty) {
		if (!blockUnknownUserResponse(cpResponse, claimsParty)) {
			return;
		}
		log.info("User with statusPolicy={} not found in IDM", StatusPolicy.BLOCK_UNKNOWN_USER);
		var flowPolicy = Flow.builder()
				.id(StandardErrorCode.UNKNOWN_USER.getLabel())
				.supportInfo(true)
				.appContinue(false)
				.build();
		cpResponse.abort(StatusCode.RESPONDER, flowPolicy);
	}

	StatusPolicy getIdmUnknownUserStatusPolicy(CpResponse cpResponse) {
		if (hasNoQueries(cpResponse)) {
			return null;
		}
		var queries = cpResponse.getIdmLookup().getQueries();
		return queries.stream()
				.map(IdmQuery::getStatusPolicy)
				.filter(statusPolicy -> StatusPolicy.BLOCK_UNKNOWN_USER.equals(statusPolicy) ||
						StatusPolicy.ALLOW_UNKNOWN_USER.equals(statusPolicy))
				.findAny().orElse(null);
	}

	private static boolean hasNoQueries(CpResponse cpResponse) {
		return cpResponse.getIdmLookup() == null || cpResponse.getIdmLookup().getQueries() == null;
	}

}
