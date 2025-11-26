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

package swiss.trustbroker.homerealmdiscovery.util;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.StatusCode;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.StatusPolicy;
import swiss.trustbroker.saml.dto.CpResponse;

@AllArgsConstructor
@Slf4j
public class DefaultIdmStatusPolicyCallback implements IdmStatusPolicyCallback {

	private final CpResponse cpResponse;

	@Override
	public void userNotActive(String statusPolicy, String userId, String userStatus) {
		var policy = statusPolicyWithDefault(statusPolicy);
		switch (policy) {
			case BLOCK:
				throw new RequestDeniedException(
						StandardErrorCode.UNKNOWN_PRINCIPAL,
						String.format("User with clientExtId=%s has state=%s - blocked with error page",
								userId, userStatus));
			case BLOCK_EXCEPTION, BLOCK_RESPONDER:
				log.error("User with clientExtId={} state={} statusPolicy={}",
						userId, userStatus, statusPolicy);
				// there is no official code for inactive users, UNKNOWN_PRINCIPAL was used for this already:
				// We don't have the RP FlowPolicy here - just set the flags we can determine here, defaults for the rest
				var flowPolicy = Flow.builder()
									 .id(StatusCode.UNKNOWN_PRINCIPAL)
									 .appContinue(policy == StatusPolicy.BLOCK_EXCEPTION)
									 .build();
				cpResponse.abort(StatusCode.RESPONDER, flowPolicy);
				break;
			default:
				log.info("User with clientExtId={} state={} statusPolicy={}",
						userId, userStatus, statusPolicy);
		}
	}

	private static StatusPolicy statusPolicyWithDefault(String statusPolicy) {
		return statusPolicy != null ? StatusPolicy.valueOf(statusPolicy) : StatusPolicy.FETCH_ACTIVE_ONLY;
	}

}
