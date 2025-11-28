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

package swiss.trustbroker.accessrequest.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestResult;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.SessionState;

/**
 * NO-OP fallback implementation of AccessRequestService, never requires any access request.
 *
 * @see AccessRequestService
 */
@Service
@ConditionalOnMissingBean(AccessRequestService.class)
@Slf4j
public class NoOpAccessRequestService implements AccessRequestService {

	@Override
	public AccessRequestResult triggerAccessRequest(AccessRequestHttpData httpData, RelyingPartyConfig relyingPartyConfig,
			SessionState stateData) {
		log.debug("{}.triggerAccessRequest called", this.getClass().getName());
		return AccessRequestResult.builder()
								  .build();
	}

	@Override
	public AccessRequestResult performAccessRequestIfRequired(AccessRequestHttpData httpData,
			RelyingPartyConfig relyingPartyConfig, SessionState stateData, Runnable refreshIdmCallback) {
		log.debug("{}.performAccessRequestIfRequired called", this.getClass().getName());
		return AccessRequestResult.builder()
								  .build();
	}
}
