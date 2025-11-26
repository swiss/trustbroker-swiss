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

package swiss.trustbroker.api.accessrequest.service;

import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.SessionState;

/**
 * Access request triggers onboarding of a user to an application due to a missing role.
 * <br/>
 * This interface is preliminary and could still change. In particular the RelyingParty and StateData abstractions.
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.AccessRequestConfig (${trustbroker.config.accessRequest}).
 */
public interface AccessRequestService {

	AccessRequestResult triggerAccessRequest(AccessRequestHttpData httpData, RelyingPartyConfig relyingPartyConfig,
			SessionState stateData);

	AccessRequestResult performAccessRequestIfRequired(AccessRequestHttpData httpData,
			RelyingPartyConfig relyingPartyConfig, SessionState stateData, Runnable refreshIdmCallback);

}
