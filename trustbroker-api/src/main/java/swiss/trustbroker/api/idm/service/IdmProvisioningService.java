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

package swiss.trustbroker.api.idm.service;

import swiss.trustbroker.api.idm.dto.IdmProvisioningRequest;
import swiss.trustbroker.api.idm.dto.IdmProvisioningResult;

/**
 * Interface for provisioning an IDM service.
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.IdmConfig (${trustbroker.config.idm}).
 *
 * @since 1.9.0
 */
public interface IdmProvisioningService {

	/**
	 * Provision a user into the IDM.
	 * <br/>
	 * Post condition: The user is present in the IDM along with all data required for the particular IDM, e.g. a profile,
	 * credentials or other.
	 *
	 * @param request not null
	 * @return result not null
	 */
	IdmProvisioningResult createOrUpdateUser(IdmProvisioningRequest request);

}
