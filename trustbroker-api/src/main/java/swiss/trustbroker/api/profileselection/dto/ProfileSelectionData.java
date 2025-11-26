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

package swiss.trustbroker.api.profileselection.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Profile selection result data.
 */
@Data
@Builder
public class ProfileSelectionData {

	private final ProfileSelectionProperties profileSelectionProperties;

	private final String selectedProfileId;

	private final boolean enforceSingleProfile;

	private final String exchangeId;

	private final String applicationName;

	private final String oidcClientId;

	public boolean isSortRoleEnabled() {
		return 	profileSelectionProperties != null && profileSelectionProperties.isSortRoleEnabled();
	}

	public boolean isFilterRoleEnabled() {
		return 	profileSelectionProperties != null && profileSelectionProperties.isFilterRoleEnabled();
	}

	public boolean isFilterRoleOutput() {
		return 	profileSelectionProperties != null && profileSelectionProperties.isFilterRoleOutput();
	}

	public String getApplicationFilterRegexp() {
		var filter = profileSelectionProperties == null
				|| "false".equalsIgnoreCase(profileSelectionProperties.getFilterRoleConfiguration())
				|| applicationName == null
				? ".*" : profileSelectionProperties.getFilterRoleConfiguration();
		return applicationName != null && "true".equalsIgnoreCase(filter) ? ".*" + applicationName + ".*" : filter;
	}

}
