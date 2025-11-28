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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.Builder;
import lombok.Data;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Profile selection result data.
 */
@Data
@Builder
public class ProfileSelectionResult {

	private String redirectUrl;

	private String selectedProfileId;

	@Builder.Default
	private Map<AttributeName, List<String>> filteredAttributes = Collections.emptyMap();

	public static ProfileSelectionResult empty() {
		return ProfileSelectionResult.builder()
									 .build();
	}

}
