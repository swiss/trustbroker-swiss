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

package swiss.trustbroker.api.idm.dto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Status after user provisioning. So far used only for auditing purposes.
 * <br/>
 * An implementation can e.g. always report UPDATED if it cannot readily differentiate the cases.
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum IdmProvisioningStatus {
	/**
	 * User newly created.
	 */
	CREATED(true),
	/**
	 * User updated.
	 */
	UPDATED(true),
	/**
	 * No update was required.
	 */
	NOT_MODIFIED(false);

	private final boolean modified;
}
