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

package swiss.trustbroker.federation.xmlconfig;

import jakarta.xml.bind.annotation.XmlEnumValue;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Provisioning mode for a claims party.
 *
 * @see swiss.trustbroker.api.idm.service.IdmProvisioningService
 * @since 1.9.0
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum ProvisioningMode {

	/**
	 * Detect and log required provisioning.
	 */
	@XmlEnumValue("detect")
	DETECT(true, true),

	/**
	 * Detect and apply provisioning.
	 */
	@XmlEnumValue("true")
	TRUE(true, false),

	/**
	 * No provisioning.
	 */
	@XmlEnumValue("false")
	FALSE(false, false);

	private final boolean enabled;

	private final boolean detectOnly;
}
