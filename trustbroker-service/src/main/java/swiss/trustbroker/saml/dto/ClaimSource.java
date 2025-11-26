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

package swiss.trustbroker.saml.dto;

import lombok.Getter;

@Getter
public enum ClaimSource {
	CP, // configured by AttributesSelection or ClaimsSelection
	IDM, // configured by UserDetailsSelection or ClaimsSelection
	PROPS, // configured by PropertiesSelection or ClaimsSelection
	SCRIPT, // injected via Scripts into properties
	CONFIG // injected by RP processing into properties (replaces ConstAttributes)
}
