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

package swiss.trustbroker.mapping.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import swiss.trustbroker.common.saml.util.SamlContextClass;

@Data
@AllArgsConstructor
@SuppressWarnings("java:S6548") // false positive - class has "named instance, not a singleton
public class CustomQoa
{

	public static final int UNDEFINED_QOA_ORDER = -1;

	public static final CustomQoa UNDEFINED_QOA = new CustomQoa(SamlContextClass.UNSPECIFIED, UNDEFINED_QOA_ORDER);

	private final String name;

	private final int order;

	public boolean isRegular() {
		return order > UNDEFINED_QOA_ORDER;
	}

	public boolean isUnspecified() {
		return order == UNDEFINED_QOA_ORDER;
	}
}
