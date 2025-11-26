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

package swiss.trustbroker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration for LDAP store sub-system.
 *
 * @since 1.10.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LdapStoreConfig {

	/**
	 * LDAP store sub-system supporting store="LDAP" IDMQuery.
	 * <br/>
	 * Default: false
	 */
	private boolean enabled;

	/**
	 * Base context for the LDAP search configured in the IDMQuery.AppFilter.
	 */
	private String searchBase;

}
