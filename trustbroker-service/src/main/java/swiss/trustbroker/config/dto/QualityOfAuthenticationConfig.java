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

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Quality of Authentication (QoA) configuration.
 * <br/>
 * A QoA value has a name (e.g. a URN) and a numerical level for ordering and mapping inbound/outbound.
 *
 * @since 1.9.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class QualityOfAuthenticationConfig {

	/**
	 * Default Qoa value.
	 */
	private String defaultQoa;

	/**
	 * QoA value for <strong>strongest possible</strong> authentication level.
	 */
	private String strongestPossible;

	/**
	 * Global mapping of QoA values to QoaLevel.
	 */
	private Map<String, Integer> mapping;

	/**
	 * Mapping of legacy QoA values to QoaLevel.
	 * <br/>
	 * Used for <code>OidcClient.usePepQoa=true</code>.
	 */
	private Map<String, Integer> legacy;

}
