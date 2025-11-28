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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Result of IDM lookup.<br/>
 * <ul>
 *     <li><code>userDetails</code> are values from the source.<br/>
 *     They are filtered via RelyingParty UserDetailsSelection.</li>
 *     <li><code>properties</code> are values derived from the attributes.<br/>
 *     They are filtered via RelyingParty PropertiesSelection.</li>
 * </ul>
 * The counts of the two before filtering are returned separately.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class IdmResult {

	@Builder.Default
	private Map<AttributeName, List<String>> userDetails = new HashMap<>();

	private int originalUserDetailsCount;

	@Builder.Default
	private Map<AttributeName, List<String>> properties = new HashMap<>();

	private int originalPropertiesCount;

	/**
	 * Returns the store(s) actually queried - including those that did not find a result.
	 * <br/>
	 * Currently this data is passed, to the <code>IdmProvisioningService</code> implementations.
	 *
	 * @since 1.12.0
	 * @see IdmRequest#getStore()
	 */
	@Builder.Default
	private Set<String> queriedStores = new HashSet<>();

	/**
	 * This is not consumed directly by the XTB core code, but may be passed to other interfaces.
	 * <br/>
	 * The map key indicates the source of the data. It can be used by the implementations to match related interface
	 * implementations in order to share internal data structures such as lookup results.
	 * <br/>
	 * Currently this data is passed, to the <code>IdmProvisioningService</code> implementations.
	 *
	 * @see IdmProvisioningRequest#getAdditionalData()
	 * @since 1.9.0
	 */
	@Builder.Default
	private Map<Object, Object> additionalData = new HashMap<>();

}
