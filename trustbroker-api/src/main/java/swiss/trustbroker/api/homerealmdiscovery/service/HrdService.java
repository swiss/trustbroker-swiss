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

package swiss.trustbroker.api.homerealmdiscovery.service;

import java.util.List;

import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdHttpData;

/**
 * Home realm discovery related customizations.
 */
public interface HrdService {

	/**
	 * Perform manipulation of CP to RP mappings.
	 *
	 * @param httpData   HTTP exchange information
	 * @param cpMappings input mappings (not null)
	 * @return if there is no modification, return the original cpMappings, don't return null
	 */
	public List<HrdClaimsProviderToRelyingPartyMapping> adaptClaimsProviderMappings(
			HrdHttpData httpData, List<? extends HrdClaimsProviderToRelyingPartyMapping> cpMappings);

}
