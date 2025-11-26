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

package swiss.trustbroker.homerealmdiscovery.service;

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdHttpData;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;

/**
 * NO-OP fallback implementation of HrdService, returns unmodified data.
 *
 * @see HrdService
 */
@Service
@ConditionalOnMissingBean(HrdService.class)
@Slf4j
public class NoOpHrdService implements HrdService {

	@Override
	@SuppressWarnings("unchecked")
	public List<HrdClaimsProviderToRelyingPartyMapping> adaptClaimsProviderMappings(
			HrdHttpData httpData, List<? extends HrdClaimsProviderToRelyingPartyMapping> cpMappings) {
		return (List<HrdClaimsProviderToRelyingPartyMapping>) cpMappings;
	}
}
