/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.profileselection.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;

@Component
public class ProfileSelectionServiceFactory {

	private final Map<String, ProfileSelectionService> services;

	private final ProfileSelectionService defaultService;

	@Autowired
	public ProfileSelectionServiceFactory(Map<String, ProfileSelectionService> services, ProfileSelectionService defaultService) {
		this.services = services;
		this.defaultService = defaultService;
	}

	public ProfileSelectionService getService(String type) {
		if (services.size() == 1) {
			return services.values().iterator().next();
		}
		if (type == null || type.isBlank()) {
			return defaultService;
		}
		return Optional.ofNullable(services.get(type.toLowerCase()))
					   .orElseThrow(() -> new IllegalArgumentException("Unknown profile selection service type: " + type));
	}

}
