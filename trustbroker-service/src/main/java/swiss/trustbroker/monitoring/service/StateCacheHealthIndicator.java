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

package swiss.trustbroker.monitoring.service;

import org.springframework.stereotype.Component;
import swiss.trustbroker.sessioncache.repo.StateCacheRepository;

/**
 * Checks access to the StateCache DB via a dummy query.
 * As a HealthIndicator, this is included into the output of /actuator/health.
 * With details, it is shown as:
 * <pre>stateCache: status: "UP"</pre>
 * Without details, it just affects the UP/DOWN status.
 */
@Component
public class StateCacheHealthIndicator extends TrustbrokerHealthIndicator {

	private final StateCacheRepository stateCacheRepository;

	public StateCacheHealthIndicator(StateCacheRepository stateCacheRepository) {
		this.stateCacheRepository = stateCacheRepository;
	}

	@Override
	public String getBackendName() {
		return "State Cache DB";
	}

	@Override
	public boolean pingBackend() {
		stateCacheRepository.findById("");
		return true;
	}

}
