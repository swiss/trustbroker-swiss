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

import java.util.concurrent.TimeUnit;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import swiss.trustbroker.common.exception.TrustBrokerException;

// Health check is executed on readiness probes at startup and after that only every minute with 60 acceptable failures.
// This means that we need at least 1 hour until an unavailable backend marks XTB as DOWN.
// We are OK with occasional failures this way and longer network outages.
// Pod restarts trigger after < 1 hour as a last resort.
//
@Slf4j
public abstract class TrustbrokerHealthIndicator implements HealthIndicator {

	private static final long HEALTHCHECK_PERIOD_MSEC = TimeUnit.MINUTES.toMillis(1);

	private static final long HEALTHCHECK_DOWN_RETRIES = 60;

	@Value("0")
	private long lastHealthCheck = 0;

	@Value("0")
	private long failCount = 0;

	public abstract boolean pingBackend();

	public abstract String getBackendName();

	@Override
	public Health health() {
		// We check once per minute at most when there is no traffic.
		if (skipBackendPing()) {
			return currentBackendStatus();
		}

		var start = System.currentTimeMillis();
		String error = null;
		try {
			if (pingBackend()) {
				markBackendUp();
				return currentBackendStatus();
			}
			error = "returned NOK";
		}
		catch (TrustBrokerException ex) {
			error = ex.getInternalMessage();
		}
		catch (Exception ex) {
			error = ex.toString();
		}
		finally {
			var dTms = System.currentTimeMillis() - start;
			if (error != null) {
				log.warn("{} health FAILED with failCount={} in dTms={} ({})", getBackendName(), failCount, dTms, error);
			}
			else {
				// slow response reported at INFO (POD check might time out)
				log.atLevel(dTms >= HEALTHCHECK_PERIOD_MSEC ? Level.INFO : Level.DEBUG)
				   .log("{} health SUCCEEDED in dTms={}", getBackendName(), dTms);
			}
		}

		if (markBackendFailed()) {
			// when going down LB might also retry a few time, but we do not want to stop pods unnecessarily anyway
			log.error("{} DOWN on readiness or liveness probes may signal POD restart", getBackendName());
		}

		return currentBackendStatus();
	}

	private synchronized boolean skipBackendPing() {
		var nextHealthCheck = System.currentTimeMillis();
		var skipPing = (nextHealthCheck - lastHealthCheck < HEALTHCHECK_PERIOD_MSEC);
		if (!skipPing) {
			lastHealthCheck = nextHealthCheck;
		}
		return skipPing;
	}

	private synchronized void markBackendUp() {
		if (failCount > 0) {
			log.info("{} health RESTORED on failCount={}", getBackendName(), failCount);
		}
		failCount = 0;
	}

	private synchronized boolean markBackendFailed() {
		failCount += 1;
		return failCount >= HEALTHCHECK_DOWN_RETRIES;
	}

	private synchronized Health currentBackendStatus() {
		if (failCount < HEALTHCHECK_DOWN_RETRIES) {
			return Health.up().build();
		}
		return Health.down().build();
	}

}
