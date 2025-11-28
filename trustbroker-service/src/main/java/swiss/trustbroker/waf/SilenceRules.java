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

package swiss.trustbroker.waf;

import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class SilenceRules {

	private static final AtomicLong lastCheckAt = new AtomicLong();

	private static final AtomicLong healthCheckCount = new AtomicLong();

	private static final long LB_HEALTH_CHECK_SHOW_PERIOD_MSEC = 6L * 60000L; // 6min

	// silence these accesses to reduce the amount of logs
	@SuppressWarnings("java:S1075") // slashes are OK
	private static final String SILENCED_PATH_REGEX = "^("
			+ "/" // top-level access common
			+ "|/favicon.ico" // the usual browser probe not of interest
			+ "|/apple-touch-icon[0-9a-z-]*.png" // Apple is special
			+ ")$";

	private static final String SILENCED_PATH_INTRANET_REGEX = "^("
			+ "/authtest/ntlm/" // used in the context of Kerberos login
			+ ")$";

	private static final Pattern SILENCED_PATHS= Pattern.compile(SILENCED_PATH_REGEX);

	private static final Pattern SILENCED_PATHS_INTRANET = Pattern.compile(SILENCED_PATH_INTRANET_REGEX);

	private SilenceRules() {
	}

	private static boolean isSilencedClientStuff(String path) {
		return SILENCED_PATHS.matcher(path).matches();
	}

	private static boolean isSilencedIntranetStuff(String path, boolean intranet) {
		return (SILENCED_PATHS_INTRANET.matcher(path).matches() && intranet);
	}

	// LB probes are shown once a minute
	private static boolean isSilencedLoadbalancer(HttpServletRequest request, NetworkConfig networkConfig) {
		var isLb = WebSupport.isLbHealthCheck(request, networkConfig);
		if (isLb) {
			long probes = healthCheckCount.getAndIncrement();
			var now = System.currentTimeMillis();
			if (now - lastCheckAt.get() < LB_HEALTH_CHECK_SHOW_PERIOD_MSEC) {
				return true;
			}
			log.info("Silenced loadbalancerHealthCheckCount={} calls in the last {}msec",
					probes, LB_HEALTH_CHECK_SHOW_PERIOD_MSEC);
			healthCheckCount.set(0);
			lastCheckAt.set(now);
		}
		return false;
	}

	@SuppressWarnings("java:S1067") // common, this is not complex
	static boolean isSilenced(HttpServletRequest request, boolean infoEnabled, boolean debugEnabled, NetworkConfig networkConfig) {
		var path = request.getRequestURI();
		return !infoEnabled // everything is silenced in the op and access logging department
				|| isSilencedClientStuff(path)
				|| isSilencedIntranetStuff(path, WebSupport.isClientOnIntranet(request, networkConfig))
				|| isSilencedLoadbalancer(request, networkConfig);
	}

}
