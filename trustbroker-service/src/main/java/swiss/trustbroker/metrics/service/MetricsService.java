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

package swiss.trustbroker.metrics.service;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Service for Micrometer metrics.
 *
 * @see <a href="https://docs.micrometer.io/micrometer/reference/concepts/naming.html">Naming Meters</a>
 */
@Service
@AllArgsConstructor
public class MetricsService {

	private static final Map<String, AtomicLong> GAUGE_CACHE = new ConcurrentHashMap<>();

	public static final String SAML_LABEL = "saml.";

	public static final String OIDC_LABEL = "oidc.";

	public static final String WS_TRUST_LABEL = "wstrust.";

	public static final String SESSION_LABEL = "sess_";

	public static final String CP_ISSUER_LABEL = "cpIssuer";

	public static final String RP_ISSUER_LABEL = "rpIssuer";

	public static final String CLIENT_ID_LABEL = "clientId";

	public static final String DESTINATION_LABEL = "destination";

	public static final String TYPE_LABEL = "type";

	public static final String STATUS_LABEL = "status";

	public static final String RESULT_LABEL = "result";

	public static final String CONFIG_STATUS_LABEL = "config.status.errors.";

	private final MeterRegistry meterRegistry;

	public void increment(EventType eventType, String event, String... tags) {
		var name = computeNamePrefix(eventType) + event;
		var counter = Counter.builder(name)
							 .tags(replaceNullValues(tags))
							 .register(meterRegistry);
		counter.increment();
	}

	private static String computeNamePrefix(EventType eventType) {
		return switch (eventType) {
			case AUTHN_REQUEST, RESPONSE, LOGOUT_REQUEST, LOGOUT_RESPONSE -> SAML_LABEL;
			case OIDC_LOGOUT, OIDC_TOKEN, OIDC_IDTOKEN -> OIDC_LABEL;
			case RST_REQUEST, RST_RESPONSE -> WS_TRUST_LABEL;
			default -> eventType.name().toLowerCase();
		};
	}

	private String[] replaceNullValues(String[] tags) {
		return Arrays.stream(tags)
				.map(tag -> tag != null ? tag : "none")
				.toArray(String[]::new);
	}

	public void gauge(String name, long value) {
		var cachedValue = GAUGE_CACHE.computeIfAbsent(name, k -> new AtomicLong());
		var gauge = this.meterRegistry.gauge(name, cachedValue);
		if (gauge == null) {
			throw new TechnicalException(String.format("Could not create Gauge metric with name=%s value=%d", name, value));

		}
		gauge.set(value);
	}

}
