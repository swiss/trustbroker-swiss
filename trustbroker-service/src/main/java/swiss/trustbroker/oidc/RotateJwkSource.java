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

package swiss.trustbroker.oidc;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.dto.JwkCacheEntity;
import swiss.trustbroker.sessioncache.service.JwkCacheService;

@Slf4j
public class RotateJwkSource<C extends SecurityContext> implements JWKSource<C> {

	private final JwkCacheService jwkCacheService;

	public final MetricsService metricsService;

	public RotateJwkSource(JwkCacheService jwkCacheService, MetricsService metricsService) {
		this.jwkCacheService = jwkCacheService;
		this.metricsService = metricsService;
	}

	@Override
	@SuppressWarnings("java:S3864") // Stream.peek is used just for debug logging
	// returns the entries with the OLDEST first (JWKSource does not specify an order)
	public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
		// SecurityContext provided by spring-sec, interface tagging
		if (context != null) {
			throw new TechnicalException(String.format("RotateJwkSource.get context=%s", context));
		}

		// get all keys including expired ones
		var jwkCacheEntities = this.jwkCacheService.getJWTEntities();

		// filter for valid ones
		Instant now = Instant.now();
		List<JWK> jwks = jwkCacheEntities.stream()
				.filter(jwkCacheEntity -> jwkCacheEntity.getExpirationTimestamp().toInstant().isAfter(now))
				.peek(jwkCacheEntity -> log.debug("Keep jwkCacheEntity={}", jwkCacheEntity)) // includes expirationTimestamp
				.map(RotateJwkSource::getJWKFromEntity)
				.toList();

		metricsService.gauge(MetricsService.SESSION_LABEL + MetricsService.OIDC_LABEL + "keys", jwks.size());
		log.debug("JWK query with selector={} returned jwkCount={} valid entries", jwkSelector, jwks.size());

		// initially and adhoc create a new key when JwkCacheService did not yet kick in creating them scheduled
		if (jwkCacheEntities.isEmpty()) {
			log.info("Key table is empty, creating an initial JWK entry");
			return createNewJwkEntry();
		}
		if (jwks.isEmpty()) {
			log.warn("All {} keys in the key table have expired, creating one adhoc. Check keySchedule/keyExpirationMinutes)",
					jwkCacheEntities.size());
			return createNewJwkEntry();
		}

		// select the oldest still valid one to give OIDC Relying Parties time to update the key set from the /jwks endpoint
		return jwkSelector.select(new JWKSet(jwks));
	}

	private List<JWK> createNewJwkEntry() {
		JWK jwk = jwkCacheService.createJWK();
		List<JWK> jwks = new ArrayList<>();
		jwks.add(jwk);
		this.jwkCacheService.saveJWK(jwk);
		return jwks;
	}

	private static JWK getJWKFromEntity(JwkCacheEntity jwkCacheEntity) {
		try {
			return JWK.parse(jwkCacheEntity.getJwk());
		}
		catch (ParseException e) {
			throw new TechnicalException(String.format("Skipping JWK while could not parse=%s", jwkCacheEntity));
		}
	}

}
