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

package swiss.trustbroker.sessioncache.service;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.saml.util.CredentialUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.sessioncache.dto.JwkCacheEntity;
import swiss.trustbroker.sessioncache.repo.JwkCacheRepository;

@Service
@Slf4j
@AllArgsConstructor
public class JwkCacheService {

	private final JwkCacheRepository repository;

	private final TrustBrokerProperties trustBrokerProperties;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final Clock clock;

	// returns the entries with the OLDEST first
	public List<JwkCacheEntity> getJWTEntities() {
		List<JwkCacheEntity> stateEntities = repository.findAllByOrderByExpirationTimestampAsc();
		if (log.isDebugEnabled()) {
			List<String> ids = stateEntities.stream().map(JwkCacheEntity::getId).toList();
			log.debug("JWK FETCH entities, count={} with ids={}", stateEntities.size(), ids);
		}
		return stateEntities;
	}

	public void saveJWK(JWK jwk) {
		JwkCacheEntity stateEntity = createCacheEntity(jwk);
		repository.save(stateEntity);
		log.debug("JWK SAVE entity id={}", stateEntity.getId());
	}

	private JwkCacheEntity createCacheEntity(JWK jwk) {
		var stateEntity = new JwkCacheEntity();
		stateEntity.setId(jwk.getKeyID());
		stateEntity.setJwk(jwk.toString());
		stateEntity.setExpirationTimestamp(Timestamp.from(
				Instant.now().plus(trustBrokerProperties.getOidc().getKeyExpirationMinutes(), ChronoUnit.MINUTES)));
		stateEntity.setDeleteTimestamp(Timestamp.from(
				Instant.now().plus(trustBrokerProperties.getOidc().getKeyDeletionMinutes(), ChronoUnit.MINUTES)));
		return stateEntity;
	}

	@SuppressWarnings("java:S2245") // use of unsecure random just for randomizing run time between PODs
	@Scheduled(cron = "${trustbroker.config.oidc.keySchedule}")
	private void updateJWKSetInDB() {
		try {
			var randomDelaySec = trustBrokerProperties.getStateCache().getReapMaxDelaySec(); // replicas distribution
			var randomDelayMs = ThreadLocalRandom.current().nextInt(randomDelaySec > 0 ? randomDelaySec * 1000 : 1);
			Thread.sleep(randomDelayMs);

			var start = clock.instant();
			log.debug("JWK Start rolling (delayMs={})...", randomDelayMs);

			var jwk = createJWK();
			var cacheEntity = createCacheEntity(jwk);
			repository.save(cacheEntity);
			log.debug("JWK Saved jwkNewKey={} expirationTime={} deleteTime={}", jwk.getKeyID(),
					cacheEntity.getExpirationTimestamp().toLocalDateTime(), cacheEntity.getDeleteTimestamp().toLocalDateTime());

			var total = repository.findAllByOrderByExpirationTimestampAsc();
			var deleted = repository.deleteAllInBatchByDeleteTimestampBefore(Timestamp.from(start));
			if (deleted == null) {
				log.debug("DB deleteAllInBatchByDeleteTimestampBefore returned null");
				deleted = 0;
			}
			var active = total.size() - deleted;
			log.info("JWK rollover jwkNewKeysCount=1 jwkTotalKeysCount={} jwkExpiredKeysCount={}", total.size(), deleted);
			// cron expression triggering too often compared too the key validity
			if (active > 99) {
				log.warn("Detected jwkActiveKeysCount={}. HINT: Check trustbroker.config.oidc.keySchedule/keyExpirationMinutes",
						active);
			}
		} catch (InterruptedException e) {
			log.info("JWK skipped reaper cycle");
			Thread.currentThread().interrupt(); // restore interrupt state
		} catch (Exception ex) {
			globalExceptionHandler.logException(ex);
		}
	}

	public JWK createJWK() {
		KeyPair keyPair = CredentialUtil.generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.keyUse(KeyUse.SIGNATURE)
				.build();
	}
}

