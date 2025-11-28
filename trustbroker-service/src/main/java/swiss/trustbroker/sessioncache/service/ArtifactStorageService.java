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

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.TimerTask;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import jakarta.persistence.OptimisticLockException;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import org.opensaml.storage.AbstractStorageService;
import org.opensaml.storage.StorageRecord;
import org.springframework.dao.ConcurrencyFailureException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.dto.ArtifactCacheEntity;
import swiss.trustbroker.sessioncache.repo.ArtifactCacheRepository;

/**
 * Minimal implementation with only methods used by OpenSAML StorageServiceSAMLArtifactMap
 */
@Slf4j
public class ArtifactStorageService extends AbstractStorageService {

	public class ArtifactCleanupTask extends TimerTask {

		@Override
		public void run() {
			try {
				var numEntries = repository.count();
				var start = clock.instant();
				log.info("Start reaping ArtifactCache...");
				var reaped = repository.deleteAllInBatchByExpirationTimestampBefore(Timestamp.from(start));
				if (reaped == null) {
					log.debug("DB deleteAllInBatchByExpirationTimestampBefore returned null");
					reaped = 0;
				}
				var duration = Duration.between(start, clock.instant()).toMillis();
				metricsService.gauge(MetricsService.SESSION_LABEL + MetricsService.SAML_LABEL + "artifacts",
						numEntries - reaped);
				var msg = String.format(
						"Completed reaping ArtifactCache in dTms=%d totalArtifacts=%s expiredArtifacts=%d after "
								+ "cleanupInterval=%s",	duration, numEntries, reaped, cleanupInterval);
				log.info(msg);
			}
			catch (OptimisticLockException | ConcurrencyFailureException ex) {
				log.info("Skipped ArtifactCache reaper cycle (entries collected by peer already). Details: {}", ex.getMessage());
			}
			catch (Exception ex) {
				GlobalExceptionHandler.logException(ex, null);
			}
		}
	}

	private final ArtifactCacheRepository repository;

	private final TimerTask cleanupTask;

	private final Duration cleanupInterval;

	private final Clock clock;

	public final MetricsService metricsService;

	public ArtifactStorageService(ArtifactCacheRepository repository, Clock clock, Duration cleanupInterval,
			MetricsService metricsService) {
		this.repository = repository;
		this.clock = clock;
		this.cleanupInterval = cleanupInterval;
		this.metricsService = metricsService;
		if (cleanupInterval.isZero()) {
			this.cleanupTask = null;
			// OK for an in memory DB, not suitable for a real DB
			log.warn("No session reaper as cleanup interval is ZERO");
		}
		else {
			this.cleanupTask = new ArtifactCleanupTask();
			setCleanupInterval(cleanupInterval);
			log.debug("Session reaper running at cleanupInterval={}", cleanupInterval);
		}
		setId("XTBArtifactStorageService");
		try {
			super.initialize();
		}
		catch (ComponentInitializationException ex) {
			throw new TechnicalException(String.format("Could not initialize ArtifactStorageService: %s", ex.getMessage()), ex);
		}
	}

	@Override
	protected TimerTask getCleanupTask() {
		return cleanupTask;
	}

	@Override
	public int getKeySize() {
		return ArtifactCacheEntity.ARTIFACT_ID_SIZE;
	}

	@Override
	public boolean isServerSide() {
		return true; // storage in DB via ArtifactCacheRepository -> does not depend on client
	}

	@Override
	public boolean isClustered() {
		return true; // storage in DB via ArtifactCacheRepository -> available on all nodes
	}

	@Override
	public boolean create(@Nonnull String context, @Nonnull String artifactId,
			@Nonnull String artifactValue, @Nullable Long expiration) {
		var expirationTimestamp = new Timestamp(expiration);
		var entity = new ArtifactCacheEntity(artifactId, artifactValue, expirationTimestamp);
		repository.save(entity);
		log.debug("Artifact CREATE artifactId={} artifactValue={} expirationTimestamp={}",
				artifactId, artifactValue, expirationTimestamp);
		return true;
	}

	@Nullable
	@Override
	public <T> StorageRecord<T> read(@Nonnull String context, @Nonnull String artifactId) {
		var entity = repository.findById(artifactId);
		if (entity.isEmpty()) {
			log.debug("Artifact NOTFOUND artifactId={}", artifactId);
			return null;
		}
		if (clock.instant().isAfter(entity.get().getExpirationTimestamp().toInstant())) {
			log.debug("Artifact EXPIRED artifactId={} expirationTimestamp={}",
					artifactId, entity.get().getExpirationTimestamp());
			return null;
		}
		log.debug("Artifact FOUND artifactId={} artifactValue={} expirationTimestamp={}",
				artifactId, entity.get().getArtifactValue(), entity.get().getExpirationTimestamp());
		return new StorageRecord<>(entity.get().getArtifactValue(), Long.MAX_VALUE);
	}

	@Nonnull
	@Override
	public <T> Pair<Long, StorageRecord<T>> read(@Nonnull String context, @Nonnull String key, long version) {
		throw new UnsupportedOperationException("read with version not implemented");
	}

	@Override
	public boolean update(@Nonnull String context, @Nonnull String key, @Nonnull String value, @Nullable Long expiration) {
		throw new UnsupportedOperationException("update not implemented");
	}

	@Nullable
	@Override
	public Long updateWithVersion(long version, @Nonnull String context, @Nonnull String key, @Nonnull String value,
			@Nullable Long expiration) {
		throw new UnsupportedOperationException("updateWithVersion not implemented");
	}

	@Override
	public boolean updateExpiration(@Nonnull String context, @Nonnull String key, @Nullable Long expiration) {
		throw new UnsupportedOperationException("updateExpiration not implemented");
	}

	@Override
	public boolean delete(@Nonnull String context, @Nonnull String artifactId) {
		repository.deleteById(artifactId);
		log.debug("Artifact DELETE artifactId={}", artifactId);
		return true;
	}

	@Override
	public boolean deleteWithVersion(long version, @Nonnull String context, @Nonnull String key) {
		throw new UnsupportedOperationException("deleteWithVersion not implemented");
	}

	@Override
	public void reap(@Nonnull String context) {
		// used by test, not by StorageServiceSAMLArtifactMap
		cleanupTask.run();
	}

	@Override
	public void updateContextExpiration(@Nonnull String context, @Nullable Long expiration) {
		throw new UnsupportedOperationException("updateContextExpiration not implemented");
	}

	@Override
	public void deleteContext(@Nonnull String context) {
		throw new UnsupportedOperationException("deleteContext not implemented");
	}
}
