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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static swiss.trustbroker.util.SessionTimeConfiguration.START_INSTANT;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.dto.ArtifactCacheEntity;
import swiss.trustbroker.sessioncache.repo.ArtifactCacheRepository;
import swiss.trustbroker.util.SessionTimeConfiguration;

@SpringBootTest
@ContextConfiguration(classes = { TrustBrokerProperties.class })
class ArtifactStorageServiceTest {

	private static final String CONTEXT = "test";

	private static final String KEY = "artifact1";

	private static final String VALUE = "value1";

	@MockitoBean
	ArtifactCacheRepository artifactCacheRepository;

	@MockitoBean
	Clock clock;

	@MockitoBean
	private MetricsService metricsService;

	ArtifactStorageService cacheService;

	@BeforeEach
	void setUp() {
		cacheService = new ArtifactStorageService(artifactCacheRepository, clock,
				Duration.ofSeconds(SessionTimeConfiguration.ARTIFACT_REAP_INTERVAL_SECS), metricsService);
		doReturn(START_INSTANT).when(clock).instant();
	}

	@ParameterizedTest
	@CsvSource(value = "0,2")
	void reap(int reaped) {
		doReturn(reaped).when(artifactCacheRepository)
				.deleteAllInBatchByExpirationTimestampBefore(Timestamp.from(START_INSTANT));
		cacheService.reap(CONTEXT);
		verify(artifactCacheRepository).deleteAllInBatchByExpirationTimestampBefore(Timestamp.from(START_INSTANT));
	}

	@Test
	void lifecycle() {
		// create
		var expiration = SessionTimeConfiguration.START_INSTANT.toEpochMilli() + SessionTimeConfiguration.ARTIFACT_LIFETIME_SECS;
		assertThat(cacheService.create(CONTEXT, KEY, VALUE, expiration), is(true));
		var entity = new ArtifactCacheEntity();
		entity.setArtifactId(KEY);
		entity.setArtifactValue(VALUE);
		entity.setExpirationTimestamp(new Timestamp(expiration));
		verify(artifactCacheRepository).save(entity);

		// read
		doReturn(Optional.of(entity)).when(artifactCacheRepository).findById(KEY);
		var result = cacheService.read(CONTEXT, KEY);
		assertThat(result, is(not(nullValue())));
		assertThat(result.getValue(), is(VALUE));

		// read missing
		assertThat(cacheService.read(CONTEXT, "notfound"), is(nullValue()));

		// read expired
		doReturn(START_INSTANT.plusSeconds(1)).when(clock).instant();
		assertThat(cacheService.read(CONTEXT, KEY), is(nullValue()));

		// delete
		assertThat(cacheService.delete(CONTEXT, KEY), is(true));
		verify(artifactCacheRepository).deleteById(KEY);
	}
}
