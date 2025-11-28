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

package swiss.trustbroker.sessioncache.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.sql.Timestamp;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class LifecycleTest {
	@Test
	void init() {
		Lifecycle lifecycle = new Lifecycle();
		assertThat(lifecycle.isValid(), is(true));
		assertThat(lifecycle.getLifecycleState(), is(LifecycleState.INIT));
	}

	@Test
	void expired() {
		Lifecycle lifecycle = new Lifecycle();
		assertThat(lifecycle.isExpired(), is(false));
		lifecycle.setLifecycleState(LifecycleState.EXPIRED);
		assertThat(lifecycle.isExpired(), is(true));
		assertThat(lifecycle.isValid(), is(false));
	}

	@Test
	void overdue() {
		var now = Instant.now();
		var lifecycle = Lifecycle
				.builder()
				.initTime(Timestamp.from(now))
				.expirationTime(Timestamp.from(now.plusSeconds(1)))
				.build();
		assertThat(lifecycle.isOverdueAt(Timestamp.from(now)), is(false));
		assertThat(lifecycle.isOverdueAt(Timestamp.from(now.plusSeconds(1))), is(false));
		assertThat(lifecycle.isOverdueAt(Timestamp.from(now.plusSeconds(2))), is(true));
	}

	@Test
	void ttlAndRemaining() {
		var lifetimeSecs = 300L;
		var now = Instant.now();
		var lifecycle = Lifecycle.builder()
				.initTime(Timestamp.from(now))
				.expirationTime(Timestamp.from(now.plusSeconds(lifetimeSecs)))
				.build();
		lifecycle.incAccessCount();
		assertThat(lifecycle.getAccessCount(), is(1L));
		assertThat(lifecycle.getTtlSec(), is(lifetimeSecs));
	}

}
