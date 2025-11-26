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

package swiss.trustbroker.util;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class SessionTimeConfiguration {

	public static final int SESSION_LIFETIME_SECS = (int) TimeUnit.HOURS.toSeconds(1);

	// reap tests are based on this value and on it being bigger than the above
	public static final int SESSION_LIFETIME_SECS_SSO = (int) TimeUnit.DAYS.toSeconds(1);

	public static final int ARTIFACT_LIFETIME_SECS = 60;

	public static final int ARTIFACT_REAP_INTERVAL_SECS = 300;

	public static final Instant START_INSTANT = Instant.ofEpochMilli(1000000l);

	public static final Instant PAST_INSTANT = START_INSTANT.minusMillis(1);

	public static final Instant EXPIRATION_INSTANT = START_INSTANT.plusMillis(TimeUnit.SECONDS.toMillis(SESSION_LIFETIME_SECS));

	public static final Instant EXPIRATION_INSTANT_SSO =
			START_INSTANT.plusMillis(TimeUnit.SECONDS.toMillis(SESSION_LIFETIME_SECS_SSO));

	@Bean
	public static Clock clock() {
		return Clock.fixed(START_INSTANT, ZoneId.systemDefault());
	}

}
