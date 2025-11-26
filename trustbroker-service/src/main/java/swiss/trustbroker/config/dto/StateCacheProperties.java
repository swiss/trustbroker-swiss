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

package swiss.trustbroker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration for DB state cache.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StateCacheProperties {

	/**
	 * If the session DB runs full (more than targetMaxEntries), XTB starts garbage collecting sessions, that might expire anyway
	 * soon to make room for new sessions and prevent storage issues.
	 */
	private int targetMaxEntries;

	/**
	 * Prevents collecting sessions related to a pending login.
	 */
	private int minSessionLifetimeSec;

	/**
	 * Use by scheduled job checking for expired sessions and delete them from the session DB StateCache. When multiple pods are
	 * running the reapMaxDelaySec is used to randomly delay the reaping to reduce concurrent work on the same data.
	 * <br/>
	 * Cron expression, default is '30 * * * * *' which means run every 60sec at HH:MM:30
	 */
	private String reapSchedule;

	/**
	 * Delay at most 25 sec randomly to allow multiple reapers on the same session DB.
	 */
	private int reapMaxDelaySec;

	/**
	 * Expected reap cycle execution in milliseconds before we start to WARN about bad performance.
	 * <br/>
	 * Default: 10000
	 */
	@Builder.Default
	private int reapWarnThresholdMs = 10000;

	/**
	 * Delay before transaction commit in milliseconds. For testing race conditions only, do not set in production environments!
	 * <br/>
	 * Default: 0
	 */
	@Builder.Default
	private int txCommitDelay = 0;

	/**
	 * Delay before transaction retry in milliseconds (negative values indicate no retry).
	 * <br/>
	 * Default: -1
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private int txRetryDelayMs = -1;

	/**
	 * Number of retries doubling the txRetryDelayMs on every try.
	 * <br/>
	 * Default: 0
	 *
	 * @since 1.10.0
	 */
	@Builder.Default
	private int txRetryCount = 0;

	/**
	 * State cache schema migration. Currently unused.
	 * <br/>
	 * Default: true
	 */
	@Builder.Default
	private boolean schemaMigration = true;
}
