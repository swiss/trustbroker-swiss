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

import java.io.Serializable;
import java.sql.Timestamp;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class Lifecycle implements Serializable {

	@NonNull
	@Builder.Default
	private LifecycleState lifecycleState = LifecycleState.INIT;

	private Timestamp initTime;

	private Timestamp ssoEstablishedTime;

	private Timestamp reauthTime;

	private Timestamp expirationTime;

	private Timestamp expiredTime;

	private long accessCount;

	@JsonIgnore
	public boolean isValid() {
		return !isExpired();
	}

	@JsonIgnore
	public boolean isExpired() {
		return lifecycleState == LifecycleState.EXPIRED;
	}

	@JsonIgnore
	public boolean isOverdueAt(Timestamp deadline) {
		return !isExpired() && expirationTime.before(deadline);
	}

	@JsonIgnore
	public boolean isSsoEstablished() {
		return lifecycleState == LifecycleState.ESTABLISHED;
	}

	@JsonIgnore
	public Timestamp getLastAuthTimestamp() {
		return reauthTime != null ? reauthTime : ssoEstablishedTime;
	}

	public synchronized void incAccessCount() {
		accessCount += 1;
	}

	@JsonIgnore
	public long getTtlSec() {
		if (initTime != null && expirationTime != null) {
			var created = initTime.getTime();
			var expiring = expirationTime.getTime();
			return (expiring - created) / 1000;
		}
		return 0;
	}

}
