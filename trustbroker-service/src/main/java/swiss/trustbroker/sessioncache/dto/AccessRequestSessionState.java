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

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessRequestSessionState implements Serializable {

	private AccessRequestState state;

	private String rpIssuerId;

	private String responseId;

	private String mode;

	private Timestamp initTime;

	private Timestamp sentTime;

	private Timestamp completedTime;

	private String returnUrl;

	@JsonIgnore
	public boolean isOngoingForRelyingParty(String issuerId) {
		if (issuerId != null && issuerId.equals(rpIssuerId)) {
			return state == AccessRequestState.WAITING_FOR_RESPONSE;
		}
		return false;
	}
}
