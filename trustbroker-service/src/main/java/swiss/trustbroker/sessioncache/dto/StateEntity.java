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
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DB entity.
 */
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "TB_AUTH_SESSION_CACHE")
public class StateEntity implements Serializable {

	@Id
	@Column(name = "SESSION_ID")
	private String id;

	@Column(name = "SP_SESSION_ID")
	private String spSessionId;

	@Column(name = "SSO_SESSION_ID")
	private String ssoSessionId;

	@Column(name = "OIDC_SESSION_ID")
	private String oidcSessionId;

	@Column(name = "DATA", columnDefinition = "MEDIUMTEXT")
	private String jsonData;

	/**
	 * The scheduled reaper uses this field to clean up the database.
	 * The state 'valid' attribute to discard invalidated entries shall not be used in the reaper (yet).
	 */
	@Column(name = "EXPIRATION_TIMESTAMP")
	private Timestamp expirationTimestamp;

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		StateEntity that = (StateEntity) o;
		return Objects.equals(id, that.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id);
	}

}
