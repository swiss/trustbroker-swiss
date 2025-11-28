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

package swiss.trustbroker.api.announcements.dto;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

@Data
public class Announcement implements Serializable {

	private String id;

	private Boolean visible;

	private String applicationId;

	private InternationalText title;

	private InternationalText message;

	private AnnouncementType type;

	private Boolean applicationAccessible;

	private InternationalText url;

	private String phoneNumber;

	private String emailAddress;

	private OffsetDateTime validFrom;

	private OffsetDateTime validTo;

	@JsonIgnore
	private OffsetDateTime cacheValidTo;

	private String applicationUrl;

	private String applicationName;

	// derived check
	@SuppressWarnings("java:S1126") // separate returns due to comments
	public boolean isValidAt(OffsetDateTime refTime) {
		if (validFrom != null && validFrom.isAfter(refTime)) {
			return false; // future
		}
		if (validTo != null && validTo.isBefore(refTime)) {
			return false; // past
		}
		if (cacheValidTo != null && cacheValidTo.isBefore(refTime)) {
			return false; // expired
		}
		return true; // valid
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Announcement announcement = (Announcement) obj;
		return Objects.equals(id, announcement.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id);
	}

}
