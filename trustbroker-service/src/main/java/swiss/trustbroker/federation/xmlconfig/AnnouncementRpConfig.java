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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.announcements.dto.AnnouncementsRpData;

/**
 * This class describes the configuration of announcements for an RP.
 *
 * @see swiss.trustbroker.api.announcements.service.AnnouncementService
 */
@XmlRootElement(name = "Announcements")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnnouncementRpConfig implements Serializable, AnnouncementsRpData {

	/**
	 * Enable this configuration.
 	 */
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * URLs for the announcement.
	 */
	@XmlElement(name = "AppUrl")
	private List<String> announcementUrls;

	@JsonIgnore
	@Override
	public boolean isAnnouncementEnabled() {
		return Boolean.TRUE.equals(enabled);
	}
}
