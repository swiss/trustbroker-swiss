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

package swiss.trustbroker.announcement.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.dto.AnnouncementsRpData;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;

/**
 * NO-OP fallback implementation of AnnouncementService, provides no announcements.
 *
 * @see AnnouncementService
 */
@Service
@ConditionalOnMissingBean(AnnouncementService.class)
@Slf4j
public class NoOpAnnouncementService implements AnnouncementService {

	@Override
	public boolean showAnnouncements(AnnouncementsRpData announcementsRpData, String providerName, Set<String> conditions) {
		log.debug("{}.showAnnouncements called", this.getClass().getName());
		return false;
	}

	@Override
	public boolean isRpAppAccessible(Announcement announcement) {
		log.debug("{}.isRpAppAccessible called", this.getClass().getName());
		return false;
	}

	@Override
	public List<Announcement> getAnnouncementsForApplication(RelyingPartyConfig relyingPartyConfig,
			AnnouncementsRpData announcementsRpData, String appName) {
		log.debug("{}.getAnnouncementsForApplication called", this.getClass().getName());
		return new ArrayList<>();
	}

	@Override
	public List<Announcement> getGlobalAnnouncements() {
		log.debug("{}.getGlobalAnnouncements called", this.getClass().getName());
		return new ArrayList<>();
	}

}
