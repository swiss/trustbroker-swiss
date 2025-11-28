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

package swiss.trustbroker;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import swiss.trustbroker.accessrequest.service.NoOpAccessRequestService;
import swiss.trustbroker.announcement.service.NoOpAnnouncementService;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.homerealmdiscovery.service.NoOpHrdService;
import swiss.trustbroker.profileselection.service.NoOpProfileSelectionService;

@SpringBootApplication
@EnableScheduling
public class Application {

	public static void main(String[] args) {
		ApplicationStart.run(Application.class, args);
	}

	@Bean
	@ConditionalOnMissingBean(ProfileSelectionService.class)
	public ProfileSelectionService profileSelectionService() {
		return new NoOpProfileSelectionService();
	}

	@Bean
	@ConditionalOnMissingBean(AccessRequestService.class)
	public AccessRequestService accessRequestService() {
		return new NoOpAccessRequestService();
	}

	@Bean
	@ConditionalOnMissingBean(AnnouncementService.class)
	public AnnouncementService announcementService() {
		return new NoOpAnnouncementService();
	}

	@Bean
	@ConditionalOnMissingBean(HrdService.class)
	public HrdService hrdService() {
		return new NoOpHrdService();
	}

}
