/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.announcement.controller;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.dto.AnnouncementUiElement;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartyUtil;
import swiss.trustbroker.util.ApiSupport;

/**
 * Controller for announcement services.
 */
@RestController
@AllArgsConstructor
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.announcements.enabled")
public class AnnouncementController {

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final AnnouncementService announcementService;

	@GetMapping(value = {
			ApiSupport.ANNOUNCEMENTS_URL + "/{issuer}/{appName}",
			ApiSupport.ANNOUNCEMENTS_URL + "/{issuer}"
	})
	public List<AnnouncementUiElement> getAnnouncements(HttpServletRequest request,
			@PathVariable("issuer") String issuer, @PathVariable(required = false, name = "appName") String appName) {

		String decodedIssuer = ApiSupport.decodeUrlParameter(issuer);
		String applicationName = null;
		if (appName != null) {
			applicationName = ApiSupport.decodeUrlParameter(appName);
		}
		log.debug("Requested announcements for issuer={} appName={}", issuer, appName);

		RelyingParty relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(decodedIssuer, null);
		if (relyingParty == null) {
			log.error("RP config was not found for issuer={} appName={}, no announcements will be shown", decodedIssuer,
					applicationName);
			return Collections.emptyList();
		}

		Set<String> idpIds = RelyingPartyUtil.getCpIdsWithoutSpecChars(relyingParty);

		List<Announcement> announcementsForApplication =
				announcementService.getAnnouncementsForApplication(relyingParty, relyingParty.getAnnouncement(), applicationName,
						idpIds);

		// adminlogin cookie shall let users pass
		var skipDisabling = OperationalUtil.skipUiFeaturesForAdminAndMonitoringClients(request, trustBrokerProperties);

		// HRD on client to display tiles with or without disabling
		return announcementsForApplication.stream()
				.map(announcementEntity -> buildAnnouncementElement(announcementEntity, skipDisabling))
				.toList();
	}

	private AnnouncementUiElement buildAnnouncementElement(Announcement announcementEntity, boolean skipDisabling) {
		var applicationAccessible = announcementService.isRpAppAccessible(announcementEntity) || skipDisabling;
		return AnnouncementUiElement.builder()
		                            .type(announcementEntity.getType())
		                            .applicationAccessible(applicationAccessible)
		                            .message(announcementEntity.getMessage())
		                            .title(announcementEntity.getTitle())
		                            .url(announcementEntity.getUrl())
		                            .phoneNumber(announcementEntity.getPhoneNumber())
		                            .emailAddress(announcementEntity.getEmailAddress())
		                            .validTo(announcementEntity.getValidTo())
		                            .build();
	}
}
