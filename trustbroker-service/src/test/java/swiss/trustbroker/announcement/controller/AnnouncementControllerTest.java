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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.dto.AnnouncementType;
import swiss.trustbroker.api.announcements.dto.AnnouncementUiElement;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AnnouncementRpConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.util.ApiSupport;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		AnnouncementController.class,
		ApiSupport.class
})
@AutoConfigureMockMvc
@TestPropertySource(properties="trustbroker.config.announcements.enabled=true")
class AnnouncementControllerTest {

	private static final String RP_ID = "urn:rp1";

	private static final String CP_ID = "cp-1";

	private static final String CP_ID_ENCODED = "CP1";

	private static final String APP_NAME = "urn:app1";

	private static final AnnouncementType ANNOUNCEMENT_TYPE = AnnouncementType.INCIDENT;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private AnnouncementService announcementService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@MockitoSpyBean
	private ApiSupport apiSupport;

	@Autowired
	private AnnouncementController controller;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
	}

	@ParameterizedTest
	@CsvSource(value = { APP_NAME, "null" }, nullValues = "null")
	void testAnnouncements(String appName) throws Exception {
		var rp = givenRelyingParty();
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(RP_ID, null)).thenReturn(rp);
		var announcement = givenAnnouncement();
		var cpIds = Set.of(CP_ID_ENCODED);
		when(announcementService.getAnnouncementsForApplication(rp, rp.getAnnouncement(), appName, cpIds))
				.thenReturn(List.of(announcement));
		when(announcementService.isRpAppAccessible(announcement)).thenReturn(true);
		var result = AnnouncementUiElement.builder()
										  .applicationAccessible(true)
										  .type(ANNOUNCEMENT_TYPE)
										  .build();
		var resultJson = new ObjectMapper().writeValueAsString(List.of(result));
		this.mockMvc.perform(get(apiSupport.getAnnouncementsApi(RP_ID, appName)))
		            .andExpect(status().isOk())
		            .andExpect(content().json(resultJson));
	}

	private static Announcement givenAnnouncement() {
		return Announcement.builder()
		                   .type(ANNOUNCEMENT_TYPE)
		                   .build();
	}

	private static RelyingParty givenRelyingParty() {
		var cp = givenClaimsProvider();
		return RelyingParty.builder()
						   .id(RP_ID)
						   .announcement(AnnouncementRpConfig.builder().enabled(true).build())
						   .claimsProviderMappings(ClaimsProviderMappings.builder().claimsProviderList(List.of(cp)).build())
						   .build();
	}

	private static ClaimsProvider givenClaimsProvider() {
		return ClaimsProvider.builder()
							 .id(CP_ID)
							 .build();
	}

}
