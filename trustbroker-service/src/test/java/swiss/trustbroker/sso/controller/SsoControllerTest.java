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

package swiss.trustbroker.sso.controller;

import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.SsoParticipant;
import swiss.trustbroker.saml.dto.SsoParticipants;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;
import swiss.trustbroker.util.WebSupport;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		SsoController.class
})
@AutoConfigureMockMvc
class SsoControllerTest {

	private static final String SSO_GROUP = "ssoGroup1";

	private static final String DEVICE_ID = "device1";

	private static final String RP_ID = "rp1";

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	RelyingPartyService relyingPartyService;

	@MockitoBean
	SamlValidator samlValidator;

	@MockitoBean
	SsoService ssoService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	private ApiSupport apiSupport;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		SamlInitializer.initSamlSubSystem();
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
		this.apiSupport = new ApiSupport(trustBrokerProperties);
	}

	private SsoParticipants createSsoParticipants(String ssoGroup, Set<String> participants) {
		var ssoParticipants = participants.stream()
				.map(rpId -> new SsoParticipant(rpId, "cpId", "image", "short", "color"))
				.collect(Collectors.toSet());
		return SsoParticipants.builder().ssoGroupName(ssoGroup).participants(ssoParticipants).build();
	}

	@Test
	void getSsoParticipants() throws Exception {
		var cookies = new Cookie[] { new Cookie("n1", "v1") };
		List<SsoParticipants> participantList = new ArrayList<>();
		participantList.add(createSsoParticipants(SSO_GROUP, Set.of("participant1", "participant2")));
		doReturn(participantList).when(ssoService).getAllSsoParticipants(cookies, DEVICE_ID);
		this.mockMvc.perform(get(apiSupport.getSsoParticipantsApi())
						.header(WebSupport.HTTP_HEADER_DEVICE_ID, DEVICE_ID)
						.cookie(cookies[0]))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON));
	}

	@Test
	void getSsoParticipantsForGroup() throws Exception {
		var cookies = new Cookie[] { new Cookie("n1", "v1") };
		var participants = createSsoParticipants(SSO_GROUP, Set.of("participant1", "participant2"));
		doReturn(participants).when(ssoService)
				.getSsoParticipants(SsoService.SsoCookieNameParams.of(SSO_GROUP), cookies, DEVICE_ID);
		this.mockMvc.perform(get(apiSupport.getSsoParticipantsApi(SSO_GROUP))
						.header(WebSupport.HTTP_HEADER_DEVICE_ID, DEVICE_ID)
						.cookie(cookies[0]))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON));
	}

	@Test
	void logoutSsoParticipant() throws Exception {
		var referer = "http://localhost:80";
		var cookies = new Cookie[] { new Cookie("n1", "v1") };
		var clearCookies = List.of(new Cookie("n1", ""));
		var cpId = "cp1";
		var subjectNameId = "subj1";
		doReturn(clearCookies).when(ssoService)
				.logoutSsoParticipantById(SsoService.SsoCookieNameParams.of(SSO_GROUP,  cpId, subjectNameId), cookies,
						DEVICE_ID, RP_ID);
		this.mockMvc.perform(delete(apiSupport.getSsoGroupApi(SSO_GROUP, RP_ID, cpId, subjectNameId))
						.header(HttpHeaders.REFERER, referer)
						.header(WebSupport.HTTP_HEADER_DEVICE_ID, DEVICE_ID)
						.cookie(cookies[0]))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(HttpHeaders.SET_COOKIE, "n1="))
				.andExpect(header().string(HttpHeaders.LOCATION, referer + "?status=" + HttpServletResponse.SC_OK));
	}

	@Test
	void logoutSsoParticipantFromSingleActiveGroup() throws Exception {
		logoutSsoParticipant(List.of(createSsoParticipants(SSO_GROUP, Set.of(RP_ID))));
	}

	@Test
	void logoutSsoParticipantFromMultipleActiveGroups() throws Exception {
		logoutSsoParticipant(List.of(
				createSsoParticipants("otherGroup", Set.of(RP_ID)),
				createSsoParticipants(SSO_GROUP, Set.of(RP_ID))));
	}

	private void logoutSsoParticipant(List<SsoParticipants> ssoParticipants) throws Exception {
		var referer = "http://localhost:80";
		var cookies = new Cookie[] { new Cookie("n1", "v1") };
		var clearCookies = List.of(new Cookie("n1", ""));
		doReturn(ssoParticipants).when(ssoService).getAllSsoParticipants(cookies, DEVICE_ID);
		doReturn(clearCookies).when(ssoService)
				.logoutSsoParticipantById(SsoService.SsoCookieNameParams.of(SSO_GROUP), cookies, DEVICE_ID, RP_ID);
		this.mockMvc.perform(delete(apiSupport.getSsoRpApi(RP_ID))
						.header(HttpHeaders.REFERER, referer)
						.header(WebSupport.HTTP_HEADER_DEVICE_ID, DEVICE_ID)
						.cookie(cookies[0]))
				.andExpect(status().isOk())
				.andExpect(ssoParticipants.size() == 1 ? header().string(HttpHeaders.SET_COOKIE, "n1=") :
						header().doesNotExist(HttpHeaders.SET_COOKIE));
	}

}
