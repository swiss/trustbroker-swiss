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

package swiss.trustbroker.profileselection.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.service.RedirectOutputService;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.profileselection.service.ProfileSelectionServiceFactory;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;
import tools.jackson.databind.ObjectMapper;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		ProfileSelectionController.class,
		ApiSupport.class
})
@AutoConfigureMockMvc
@TestPropertySource(properties="trustbroker.config.profileselection.enabled=true")
class ProfileSelectionControllerTest {

	private static final String SESSION_ID = "relay1";

	private static final String URL = "https://localhost";

	private static final String PROFILE_ID = "id1";

	private static final String RP_ID = "rp1";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private ProfileSelectionServiceFactory profileSelectionServiceFactory;

	@MockitoBean
	private RelyingPartyService relyingPartyService;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private StateCacheService stateCacheService;

	@MockitoBean
	private List<OutputService> outputServices;

	@MockitoBean
	private RedirectOutputService redirectOutputService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@MockitoSpyBean
	private ApiSupport apiSupport;

	@Autowired
	private ProfileSelectionController controller;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
	}

	@Test
	void handleProfiles() throws Exception {
		var result = ProfileResponse.builder().redirectUrl(URL).id(PROFILE_ID).build();
		var resultJson = new ObjectMapper().writeValueAsString(result);
		var spStateData = StateData.builder().id("authn1").issuer(RP_ID).build();
		var stateData = StateData.builder().id(PROFILE_ID).spStateData(spStateData).build();
		var cpResponse = CpResponse.builder().build();
		stateData.setCpResponse(cpResponse);
		var rp = RelyingParty.builder()
							 .id(RP_ID)
							 .idmLookup(IdmLookup.builder().store("test").build())
							 .build();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ID, null);
		doReturn(stateData).when(stateCacheService).find(PROFILE_ID, ProfileSelectionController.class.getSimpleName());
		var profileSelectionData = ProfileSelectionData.builder().selectedProfileId(PROFILE_ID).ignoreEmptyProfiles(true).build();
		var mockProfileSelectionService = mock(ProfileSelectionService.class);
		when(profileSelectionServiceFactory.getProfileSelectionService(any(IdmLookup.class)))
				.thenReturn(mockProfileSelectionService);
		doReturn(result).when(mockProfileSelectionService).buildProfileResponse(profileSelectionData, stateData.getCpResponse());
		this.mockMvc.perform(get(apiSupport.getProfilesApi()).header(WebSupport.HTTP_HEADER_XTB_PROFILE_ID, PROFILE_ID))
		            .andExpect(status().isOk())
		            .andExpect(content().json(resultJson));
	}

	private RequestBuilder postSelectedProfile(String redirectUrl) {
		var request = new ProfileRequest(PROFILE_ID, SESSION_ID);
		var requestJson = new ObjectMapper().writeValueAsString(request);
		doReturn(redirectUrl).when(relyingPartyService)
		                     .sendResponseWithSelectedProfile(eq(outputServices), eq(request), any(), any());
		when(redirectOutputService.handleRedirect(any(), any(), eq(redirectUrl)))
				.thenReturn(redirectUrl);
		return post(apiSupport.getProfileApi())
				.content(requestJson)
				.contentType(MediaType.APPLICATION_JSON_VALUE);
	}

	@Test
	void handleSelectProfile() throws Exception {
		this.mockMvc.perform(postSelectedProfile(null))
		            .andExpect(status().isOk());
	}

	@Test
	void handleSelectProfileWithRedirect() throws Exception {
		this.mockMvc.perform(postSelectedProfile(URL))
		            .andExpect(status().is3xxRedirection())
		            .andExpect(header().string(HttpHeaders.LOCATION, URL));
	}

}
