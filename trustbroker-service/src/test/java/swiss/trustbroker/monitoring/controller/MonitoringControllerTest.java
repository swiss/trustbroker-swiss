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

package swiss.trustbroker.monitoring.controller;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.monitoring.dto.Status;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.dto.UiObjects;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.ClaimsProviderService;
import swiss.trustbroker.saml.service.SamlOutputService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		MonitoringController.class
})
@AutoConfigureMockMvc
class MonitoringControllerTest {

	private static final String RP_URN = "urn:rpIssuer1";

	private static final String CP_URN = "urn:cpIssuer1";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private SamlValidator samlValidator;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private AssertionConsumerService assertionConsumerService;

	@MockitoBean
	private ClaimsProviderService claimsProviderService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@MockitoBean
	private SamlOutputService samlOutputService;

	private ApiSupport apiSupport;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		SamlInitializer.initSamlSubSystem();
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
		this.apiSupport = new ApiSupport(trustBrokerProperties);
	}

	@Test
	void testMonitoringNoRp() throws Exception {
		this.mockMvc.perform(get(apiSupport.getMonitoringAcsUrl()))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(content().string(containsString(Status.INVALID.name())));
	}

	@Test
	void testMonitoringInvalidRp() throws Exception {
		this.mockMvc.perform(get(apiSupport.getMonitoringAcsUrl("dummy")))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(content().string(containsString(Status.INVALID.name())));
	}

	@Test
	void testMonitoringCpNotMatchingRp() throws Exception {
		var rp = createRelyingParty();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_URN, null, true);
		var state = createState();
		doReturn(state).when(assertionConsumerService)
					   .saveState(any(), anyBoolean(), any(), eq(rp), eq(Optional.empty()), any());
		var rpRequest = createRpRequest("dummyCp");
		doReturn(rpRequest).when(assertionConsumerService).handleRpAuthnRequest(any(), any(), eq(state));

		this.mockMvc.perform(get(apiSupport.getMonitoringAcsUrl(RP_URN, CP_URN)))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(content().string(containsString(Status.INVALID.name())));
	}

	@Test
	void testMonitoringMultipleCpForRp() throws Exception {
		var rp = createRelyingParty();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_URN, null, true);
		var state = createState();
		doReturn(state).when(assertionConsumerService)
					   .saveState(any(), anyBoolean(), any(), eq(rp), eq(Optional.empty()), any());
		var rpRequest = createRpRequest(CP_URN, "otherCp");
		doReturn(rpRequest).when(assertionConsumerService).handleRpAuthnRequest(any(), any(), eq(state));

		this.mockMvc.perform(get(apiSupport.getMonitoringAcsUrl(RP_URN)))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(content().string(containsString(Status.INVALID.name())));
	}

	@Test
	void testMonitoringRp() throws Exception {
		var rp = createRelyingParty();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_URN, null, true);
		var state = createState();
		doReturn(state).when(assertionConsumerService)
					   .saveState(any(), anyBoolean(), any(), eq(rp), eq(Optional.empty()), any());
		var rpRequest = createRpRequest(CP_URN);
		doReturn(rpRequest).when(assertionConsumerService).handleRpAuthnRequest(any(), any(), eq(state));

		// content empty, would be generated by real ClaimsProviderService
		this.mockMvc.perform(get(apiSupport.getMonitoringAcsUrl(RP_URN)))
				.andExpect(status().isOk())
				.andExpect(content().string(""));

		verify(claimsProviderService, times(1))
				.sendSamlToCpWithMandatoryIds(any(), any(), eq(state), any());
	}

	@ParameterizedTest
	@MethodSource
	void testMonitoringRpCp(Function<String, String> encoder, boolean queryParams) throws Exception {
		var rp = createRelyingParty();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_URN, null, true);
		var state = createState();
		doReturn(state).when(assertionConsumerService)
					   .saveState(any(), anyBoolean(), any(), eq(rp), eq(Optional.empty()), any());
		var rpRequest = createRpRequest("otherCp1", CP_URN);
		doReturn(rpRequest).when(assertionConsumerService).handleRpAuthnRequest(any(), any(), eq(state));

		// content empty, would be generated by real ClaimsProviderService
		var url = queryParams ? apiSupport.getMonitoringAcsUrlWithQueryParameters(encoder.apply(RP_URN), encoder.apply(CP_URN))
				: apiSupport.getMonitoringAcsUrl(encoder.apply(RP_URN), encoder.apply(CP_URN));
		this.mockMvc.perform(get(url))
				.andExpect(status().isOk())
				.andExpect(content().string(""));

		verify(claimsProviderService, times(1))
				.sendSamlToCpWithMandatoryIds(any(), any(), eq(state), any());
	}

	static Object[][] testMonitoringRpCp() {
		return new Object[][] {
				{ Function.identity(), false },
				{ Function.identity(), true },
				{ MonitoringControllerTest.encode(), false },
				{ MonitoringControllerTest.encode(), true }
		};
	}

	private static Function<String, String> encode() {
		return Base64Util::urlEncode;
	}

	@Test
	void testMonitoringRpSuccessfulResponse() throws Exception {
		mockDisabledSecurity();
		var responseStrEncoded = createSamlResponse(StatusCode.SUCCESS);
		this.mockMvc.perform(post(apiSupport.getMonitoringAcsUrl(RP_URN, CP_URN))
						.contentType(MediaType.TEXT_XML_VALUE)
						.param(SamlIoUtil.SAML_RESPONSE_NAME, responseStrEncoded)
				)
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(Status.UP.name())));
	}

	@Test
	void testMonitoringRpFailedResponse() throws Exception {
		mockDisabledSecurity();
		var responseStrEncoded = createSamlResponse(StatusCode.AUTHN_FAILED);
		this.mockMvc.perform(post(apiSupport.getMonitoringAcsUrl(RP_URN, CP_URN))
						.contentType(MediaType.TEXT_XML_VALUE)
						.param(SamlIoUtil.SAML_RESPONSE_NAME, responseStrEncoded)
				)
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(Status.DOWN.name())));
	}

	private void mockDisabledSecurity() {
		var checks = new SecurityChecks();
		checks.setRequireSignedAssertion(false);
		checks.setRequireSignedResponse(false);
		doReturn(checks).when(trustBrokerProperties).getSecurity();
	}

	private static String createSamlResponse(String statusCode) {
		var response = SamlFactory.createResponse(Response.class, CP_URN);
		response.setStatus(SamlFactory.createResponseStatus(statusCode));
		var responseStr = OpenSamlUtil.samlObjectToString(response);
		return Base64Util.urlEncode(responseStr);
	}

	private static RelyingParty createRelyingParty() {
		return RelyingParty.builder().id(RP_URN).build();
	}

	private static StateData createState() {
		return StateData.builder().id("random1").build();
	}

	private static RpRequest createRpRequest(String... cpUrn) {
		var uiObjectList = Arrays.stream(cpUrn).map(MonitoringControllerTest::createUiObject).toList();
		var uiObjects = UiObjects.builder().tiles(uiObjectList).build();
		return RpRequest.builder().uiObjects(uiObjects).build();
	}

	private static UiObject createUiObject(String urn) {
		return UiObject.builder().urn(urn).build();
	}

}
