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

package swiss.trustbroker.saml.controller;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.xml.validation.Validator;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.xmlsec.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.setup.config.BootstrapProperties;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.GuiProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.service.FederationMetadataService;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.homerealmdiscovery.controller.HrdController;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.saml.service.ArtifactResolutionService;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.AuthenticationService;
import swiss.trustbroker.saml.service.ClaimsProviderService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.service.SamlOutputService;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.saml.util.SkinnyHrd;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;

// hacky class requiring to mock out new unused/untested facilities
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration(classes = {
		AppController.class,
		AssertionConsumerService.class,
		RelyingPartySetupService.class,
		RelyingPartyDefinitions.class,
		SamlValidator.class,
		ApiSupport.class,
		AuthenticationService.class
})
@AutoConfigureMockMvc
class AppControllerTest {

	private static final String URL_TEMPLATE = ApiSupport.SAML_API;

	private static final String TEST_RELAY_STATE = "idp-relay-state";

	private static final String RP_ISSUER_SINGLE_CP = "urn:test:SSO-GROUP1-SINGLE-CP-TEST";

	private static final String CP_ISSUER = "urn:test:TESTCP";

	private static final String RP_ISSUER_MULTIPLE_CP = "urn:test:SSO-GROUP2-PART1-TEST";

	private static final String VERSION_INFO = "XTB/9.8.7.654321@TEST";

	@MockitoBean
	private HrdController hrdController;

	@MockitoBean
	@Qualifier("samlSchemaValidator")
	private Validator validator;

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	@Qualifier("stateCache")
	private StateCacheService stateCacheService;

	@MockitoBean
	private RelyingPartyService relyingPartyService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private ClaimsProviderService claimsProviderService;

	@MockitoBean
	private FederationMetadataService federationMetadataService;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private AnnouncementService announcementService;

	@MockitoBean
	private ArtifactResolutionService artifactResolutionService;

	@MockitoBean
	private SamlOutputService outputService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@Autowired
	private ApiSupport apiSupport;

	@Autowired
	private AppController appController;

	@MockitoBean
	private SsoService ssoService;

	@MockitoBean
	private AuditService auditService;

	@MockitoBean
	private QoaMappingService qoaMappingService;

	@MockitoBean
	private HrdService hrdService;

	private MockMvc mockMvc;

	@BeforeAll
	static void setupAll() {
		SamlInitializer.initSamlSubSystem();

		new CoreAttributeInitializer().init();
		// AssertionConsumerService needs this:
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.AUTH_LEVEL);

		System.setProperty(BootstrapProperties.GIT_CONFIG_CACHE, ServiceSamlTestUtil.getResourceDir());
	}

	@BeforeEach
	void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
		when(trustBrokerProperties.getGui()).thenReturn(new GuiProperties());
		when(trustBrokerProperties.getSaml()).thenReturn(new SamlProperties());
		when(trustBrokerProperties.getOidc()).thenReturn(new OidcProperties());
		doAnswer(invocation -> invocation.getArgument(1)).when(hrdService).adaptClaimsProviderMappings(any(), any());
	}

	@Test
	void handleIncomingMessagesRequestMissingIDTest() {
		AuthnRequest authnRequest = ServiceSamlTestUtil.loadAuthnRequest();
		Signature newSignature =
				ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_TB_KEYSTORE_JKS,
						SamlTestBase.TEST_KEYSTORE_PW, SamlTestBase.TEST_KEYSTORE_TB_ALIAS);
		authnRequest.setIssueInstant(Instant.now());

		authnRequest.setID(null);

		authnRequest.setSignature(newSignature);
		SamlUtil.signSamlObject(authnRequest, newSignature);
		String encodedMessage = SamlUtil.encode(authnRequest);

		mockProperties();
		mockRequestConfiguration();

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(
					post(URL_TEMPLATE)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
							.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage));
		});
		Throwable cause = exception.getCause();
		assertInstanceOf(RequestDeniedException.class, cause, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesInvalidRequestACUrlTest() {
		AuthnRequest authnRequest = ServiceSamlTestUtil.loadAuthnRequest();
		Signature newSignature =
				ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_TB_KEYSTORE_JKS, SamlTestBase.TEST_KEYSTORE_PW,
						SamlTestBase.TEST_KEYSTORE_TB_ALIAS);
		authnRequest.setIssueInstant(Instant.now());

		authnRequest.setAssertionConsumerServiceURL("https://testAssertionUrl");

		authnRequest.setSignature(newSignature);
		SamlUtil.signSamlObject(authnRequest, newSignature);
		String encodedMessage = SamlUtil.encode(authnRequest);

		mockProperties();
		mockRequestConfiguration();

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(
					post(URL_TEMPLATE)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
							.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesInvalidRequestSignatureTest() {
		AuthnRequest authnRequest = ServiceSamlTestUtil.loadAuthnRequest();
		Signature newSignature = ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_IDP_MOCK_KEYSTORE_JKS,
				SamlTestBase.TEST_KEYSTORE_PW, SamlTestBase.TEST_IDP_MOCK_KEYSTORE_ALIAS);
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setSignature(newSignature);
		SamlUtil.signSamlObject(authnRequest, newSignature);
		String encodedMessage = SamlUtil.encode(authnRequest);

		mockProperties();
		mockRequestConfiguration();

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(
					post(URL_TEMPLATE)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
							.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestTest() throws Exception {
		var authnRequest = prepareValidIncomingAuthnRequest();
		String encodedMessage = SamlUtil.encode(authnRequest);
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION,
						apiSupport.getHrdUrl(ServiceSamlTestUtil.AUTHN_REQUEST_ISSUER_ID, authnRequest.getID())));
	}

	@Test
	void handleIncomingMessagesInvalidBindingTest() {
		var authnRequest = prepareValidIncomingAuthnRequest();
		var encodedMessage = SamlUtil.encode(authnRequest);

		mockProperties();
		mockRequestConfiguration();
		var relyingParty = getRelyingParty(ServiceSamlTestUtil.AUTHN_REQUEST_ISSUER_ID);
		relyingParty.setSaml(Saml.builder()
				.artifactBinding(ArtifactBinding.builder().inboundMode(ArtifactBindingMode.REQUIRED).build())
				.build());
		var exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(
					post(URL_TEMPLATE)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
							.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage));
		});
		var cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
		var rex = (RequestDeniedException)cause;
		assertThat(rex.getInternalMessage(), containsString("does not support inbound binding"));
	}

	@Test
	void handleIncomingMessagesValidRedirectAuthnRequestTest() throws Exception {
		// signature is embedded in message as in POST (the normal redirect way is to use a separate query parameter)
		var authnRequest = prepareValidIncomingAuthnRequest();
		var encodedMessage = SamlIoUtil.encodeSamlRedirectData(authnRequest);
		this.mockMvc.perform(get(URL_TEMPLATE).queryParam(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION,
						apiSupport.getHrdUrl(ServiceSamlTestUtil.AUTHN_REQUEST_ISSUER_ID, authnRequest.getID())));
	}

	@Test
	void handleIncomingMessagesValidRedirectAuthnRequestTestSignature() throws Exception {
		handleIncomingMessagesValidRedirectAuthnRequest(false);
	}

	@Test
	void handleIncomingMessagesValidRedirectAuthnRequestTestDoubleSignature() throws Exception {
		handleIncomingMessagesValidRedirectAuthnRequest(true);
	}

	private void handleIncomingMessagesValidRedirectAuthnRequest(boolean doubleSignature) throws Exception {
		var authnRequest = prepareValidIncomingAuthnRequest();
		var query = SamlTestBase.buildRedirectQueryString(authnRequest, doubleSignature);
		this.mockMvc.perform(get(new URI(URL_TEMPLATE + '?' + query)))
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION,
						apiSupport.getHrdUrl(ServiceSamlTestUtil.AUTHN_REQUEST_ISSUER_ID, authnRequest.getID())));
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSsoSkipAuthenticationTest() throws Exception {
		handleIncomingMessagesSso(RP_ISSUER_MULTIPLE_CP, CP_ISSUER, SsoService.SsoSessionOperation.JOIN);
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSsoStepupTest() throws Exception {
		handleIncomingMessagesSso(RP_ISSUER_MULTIPLE_CP, CP_ISSUER, SsoService.SsoSessionOperation.STEPUP);
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSingleCpSsoSkipAuthenticationTest() throws Exception {
		handleIncomingMessagesSso(RP_ISSUER_SINGLE_CP, CP_ISSUER, SsoService.SsoSessionOperation.JOIN);
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSingleCpSsoStepupTest() throws Exception {
		handleIncomingMessagesSso(RP_ISSUER_SINGLE_CP, CP_ISSUER, SsoService.SsoSessionOperation.STEPUP);
	}

	private void handleIncomingMessagesSso(String rpIssuer, String cpIssuer, SsoService.SsoSessionOperation op) throws Exception {
		var authnRequest = prepareValidIncomingAuthnRequest(rpIssuer);
		var stateData = ServiceSamlTestUtil.givenStateCacheData();
		doReturn(Optional.of(stateData)).when(ssoService).findValidStateFromCookies(
				argThat(rp -> rp.getId().equals(rpIssuer)),
				argThat(cp -> cp.getId().equals(cpIssuer)),
				any());
		doReturn(op).when(ssoService).skipCpAuthentication(
				argThat(cp -> cp.getId().equals(cpIssuer)),
				argThat(rp -> rp.getId().equals(rpIssuer)),
				any(), eq(stateData));
		var encodedMessage = SamlUtil.encode(authnRequest);
		var expectedLocation = op.skipCpAuthentication() ? apiSupport.getDeviceInfoUrl(cpIssuer, rpIssuer, authnRequest.getID()) :
				apiSupport.getHrdUrl(rpIssuer, authnRequest.getID());
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION, expectedLocation));
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSingleCpTest() throws Exception {
		var rpIssuer = "urn:test:SINGLE-CP-TEST";
		var authnRequest = prepareValidIncomingAuthnRequest(rpIssuer);
		String encodedMessage = SamlUtil.encode(authnRequest);
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isOk());
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestSkinnyHrdTest() throws Exception {
		var skinny = "showSkinny";
		var skinnyHrdTriggers =
				List.of(RegexNameValue.builder().name(skinny).regex("true").value(SkinnyHrd.SKINNY_HRD_HTML).build());
		doReturn(skinnyHrdTriggers).when(trustBrokerProperties).getSkinnyHrdTriggers();
		doReturn(VERSION_INFO).when(trustBrokerProperties).getVersionInfo();
		var authnRequest = prepareValidIncomingAuthnRequest();
		var encodedMessage = SamlUtil.encode(authnRequest);
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage)
						.header(skinny, "true")
				)
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION, containsString(SkinnyHrd.SKINNY_HRD_HTML)))
				.andExpect(header().string(HttpHeaders.LOCATION, containsString(authnRequest.getID())))
				.andExpect(header().string(HttpHeaders.LOCATION, containsString(VERSION_INFO)));
	}

	@Test
	void handleIncomingMessagesValidPostAuthnRequestAnnouncementsTest() throws Exception {
		doReturn(true).when(announcementService).showAnnouncements(any(), nullable(String.class), eq(Set.of()));
		var authnRequest = prepareValidIncomingAuthnRequest();
		var encodedMessage = SamlUtil.encode(authnRequest);
		var referer = "https://saml-test.localdomain/caller";
		var origin = "https://saml-test.localdomain";
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage)
						.header(HttpHeaders.REFERER, referer)
						.header(HttpHeaders.ORIGIN, origin)
				)
				.andExpect(status().isFound())
				.andExpect(header().string(HttpHeaders.LOCATION, apiSupport.getAnnouncementsUrl(
						ServiceSamlTestUtil.AUTHN_REQUEST_ISSUER_ID, authnRequest.getID(), null)));
	}

	private AuthnRequest prepareValidIncomingAuthnRequest() {
		return prepareValidIncomingAuthnRequest(null);
	}

	private AuthnRequest prepareValidIncomingAuthnRequest(String issuerId) {
		var authnRequest = ServiceSamlTestUtil.loadAuthnRequest();
		if (issuerId != null) {
			authnRequest.setIssuer(SamlFactory.createIssuer(issuerId));
		}
		return prepareValidIncomingRequest(authnRequest);
	}

	private <T extends RequestAbstractType> T prepareValidIncomingRequest(T request) {
		doThrow(new IllegalArgumentException()).when(relyingPartyService).sendFailedSamlResponseToRp(
				any(), any(), any(), any(), any());
		var newSignature =
				ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_TB_KEYSTORE_JKS, SamlTestBase.TEST_KEYSTORE_PW,
						SamlTestBase.TEST_KEYSTORE_TB_ALIAS);
		request.setIssueInstant(Instant.now());

		request.setSignature(newSignature);
		SamlUtil.signSamlObject(request, newSignature);

		mockProperties();
		mockRequestConfiguration();

		return request;
	}

	@Test
	void handleIncomingMessagesResponseNotInCacheTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockInvalidCache();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesNotSuccessResponseStatusTest() throws Exception {
		var status = SamlFactory.createResponseStatus(StatusCode.AUTHN_FAILED);
		handleIncomingResponseWithStatus(status);
	}

	@Test
	void handleIncomingMessagesSwitchToEnterpriseTest() throws Exception {
		when(trustBrokerProperties.isHandleEnterpriseSwitch()).thenReturn(true);
		when(trustBrokerProperties.getEnterpriseIdpId()).thenReturn("TheEnterpriseIdp");
		var status = SamlFactory.createResponseStatus(StatusCode.RESPONDER, "switch to enterprise", StatusCode.NO_AUTHN_CONTEXT);
		handleIncomingResponseWithStatus(status);
	}

	private void handleIncomingResponseWithStatus(Status status) throws Exception {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		authnResponse.setStatus(status);

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.params(params))
				.andExpect(status().isOk());
	}

	@Test
	void handleIncomingMessagesInvalidResponseIssuerTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		authnResponse.setIssuer(SamlFactory.createIssuer("testwrongissuer"));

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesInvalidResponseRelayStateTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, "testwrong_RelayState");

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesNoAssertionInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		authnResponse.getAssertions().clear();

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException, "Got unexpected exception " + cause);
	}

	@Test
	void handleIncomingMessagesMoreAssertionInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);
		authnResponse.getAssertions().add(OpenSamlUtil.buildAssertionObject());

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionSubjectInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		assertion.setSubject(null);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionNameIdInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		assertion.getSubject().setNameID(null);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionSignatureInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = resetAssertionSignatureWithWrongSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionNotSignedInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = authnResponse.getAssertions().get(0);
		assertion.setSignature(null);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionTimestampInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionSubjectConfirmationInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		authnResponse.setInResponseTo("wrong id");

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@Test
	void handleIncomingMessagesInvalidAssertionAudienceInResponseTest() {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);
		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);


		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockPropertiesWithWrongIssuer();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		Exception exception = assertThrows(ServletException.class, () -> {
			this.mockMvc.perform(post(URL_TEMPLATE)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.params(params));
		});
		Throwable cause = exception.getCause();
		assertTrue(cause instanceof RequestDeniedException);
	}

	@ParameterizedTest
	@CsvSource(value = {
			URL_TEMPLATE,
			ApiSupport.ADFS_ENTRY_URL_TRAILING_SLASH
	})
	void handleIncomingMessagesValidResponseTest(String entryUrl) throws Exception {
		Response authnResponse = ServiceSamlTestUtil.loadAuthnResponse();
		authnResponse.setIssueInstant(Instant.now());

		Instant newNotOnOrAfter = Instant.now().plus(60, ChronoUnit.MINUTES);
		authnResponse.getAssertions().get(0).getConditions().setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getConditions().setNotBefore(Instant.now());
		authnResponse.getAssertions().get(0).getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(newNotOnOrAfter);
		authnResponse.getAssertions().get(0).getAuthnStatements().get(0).setAuthnInstant(Instant.now());
		authnResponse.getAssertions().get(0).setIssueInstant(Instant.now());

		Assertion assertion = resetAssertionSignature(authnResponse);

		authnResponse.getAssertions().clear();
		authnResponse.getAssertions().add(assertion);

		String encodedMessage = SamlUtil.encode(authnResponse);

		mockRequestConfiguration();
		mockCacheService();
		mockProperties();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);
		params.add(SamlIoUtil.SAML_RELAY_STATE, TEST_RELAY_STATE);

		this.mockMvc.perform(post(entryUrl)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.params(params))
				.andExpect(status().isOk());
	}

	@Test
	void handleIncomingSampleResponseTest() {
		var authnResponse = ServiceSamlTestUtil.loadSampleResponse();
		mockProperties();
		assertDoesNotThrow(() -> appController.validateSamlSchema(authnResponse, null));
	}

	private RelyingParty getRelyingParty(String rpId) {
		return relyingPartyDefinitions.getRelyingPartySetup().getRelyingParties().stream()
						.filter(rp -> rp.getId().equals(rpId)).findFirst().orElseThrow();
	}

	private Assertion resetAssertionSignature(Response response) {
		Signature newSignature =
				ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_TB_KEYSTORE_JKS, SamlTestBase.TEST_KEYSTORE_PW,
						SamlTestBase.TEST_KEYSTORE_TB_ALIAS);

		Assertion assertion = response.getAssertions().get(0);
		assertion.setSignature(null);
		assertion.setSignature(newSignature);
		SamlUtil.signSamlObject(assertion, newSignature);

		// signed response now checked when present
		response.setSignature(null);

		return assertion;
	}

	private Assertion resetAssertionSignatureWithWrongSignature(Response authnResponse) {
		Signature newSignature = ServiceSamlTestUtil.givenSignature(SamlTestBase.TEST_IDP_MOCK_KEYSTORE_JKS,
				SamlTestBase.TEST_KEYSTORE_PW, SamlTestBase.TEST_IDP_MOCK_KEYSTORE_ALIAS);

		Assertion assertion = authnResponse.getAssertions().get(0);
		assertion.setSignature(null);
		assertion.setSignature(newSignature);
		SamlUtil.signSamlObject(assertion, newSignature);
		return assertion;
	}


	private void mockProperties() {
		when(trustBrokerProperties.getSecurity()).thenReturn(ServiceSamlTestUtil.givenEnabledSecurity());
		when(trustBrokerProperties.getIssuer()).thenReturn("http://test.trustbroker.swiss");
		when(trustBrokerProperties.getQoa()).thenReturn(givenQoaConfig());
	}

	private QualityOfAuthenticationConfig givenQoaConfig() {
		Map<String, Integer> qoaMap = new HashMap<>();
		qoaMap.put("urn:qoa:names:tc:ac:classes:10", 10);
		qoaMap.put("urn:qoa:names:tc:ac:classes:20", 20);
		qoaMap.put("urn:qoa:names:tc:ac:classes:30", 30);
		QualityOfAuthenticationConfig qoa = new QualityOfAuthenticationConfig();
		qoa.setMapping(qoaMap);
		return qoa;
	}

	private void mockPropertiesWithWrongIssuer() {
		when(trustBrokerProperties.getSecurity()).thenReturn(ServiceSamlTestUtil.givenEnabledSecurity());
		when(trustBrokerProperties.getIssuer()).thenReturn("http://wrongissuer");
	}

	private void mockCacheService() {
		when(stateCacheService.find(any(), any())).thenReturn(ServiceSamlTestUtil.givenStateCacheData());
	}

	private void mockInvalidCache() {
		when(stateCacheService.find(any(), any())).thenReturn(ServiceSamlTestUtil.givenInvalidStateCache());
	}

	private void mockRequestConfiguration() {
		when(relyingPartyDefinitions.getRelyingPartySetup())
				.thenReturn(ServiceSamlTestUtil.loadBaseClaimMergeTest());
		var cpDefinitions = ServiceSamlTestUtil.loadClaimsProviderDefinitions();
		when(relyingPartyDefinitions.getClaimsProviderDefinitions())
				.thenReturn(cpDefinitions);
		when(relyingPartyDefinitions.getClaimsProviderSetup())
				.thenReturn(ServiceSamlTestUtil.loadClaimsProviderSetup());
		when(relyingPartyDefinitions.getSsoGroupSetup())
				.thenReturn(ServiceSamlTestUtil.loadSsoGroups());
	}

	@Test
	void handleIncomingPostLogoutRequest() throws Exception {
		var request = prepareIncomingLogoutRequest();
		var encodedMessage = SamlUtil.encode(request);
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isOk());
		verify(relyingPartyService).handleLogoutRequest(any(), any(), any(), any(), any(), any());
	}

	@Test
	void handleIncomingSoapLogoutRequest() throws Exception {
		var request = prepareIncomingLogoutRequest();
		var context = OpenSamlUtil.createMessageContext(request, null, URL_TEMPLATE, null);
		var mockResponse = new MockHttpServletResponse();
		OpenSamlUtil.encodeSamlSoapMessage(mockResponse, context);
		this.mockMvc.perform(post(URL_TEMPLATE)
							.contentType(mockResponse.getContentType())
							.content(mockResponse.getContentAsByteArray()))
					.andExpect(status().isOk());
		verify(relyingPartyService).handleLogoutRequest(any(), any(), any(), any(), any(), any());
	}

	@Test
	void handleIncomingRedirectLogoutRequest() throws Exception {
		// signature is embedded in message as in POST (the normal redirect way is to use a separate query parameter)
		var request = prepareIncomingLogoutRequest();
		var encodedMessage = SamlIoUtil.encodeSamlRedirectData(request);
		this.mockMvc.perform(get(URL_TEMPLATE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage))
				.andExpect(status().isOk());
		verify(relyingPartyService).handleLogoutRequest(any(), any(), any(), any(), any(), any());
	}

	@Test
	void handleIncomingMessagesValidRedirectLogoutRequestTestSignature() throws Exception {
		handleIncomingMessagesValidRedirectLogoutRequest(false);
	}

	@Test
	void handleIncomingMessagesValidRedirectLogoutRequestTestDoubleSignature() throws Exception {
		handleIncomingMessagesValidRedirectLogoutRequest(true);
	}

	@Test
	void handleIncomingMessagesLogoutResponseTest() throws Exception {
		mockProperties();
		mockRequestConfiguration();
		var logoutResponse = prepareIncomingLogoutResponse();
		var encodedMessage = SamlUtil.encode(logoutResponse);
		this.mockMvc.perform(post(URL_TEMPLATE)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.param(SamlIoUtil.SAML_REQUEST_NAME, encodedMessage)
						.param(SamlIoUtil.SAML_RELAY_STATE, "relayStateId"))
				.andExpect(status().isOk());
	}

	@Test
	void federationMetadata() throws Exception {
		var content = "test";
		doReturn(content).when(federationMetadataService).getFederationMetadata(true, true);
		this.mockMvc
				.perform(get(ApiSupport.METADATA_URL))
				.andExpect(status().isOk())
				.andExpect(content().string(content));
	}

	private void handleIncomingMessagesValidRedirectLogoutRequest(boolean doubleSignature) throws Exception {
		var request = prepareIncomingLogoutRequest();
		var query = SamlTestBase.buildRedirectQueryString(request, doubleSignature);

		this.mockMvc.perform(get(new URI(URL_TEMPLATE + '?' + query)))
				.andExpect(status().isOk());
	}

	private LogoutRequest prepareIncomingLogoutRequest() {
		var logoutRequest = ServiceSamlTestUtil.loadLogoutRequest();
		return prepareValidIncomingRequest(logoutRequest);
	}

	private LogoutResponse prepareIncomingLogoutResponse() {
		var logoutResponse = ServiceSamlTestUtil.loadLogoutResponse();
		logoutResponse.setIssueInstant(Instant.now());
		return logoutResponse;
	}
}
