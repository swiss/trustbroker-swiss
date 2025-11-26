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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.or;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import jakarta.servlet.http.Cookie;
import org.apache.xml.security.utils.EncryptionConstants;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestResult;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.idm.dto.IdmProvisioningRequest;
import swiss.trustbroker.api.idm.dto.IdmProvisioningResult;
import swiss.trustbroker.api.idm.dto.IdmProvisioningStatus;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmProvisioningService;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.TrustBrokerConfiguration;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AccessRequest;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplications;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Encryption;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.HomeName;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.ProvisioningMode;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.SloResponse;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.dto.SloNotification;
import swiss.trustbroker.sso.dto.SloResponseParameters;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest
@ContextConfiguration(classes = {
		RelyingPartyService.class,
		TrustBrokerConfiguration.class,
		ApiSupport.class,
		SamlOutputService.class
})
@TestPropertySource(properties = "trustbroker.config.devmode.enabled=false")
class RelyingPartyServiceTest extends ServiceTestBase {

	private static final String COOKIE_NAME = "sessionCookie";

	private static final String COOKIE_NAME2 = "sessionCookie2";

	private static final String RELAY_STATE = "relayStateRp";

	private static final String REFERRER = "http://localhost/logout";

	private static final String SLO_URL = "http://localhost/slo";

	private static final String DESTINATION_URL = "http://localhost/acs";

	private static final String CLIENT_EXT_ID = "clientExtId";

	private static final String CP_ISSUER_ID = "cpIssuerId";

	private static final String HOME_NAME = "homeNameUrn";

	private static final String USER_NAME_ID = "userNameId";

	private static final String RP_ISSUER_ID = "rpIssuerId";

	private static final String ISSUER_ID = "selfIssuerId";

	private static final String CLIENT_ID = "clientId";

	private static final String PERIMETER_URL = "http://test.trustbroker.swiss";

	private static final String IDENTITY_QUERY = "IDENTITY";

	private static final String HINT_PARAMETER = "select_cp";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private IdmQueryService idmQueryService;

	@MockitoBean
	private IdmProvisioningService idmProvisioningService;

	@MockitoBean
	ScriptService scriptService;

	@MockitoBean
	private ProfileSelectionService profileSelectionService;

	@MockitoBean
	private SsoService ssoService;

	@MockitoBean
	private AuditService auditService;

	@MockitoBean
	private AccessRequestService accessRequestService;

	@MockitoBean
	private ResponseFactory responseFactory;

	@MockitoBean
	private StateCacheService stateCacheService;

	@MockitoBean
	private ArtifactCacheService artifactCacheService;

	@MockitoBean
	private UnknownUserPolicyService unknownUserPolicyService;

	@MockitoBean
	private QoaMappingService qoaService;

	@MockitoBean
	private ClaimsMapperService claimsMapperService;

	@Autowired
	private SamlOutputService outputService;

	@Autowired
	private RelyingPartyService relyingPartyService;

	private final ServiceSamlTestUtil samlTestUtil = new ServiceSamlTestUtil();

	@Autowired
	private ApiSupport apiSupport;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();

		new CoreAttributeInitializer().init();

		// testAddAllProperties needs this:
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_NAME);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_REALM);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.ISSUED_CLIENT_EXT_ID);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.AUTH_LEVEL);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.SSO_SESSION_ID);
	}

	@BeforeEach
	void setupMocks() {
		doReturn(CustomQoa.UNDEFINED_QOA).when(qoaService).getUnspecifiedAuthLevel();
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false", "false" })
	void handleLogoutRequest(boolean succeedLogout) throws UnsupportedEncodingException {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var logoutRequest = setupLogoutRequestMockData(request, succeedLogout, null);

		var signatureContext = SignatureContext.forPostBinding();
		relyingPartyService.handleLogoutRequest(outputService, logoutRequest, RELAY_STATE, request, response, signatureContext);

		// we always send a success response
		var expectedContent = new ArrayList<String>();
		expectedContent.add(RELAY_STATE);
		assertContent(response, StatusCode.SUCCESS, expectedContent);
	}

	@ParameterizedTest
	@MethodSource
	void handleLogoutRequestInvalidBinding(ArtifactBindingMode mode, SignatureContext signatureContext) {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var logoutRequest = setupLogoutRequestMockData(request, true, mode);

		var ex = assertThrows(RequestDeniedException.class, () -> relyingPartyService.handleLogoutRequest(outputService,
				logoutRequest, RELAY_STATE,	request, response, signatureContext));
		assertThat(ex.getInternalMessage(), containsString("does not support inbound binding"));
	}

	static Object[][] handleLogoutRequestInvalidBinding() {
		return new Object[][] {
				{ ArtifactBindingMode.NOT_SUPPORTED, SignatureContext.forArtifactBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forPostBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forRedirectBinding("") }
		};
	}

	@Test
	void testAddAllProperties() {
		var issuer = "SAMPLE-CP";
		var clientExtId = "1234";
		String homeName = "Test-Login";
		var nameId = "id/232";
		var authnValue = "authnValue";
		var ssoSessionIdValue = "test-sso-session-uuid";
		var cpResponse = givenCpResponse(issuer, clientExtId, homeName, nameId, false);
		var cp = ClaimsParty.builder().id(issuer).authLevel(authnValue).build();
		when(relyingPartySetupService.getClaimsProviderSetupByIssuerId(issuer, "")).thenReturn(cp);

		var initialPropertiesSize = cpResponse.getProperties().size();
		var stateDate = StateData.builder().id("test-sess-id").ssoSessionId(ssoSessionIdValue).build();
		TraceSupport.switchToConversation("conversationId");
		relyingPartyService.setProperties(cpResponse);
		RelyingPartyService.adjustSsoSessionIdProperty(stateDate, cpResponse);

		var properties = cpResponse.getProperties();
		var propertiesSize = properties.size();

		assertEquals(0, initialPropertiesSize);
		assertTrue(propertiesSize > initialPropertiesSize);
		assertEquals(6, propertiesSize);

		var attributeHomeRealm = cpResponse.getProperty(CoreAttributeName.HOME_REALM.getNamespaceUri());
		var attributeHomeName = cpResponse.getProperty(CoreAttributeName.HOME_NAME.getNamespaceUri());
		var attributeClientExtId = cpResponse.getProperty(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getNamespaceUri());
		var attributeAuthLevel = cpResponse.getProperty(CoreAttributeName.AUTH_LEVEL.getNamespaceUri());
		var attributeSsoSessionId = cpResponse.getProperty(CoreAttributeName.SSO_SESSION_ID.getNamespaceUri());

		assertEquals(attributeHomeName, homeName);
		assertEquals(attributeHomeRealm, issuer);
		assertEquals(attributeClientExtId, clientExtId);
		assertEquals(attributeAuthLevel, authnValue);
		assertEquals(attributeSsoSessionId, ssoSessionIdValue);
	}

	@Test
	void testFilterProperties() {
		var cpIssuerId = "SAMPLE-CP";
		var clientExtId = "1234";
		var homeName = "TEST-Login";
		var nameId = "id/232";
		var cpResponse = givenCpResponse(cpIssuerId, clientExtId, homeName, nameId, true);
		var attributesSelection = givenAttributesSelection();
		var rpIssuerId = "rp1";
		var relyingParty = RelyingParty.builder().id(rpIssuerId).propertiesSelection(attributesSelection).build();
		var referrer = "test";
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuerId, referrer)).thenReturn(relyingParty);

		relyingPartyService.filterPropertiesSelection(cpResponse, rpIssuerId, referrer);

		Map<Definition, List<String>> definitionListMap = cpResponse.getProperties();
		int propertiesSize = definitionListMap.size();

		assertEquals(1, propertiesSize);
		List<String> definitionNames = definitionListMap.keySet()
				.stream()
				.map(Definition::getName)
				.toList();
		assertTrue(definitionNames.contains(CoreAttributeName.HOME_REALM.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.HOME_NAME.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.EMAIL.getName()));
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void testPerformSilentAccessRequestDone(boolean fallback) {
		var spStateData = buildSpStateData();
		var rpIssuer = "rpIssuer1";
		spStateData.setIssuer(rpIssuer);
		var stateData = buildStateData("group1", "idx1", spStateData, Collections.emptySet(), null);
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty
				.builder()
				.id(rpIssuer)
				.accessRequest(AccessRequest.builder().authorizedApplications(AuthorizedApplications.builder().build()).build())
				.build();
		var idmLookup = IdmLookup.builder().build();
		var cpResponse = CpResponse.builder().rpIssuer("rp2").issuer(CP_ISSUER_ID).idmLookup(idmLookup).build();
		stateData.setCpResponse(cpResponse);
		var claimsParty = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		var url = fallback ? "https://localhost/initiate" : null;
		var httpData = AccessRequestHttpData.of(request);
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(rpIssuer, null);
		mockClaimsParty();

		var idmRefreshCallback = ArgumentCaptor.forClass(Runnable.class);
		doReturn(AccessRequestResult.of(false,  url))
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData),
						idmRefreshCallback.capture());

		// url is returned by AR
		assertThat(relyingPartyService.performAccessRequestWithDataRefreshIfRequired(
				request, relyingParty, claimsParty, stateData, null), is(url));
		assertThat(idmRefreshCallback.getValue(), is(not(nullValue())));
		idmRefreshCallback.getValue().run(); // would have been called by the real method

		// initial refresh and refresh after AR
		var relyingPartyConfig = ArgumentCaptor.forClass(RelyingPartyConfig.class);
		var cpResponseData = ArgumentCaptor.forClass(CpResponseData.class);
		var queryData = ArgumentCaptor.forClass(IdmRequests.class);
		var callback = ArgumentCaptor.forClass(IdmStatusPolicyCallback.class);
		verify(idmQueryService, times(1)).getAttributesAudited(relyingPartyConfig.capture(),
				cpResponseData.capture(), queryData.capture(), callback.capture());
		assertThat(relyingPartyConfig.getValue().getId(), is(rpIssuer));
		assertThat(cpResponseData.getValue().getIssuerId(), is(cpResponse.getIssuer()));
		assertThat(queryData.getValue().getQueryList(), hasSize(idmLookup.getQueries().size()));
		assertThat(callback.getValue(), instanceOf(DefaultIdmStatusPolicyCallback.class));
		if (fallback) {
			verify(stateCacheService).save(stateData, RelyingPartyService.class.getSimpleName());
		}
		else {
			verifyNoInteractions(stateCacheService);
		}
	}

	@ParameterizedTest
	@MethodSource
	void testPerformInteractiveAccessRequestRequired(boolean retainSession, String url) {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		var claimsParty = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(retainSession, url))
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData), any());

		assertThat(relyingPartyService.performAccessRequestWithDataRefreshIfRequired(
				request, relyingParty, claimsParty, stateData, null), is(url));
		if (retainSession) {
			verify(ssoService).establishImplicitSso(relyingParty, claimsParty, stateData);
			verifyNoInteractions(stateCacheService);
		}
		else {
			verifyNoInteractions(ssoService);
			verify(stateCacheService).save(stateData, RelyingPartyService.class.getSimpleName());
		}
		verifyNoInteractions(idmQueryService);
	}

	static Object[][] testPerformInteractiveAccessRequestRequired() {
		return new Object[][] {
				{ false, "https://localhost/redirect" },
				{ true, null }
		};
	}

	@ParameterizedTest
	@CsvSource(value = { "true,null", "false," + DESTINATION_URL }, nullValues = "null")
	void testSkipInteractiveAccessRequest(boolean intranet, String expected) {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		var claimsParty = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		when(trustBrokerProperties.getHrdHintTestParameter()).thenReturn(HINT_PARAMETER);
		request.addHeader(HINT_PARAMETER, "anycp");
		var network = new NetworkConfig();
		when(trustBrokerProperties.getNetwork()).thenReturn(network);
		request.addHeader(network.getNetworkHeader(),
				intranet ? network.getIntranetNetworkName() : network.getInternetNetworkName());
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(false, DESTINATION_URL))
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData), any());

		assertThat(relyingPartyService.performAccessRequestWithDataRefreshIfRequired(
				request, relyingParty, claimsParty, stateData, null), is(expected));
	}

	@Test
	void testNoAccessRequestRequired() {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		var claimsParty = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(false, null))
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData), any());

		assertThat(relyingPartyService.performAccessRequestWithDataRefreshIfRequired(
				request, relyingParty, claimsParty, stateData, null), is(nullValue()));

		verifyNoInteractions(stateCacheService);

		verifyNoInteractions(idmQueryService);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false,true,true,false,false",
			"true,false,false,true,true",
			"null,true,false,true,false"
	}, nullValues = "null")
	void testSignResponse(Boolean requireSignedResponse, boolean signSuccessResponse, boolean signFailureResponse,
			boolean expectedSignSuccessResponse, boolean expectedSignFailureResponse) {
		var secPol = SecurityPolicies.builder().requireSignedResponse(requireSignedResponse).build();
		var relyingParty = RelyingParty.builder().id("rp1").securityPolicies(secPol).build();
		var secChecks = new SecurityChecks();
		secChecks.setDoSignSuccessResponse(signSuccessResponse);
		secChecks.setDoSignFailureResponse(signFailureResponse);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();

		assertThat(relyingPartyService.signFailureResponse(relyingParty), is(expectedSignFailureResponse));
		assertThat(relyingPartyService.signSuccessResponse(relyingParty), is(expectedSignSuccessResponse));
	}

	@Test
	void testSetAssertionNoEncryption() {
		var authnResponse = givenResponseWithoutAssertion();
		var assertion = givenAssertion();
		var relyingParty = givenMockedRelyingParty(false);
		givenMockedOidcProperties(PERIMETER_URL);

		relyingPartyService.addAssertionToResponse(authnResponse, assertion, relyingParty);
		assertNotNull(authnResponse.getAssertions());
		assertNotNull(authnResponse.getAssertions().get(0));
		assertEquals(1, authnResponse.getAssertions().size());
	}

	@Test
	void testAddAssertionToResponseEncryptionWithDefaults() {
		Response authnResponse = givenResponseWithoutAssertion();
		Assertion assertion = givenAssertion();
		RelyingParty relyingParty = givenRelyingPartyWithEncryptionCred();
		givenMockedOidcProperties(PERIMETER_URL);

		relyingPartyService.addAssertionToResponse(authnResponse, assertion, relyingParty);
		expectedResult(authnResponse, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
				EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
	}

	@Test
	void testAddAssertionToResponseEncryption() {
		Response authnResponse = givenResponseWithoutAssertion();
		Assertion assertion = givenAssertion();
		String dataEncryAlg = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192;
		String keyEncryAlg = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP_11;
		givenMockedOidcProperties(PERIMETER_URL);
		RelyingParty relyingParty = givenRelyingPartyWithEncryption(dataEncryAlg, keyEncryAlg);

		relyingPartyService.addAssertionToResponse(authnResponse, assertion, relyingParty);
		expectedResult(authnResponse, dataEncryAlg, keyEncryAlg);
	}

	@Test
	void sendAbortedSamlResponseToRpWithConfirmation() {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setStatusCode("responderCode");
		cpResponse.setFlowPolicy(Flow.builder().id("denied").appContinue(true).build());
		var mockHttpRequest = new MockHttpServletRequest();
		var requestId = "000102030405060708090a0b0c0d0e0f";
		mockHttpRequest.addHeader("X-Request-Id", requestId);
		TraceSupport.setMdcTraceContext(mockHttpRequest);
		var traceId = TraceSupport.getOwnTraceParent();
		assertThat(traceId, startsWith(requestId));
		assertThat(traceId.length(), is(49));
		var stateData = givenState(RP_ISSUER_ID);
		stateData.setCpResponse(cpResponse);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var mockHttpResponse = new MockHttpServletResponse();
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, stateData, null,
				mockHttpRequest, mockHttpResponse);
		assertThat(result, is("/app/failure/denied/" + traceId + "/" + ApiSupport.encodeUrlParameter("sessionId") + "/continue"));
	}

	@Test
	void sendAbortedSamlResponseToRp() throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		givenMockedRelyingParty(false);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setStatusCode(StatusCode.RESPONDER);
		cpResponse.setRpDestination(DESTINATION_URL);
		var nestedCode = "statusNestedCodeId";
		var statusMessage = "lorem ipsum dolor";
		cpResponse.setStatusNestedCode(nestedCode);
		cpResponse.setStatusMessage(statusMessage);
		var stateData = givenState(RP_ISSUER_ID);
		stateData.setCpResponse(cpResponse);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		mockSecurityChecks();
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, stateData, null,
				mockHttpRequest, mockHttpResponse);
		assertThat(result, is(nullValue()));
		var response = samlTestUtil.extractSamlPostResponse(mockHttpResponse.getContentAsString());
		assertThat(response.getStatus().getStatusCode().getValue(), is(StatusCode.RESPONDER));
		assertThat(response.getStatus().getStatusCode().getStatusCode().getValue(), is(nestedCode));
		assertThat(response.getStatus().getStatusMessage().getValue(), is(statusMessage));
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendSuccessSamlResponseToRp(boolean useArtifactBinding) throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		givenMockedOidcProperties(PERIMETER_URL);
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		var cpResponse = givenCpResponse();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		stateData.setCpResponse(cpResponse);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockSecurityChecks();
		mockClaimsParty();
		var arResult = AccessRequestResult.of(false, null);
		var httpData = AccessRequestHttpData.of(mockHttpRequest);
		doReturn(arResult)
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData), any());

		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doInitialProfileSelection(
				ProfileSelectionData.builder().exchangeId(RELAY_STATE).oidcClientId(CLIENT_ID).build(),
				relyingParty, cpResponse, stateData);
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, stateData, null,
				mockHttpRequest, mockHttpResponse);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendFailedSamlResponseToRp(boolean useArtifactBinding) throws Exception {
		var responseData = givenFailedResponseData();
		givenMockedRelyingParty(useArtifactBinding);
		var cpResponse = givenCpResponse();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.setCpResponse(cpResponse);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockSecurityChecks();
		var result = relyingPartyService.sendFailedSamlResponseToRp(outputService, responseData, mockHttpRequest,
				mockHttpResponse, stateData);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.AUTHN_FAILED, mockHttpResponse);
	}

	@ParameterizedTest
	@MethodSource
	void sendFailedSamlResponseToRpAborted(String statusCode, String statusMessage, String nestedStatusCode, Flow flow,
			String expectedRedirectUrl) throws Exception {
		var responseData = givenFailedResponseData();
		givenMockedRelyingParty(false);
		var cpResponse = givenCpResponse();
		cpResponse.abort(statusCode, statusMessage, nestedStatusCode, flow);
		var stateData = givenState(RP_ISSUER_ID);
		stateData.setCpResponse(cpResponse);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockSecurityChecks();
		var result = relyingPartyService.sendFailedSamlResponseToRp(outputService, responseData, mockHttpRequest,
				mockHttpResponse, stateData);
		if (expectedRedirectUrl == null) {
			assertThat(result, is(nullValue()));
			validateResponse(false, statusCode, mockHttpResponse);
		}
		else {
			assertNotNull(result);
			assertTrue(result.matches(expectedRedirectUrl), result + " does not match " + expectedRedirectUrl);
		}
	}

	static Object[][] sendFailedSamlResponseToRpAborted() {
		var redirectUrl = "https://localhost/app";
		return new Object[][] {
				{ StatusCode.AUTHN_FAILED, null, null, null, null },
				{ StatusCode.RESPONDER, "Failed", "Invalid",
						Flow.builder().id("FlowId").reLogin(true).build(),
						ApiSupport.ERROR_PAGE_URL + "/flowid/[^.]+[.][^.]+/" + Flow.RELOGIN_FLAG },
				{ StatusCode.RESPONDER, "Failed", "Invalid",
						Flow.builder().id("TEST").appContinue(true).build(),
						ApiSupport.ERROR_PAGE_URL + "/test/[^.]+[.][^.]+/" + Flow.CONTINUE_FLAG },
				{ StatusCode.RESPONDER, "Failed", "Invalid",
						Flow.builder().id("Sup").supportInfo(true).build(),
						ApiSupport.ERROR_PAGE_URL + "/sup/[^.]+[.][^.]+/" + Flow.SUPPORT_FLAG },
				{ StatusCode.RESPONDER, "App blocked", "Blocked",
						Flow.builder().id("Any").appRedirectUrl(redirectUrl).build(), redirectUrl }
		};
	}

	@ParameterizedTest
	@CsvSource(value = {
			// ArtifactBinding is independent of the IDM flags
			"false,true,true,true,true",
			"false,true,true,false,false",
			"true,false,false,false,true",
			"true,true,false,false,false"
	})
	void sendAuthnResponseToRpFromState(boolean useArtifactBinding, boolean sameRp, boolean ssoEnabled, boolean forceIdmFetch,
			boolean expectIdmRefresh) throws Exception {
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		relyingParty.setSso(Sso.builder().enabled(ssoEnabled).forceIdmRefresh(forceIdmFetch).build());
		givenMockedOidcProperties(PERIMETER_URL);
		mockSecurityChecks();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setRelayState(RELAY_STATE);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var ssoStateData = givenState(RP_ISSUER_ID);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		if (sameRp) {
			cpResponse.setRpIssuer(RP_ISSUER_ID);
		}
		cpResponse.setRpDestination(DESTINATION_URL);
		ssoStateData.setCpResponse(cpResponse);
		ssoStateData.setSelectedProfileExtId(PROFILE_ID);
		var profileSelectionData = ProfileSelectionData.builder()
				.oidcClientId(CLIENT_ID)
				.exchangeId(RELAY_STATE)
				.build();
		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doSsoProfileSelection(
				profileSelectionData, relyingParty, cpResponse, stateData);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockClaimsParty();
		var result = relyingPartyService.sendAuthnResponseToRpFromState(outputService, mockHttpRequest, mockHttpResponse,
				ssoStateData, stateData);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
		verify(ssoService).completeDeviceInfoPreservingStateForSso(ssoStateData, stateData, relyingParty);
		if (expectIdmRefresh) {
			var relyingPartyConfig = ArgumentCaptor.forClass(RelyingPartyConfig.class);
			var cpResponseData = ArgumentCaptor.forClass(CpResponseData.class);
			var queryData = ArgumentCaptor.forClass(IdmRequests.class);
			var callback = ArgumentCaptor.forClass(IdmStatusPolicyCallback.class);
			verify(idmQueryService, times(1)).getAttributes(relyingPartyConfig.capture(),
					cpResponseData.capture(), queryData.capture(), callback.capture());
			assertThat(relyingPartyConfig.getValue().getId(), is(RP_ISSUER_ID));
			assertThat(cpResponseData.getValue().getIssuerId(), is(CP_ISSUER_ID));
			assertThat(queryData.getValue().getQueryList(), hasSize(3));
			assertThat(queryData.getValue().getQueryList().get(0).getName(), is(IDENTITY_QUERY));
			assertThat(callback.getValue(), instanceOf(DefaultIdmStatusPolicyCallback.class));
		}
		else {
			verifyNoInteractions(idmQueryService);
		}
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendResponseWithSamlResponseFromCp(boolean useArtifactBinding) throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		givenMockedOidcProperties(PERIMETER_URL);
		mockSecurityChecks();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var cpResponse = givenCpResponse();
		var claimsParty = mockClaimsParty();
		mockProvisioning(claimsParty, cpResponse);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		var arResult = AccessRequestResult.of(false, null);
		var httpData = AccessRequestHttpData.of(mockHttpRequest);
		doReturn(arResult)
				.when(accessRequestService).performAccessRequestIfRequired(eq(httpData), eq(relyingParty), eq(stateData), any());
		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doInitialProfileSelection(
				ProfileSelectionData.builder().exchangeId(RELAY_STATE).oidcClientId(CLIENT_ID).build(),
				relyingParty, cpResponse, stateData);

		var result = relyingPartyService.sendResponseWithSamlResponseFromCp(outputService, responseData, cpResponse,
				mockHttpRequest, mockHttpResponse);

		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
	}

	private void mockProvisioning(ClaimsParty claimsParty, CpResponse cpResponse) {
		var name = claimsParty.getAttributesSelection().getDefinitions().get(0);
		assertTrue(name.isProvisioningAttribute());
		var email = claimsParty.getAttributesSelection().getDefinitions().get(1);
		assertTrue(email.isProvisioningAttribute());
		assertTrue(email.isProvisioningIdAttribute());
		var homeName = claimsParty.getAttributesSelection().getDefinitions().get(2);
		assertFalse(homeName.isProvisioningAttribute());
		var originalAttributes = Map.of(name, List.of("name"), email, List.of("email"), homeName, List.of("homename"));
		var provisionedAttributes = List.of(name, email);
		var qoa = 10;
		cpResponse.setOriginalAttributes(originalAttributes);
		Map<Object, Object> additionalAttributes = Map.of("Key1", 100);
		cpResponse.setAdditionalIdmData(additionalAttributes);
		var provRequest = IdmProvisioningRequest.builder()
												.identifyingClaim(provisionedAttributes.get(1)) // from CP AttributeSelection
												.homeName(HOME_NAME)
												.cpSubjectNameId(USER_NAME_ID)
												.idmAttributes(Collections.emptyMap())
												.cpAttributes(originalAttributes)
												.provisioningAttributes(provisionedAttributes)
												.cpAuthenticationQoa(qoa)
												.modes(Collections.emptyList())
												.additionalData(additionalAttributes)
												.queriedStores(Collections.emptySet())
												.build();
		var provResult = IdmProvisioningResult.builder().status(IdmProvisioningStatus.CREATED).build();
		doReturn(qoa).when(qoaService).getMaxQoaOrder(cpResponse.getContextClasses(), claimsParty.getQoaConfig());
		doReturn(provResult).when(idmProvisioningService).createOrUpdateUser(provRequest);
	}

	@Test
	void reloadIdmData() {
		var relyingParty = givenMockedRelyingParty(false);
		var stateData = givenStateDataWithCpResponse();
		var value = "first1";
		var idmResult = IdmResult.builder().userDetails(
				Map.of(Definition.ofName(CoreAttributeName.FIRST_NAME),
				List.of(value))).build();
		doReturn(Optional.of(idmResult)).when(idmQueryService).getAttributesAudited(any(), any(), any(), any());
		mockClaimsParty();
		relyingPartyService.reloadIdmData(relyingParty, stateData);

		assertThat(stateData.getCpResponse().getUserDetail(CoreAttributeName.FIRST_NAME.getName()), is(value));
	}

	private StateData givenStateDataWithCpResponse() {
		var stateData = givenState(RP_ISSUER_ID);
		var cpResponse = givenCpResponse(CP_ISSUER_ID,  null, null, null, false);
		stateData.setCpResponse(cpResponse);
		stateData.setIssuer(CP_ISSUER_ID);
		return stateData;
	}

	private void validateResponse(boolean useArtifactBinding, String statusCode, MockHttpServletResponse mockHttpResponse)
			throws UnsupportedEncodingException {
		if (useArtifactBinding) {
			var response = samlTestUtil.extractSamlArtifactValue(mockHttpResponse.getContentAsString());
			assertThat(response, is(not(nullValue())));
			var sourceId = OpenSamlUtil.extractSourceIdFromArtifactId(response);
			assertThat(sourceId, is(OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(ISSUER_ID)));
		}
		else {
			var response = samlTestUtil.extractSamlPostResponse(mockHttpResponse.getContentAsString());
			assertThat(response.getStatus().getStatusCode().getValue(), is(statusCode));
		}
	}

	private void mockArtifactBinding() {
		var samlProperties = new SamlProperties();
		var ar = new ArtifactResolution();
		ar.setIndex(0);
		ar.setServiceUrl("http://localhost:1/arp");
		samlProperties.setArtifactResolution(ar);
		doReturn(samlProperties).when(trustBrokerProperties).getSaml();
		doReturn(ISSUER_ID).when(trustBrokerProperties).getIssuer();
		var artifactMap = OpenSamlUtil.createArtifactMap();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();
	}

	@ParameterizedTest
	@MethodSource
	void useArtifactBinding(ArtifactBindingMode mode, SamlBinding binding, Boolean rpSessionInit,
			Boolean cpSessionInit, boolean result) {
		var relyingParty = givenMockedRelyingParty(false);
		if (mode != null) {
			relyingParty.setSaml(
					Saml.builder()
							.artifactBinding(ArtifactBinding.builder().outboundMode(mode).build())
							.build());
		}
		var stateData = (rpSessionInit != null || cpSessionInit != null) ? givenState(RP_ISSUER_ID) : null;
		if (stateData != null) {
			stateData.getSpStateData().setRequestBinding(
					Boolean.TRUE.equals(rpSessionInit) ? SamlBinding.ARTIFACT : SamlBinding.POST);
			stateData.setRequestBinding(Boolean.TRUE.equals(cpSessionInit) ? SamlBinding.ARTIFACT : SamlBinding.POST);
		}
		assertThat(RelyingPartyService.useArtifactBinding(relyingParty, stateData, binding), is(result));
	}

	static Object[][] useArtifactBinding() {
		return new Object[][] {
				{ null, null, null, null, false },
				{ null, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, null, null, null, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, false },
				{ ArtifactBindingMode.REQUIRED, null, null, null, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.POST, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.REDIRECT, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, null, null, null, false },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.FALSE, Boolean.FALSE, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.FALSE, Boolean.FALSE, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.REDIRECT, null, null, false }
		};
	}

	@Test
	void assertionEncryptionReqTest() {
		String rpid = "rpid";
		OidcProperties oidcConfig = givenMockedOidcProperties(PERIMETER_URL);

		assertFalse(relyingPartyService.assertionEncryptionReq(null, false, rpid));
		assertTrue(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), false, rpid));
		assertFalse(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), true, rpid));

		oidcConfig.setSamlEncrypt(true);
		assertTrue(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), true, rpid));
	}

	@Test
	void validateRpQoaRequirementTest() {
		var cpResponse = givenCpResponse();
		var state = givenStateDataWithCpResponse();

		Map<String, Integer> globalMapping = Map.of(
				"qoa:10", 10,
				"qoa:20", 20,
				"qoa:password", 20,
				"qoa:30", 30,
				"qoa:50", 50
		);
		var rpQoa = Qoa.builder().enforce(true).comparison(QoaComparison.EXACT).mapOutbound(true).classes(
				List.of(AcClass.builder().contextClass("qoa:20").build(),
						AcClass.builder().contextClass("qoa:30").build(),
						AcClass.builder().contextClass("qoa:50").build())

		).build();
		var relyingParty = RelyingParty.builder()
									   .id(RP_ISSUER_ID)
									   .qoa(rpQoa)
									   .build();
		var cpQoaConf = Qoa.builder().enforce(true).comparison(QoaComparison.MINIMUM).mapOutbound(true).classes(
				List.of(AcClass.builder().contextClass("qoa:30").build(),
						AcClass.builder().contextClass("qoa:password").order(40).downgradeToMaximumRequested(true).build(),
						AcClass.builder().contextClass("qoa:400").order(41).downgradeToMaximumRequested(true).build(),
						AcClass.builder().contextClass("qoa:50").build())

		).build();
		var claimsParty = ClaimsParty.builder()
									 .id(CP_ISSUER_ID)
									 .qoa(cpQoaConf)
									 .build();

		doReturn(globalMapping).when(trustBrokerProperties).getQoaMap();
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID, null);
		doReturn(Optional.of(claimsParty)).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(CP_ISSUER_ID);
		doReturn(new QoaConfig(rpQoa, "rpIssuerId"))
				.when(qoaService).getQoaConfiguration(state.getSpStateData(), relyingParty);

		// Rp request Qoas
		state.getSpStateData().setComparisonType(QoaComparison.EXACT);
		state.getSpStateData().setContextClasses(List.of("qoa:20", "qoa:30", "qoa:50"));

		cpResponse.setContextClasses(List.of("qoa:30"));
		doReturn(List.of("qoa:30")).when(qoaService).mapResponseQoasToOutbound(any(), any(), any(), any(), any());
		assertDoesNotThrow(() -> relyingPartyService.validateRpQoaRequirement(state, cpResponse));

		cpResponse.setContextClasses(List.of("qoa:password"));
		doReturn(List.of("qoa:20")).when(qoaService).mapResponseQoasToOutbound(any(), any(), any(), any(), any());
		assertDoesNotThrow(() -> relyingPartyService.validateRpQoaRequirement(state, cpResponse));

		cpResponse.setContextClasses(List.of("qoa:400"));
		doReturn(List.of("qoa:20")).when(qoaService).mapResponseQoasToOutbound(any(), any(), any(), any(), any());
		assertDoesNotThrow(() -> relyingPartyService.validateRpQoaRequirement(state, cpResponse));

		cpResponse.setContextClasses(List.of("qoa:10"));
		doReturn(List.of("qoa:10")).when(qoaService).mapResponseQoasToOutbound(any(), any(), any(), any(), any());
		var ex = assertThrows(RequestDeniedException.class, () -> relyingPartyService.validateRpQoaRequirement(state, cpResponse));
		assertThat(ex.getInternalMessage(), CoreMatchers.containsString(CP_ISSUER_ID));
		assertThat(ex.getInternalMessage(), CoreMatchers.containsString(RP_ISSUER_ID));
	}

	private CpResponse givenCpResponse() {
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setRpDestination(DESTINATION_URL);
		cpResponse.setContextClasses(List.of("qoa10"));
		return cpResponse;
	}

	private ResponseData<Response> givenFailedResponseData() {
		var authnResponse = givenResponseWithoutAssertion();
		var status = SamlFactory.createResponseStatus(StatusCode.AUTHN_FAILED);
		authnResponse.setStatus(status);
		givenMockedOidcProperties(PERIMETER_URL);
		return ResponseData.of(authnResponse, RELAY_STATE, null);
	}

	private void mockSecurityChecks() {
		var secChecks = new SecurityChecks();
		secChecks.setDoSignSuccessResponse(false);
		secChecks.setDoSignFailureResponse(false);
		secChecks.setDoSignAssertions(false);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();
	}

	private OidcProperties givenMockedOidcProperties(String perimeterUrl) {
		OidcProperties oidcConfig = new OidcProperties();
		oidcConfig.setSamlEncrypt(false);
		oidcConfig.setPerimeterUrl(perimeterUrl);
		when(trustBrokerProperties.getOidc()).thenReturn(oidcConfig);
		return oidcConfig;
	}

	private static void expectedResult(Response authnResponse, String dataEncryAlg, String keyEncryAlg) {
		assertEquals(0, authnResponse.getAssertions().size());
		List<EncryptedAssertion> encryptedAssertions = authnResponse.getEncryptedAssertions();
		assertNotNull(encryptedAssertions);
		assertNotNull(encryptedAssertions.get(0));
		assertEquals(1, encryptedAssertions.size());
		assertNotNull(encryptedAssertions.get(0).getEncryptedData().getEncryptionMethod());
		assertEquals(dataEncryAlg, encryptedAssertions.get(0).getEncryptedData().getEncryptionMethod().getAlgorithm());
		assertNotNull(encryptedAssertions.get(0).getEncryptedKeys().get(0).getEncryptionMethod());
		assertEquals(keyEncryAlg, encryptedAssertions.get(0).getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm());
	}

	private RelyingParty givenRelyingPartyWithEncryption(String dataEncryAlg, String keyEncryAlg) {
		var encryption = Encryption.builder()
				.dataEncryptionAlgorithm(dataEncryAlg)
				.keyEncryptionAlgorithm(keyEncryAlg)
				.build();
		var saml = Saml.builder()
				.encryption(encryption)
				.build();
		return RelyingParty.builder()
				.rpEncryptionTrustCredential(SamlTestBase.dummyCredential())
				.id("Testid")
				.saml(saml)
				.build();
	}

	private RelyingParty givenMockedRelyingParty(boolean useArtifactBinding) {
		var relyingParty = RelyingParty.builder()
				.id(RP_ISSUER_ID)
				.build();
		if (useArtifactBinding) {
			relyingParty.setSaml(Saml.builder()
					.artifactBinding(ArtifactBinding.builder().outboundMode(ArtifactBindingMode.REQUIRED).build())
					.build());
			mockArtifactBinding();
		}
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID, null);
		return relyingParty;
	}

	private static RelyingParty givenRelyingPartyWithEncryptionCred() {
		return RelyingParty.builder()
				.rpEncryptionTrustCredential(SamlTestBase.dummyCredential())
				.id(RP_ISSUER_ID)
				.build();
	}

	private ClaimsParty mockClaimsParty() {
		var name = Definition.ofNames(CoreAttributeName.NAME);
		name.setProvision(Boolean.TRUE.toString());
		var email = Definition.ofNames(CoreAttributeName.EMAIL);
		email.setProvision(Boolean.TRUE.toString());
		email.setProvisioningId(true);

		var claimsParty = ClaimsParty.builder()
				.id(CP_ISSUER_ID)
				.provision(ProvisioningMode.TRUE)
				.homeName(HomeName.builder().value(HOME_NAME).build())
				.attributesSelection(
						AttributesSelection.builder()
								.definitions(List.of(name, email, Definition.ofNames(CoreAttributeName.HOME_NAME)))
								.build()
				)
				.qoa(Qoa.builder().build())
				.build();
		doReturn(claimsParty).when(relyingPartySetupService)
							 .getClaimsProviderSetupByIssuerId(eq(CP_ISSUER_ID), or(eq(null), eq("")));
		doReturn(Optional.of(claimsParty)).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(CP_ISSUER_ID);
		return claimsParty;
	}

	private Assertion givenAssertion() {
		Assertion assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		// ID
		assertion.setID(UUID.randomUUID().toString());
		// issuer
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue("TEST_AUDIENCE");

		return assertion;
	}

	private Response givenResponseWithoutAssertion() {
		Response response = SamlFactory.createResponse(Response.class, trustBrokerProperties.getIssuer());
		response.setDestination("http://any.trustbroker.swiss");
		return response;
	}

	private AttributesSelection givenAttributesSelection() {
		List<Definition> definitions = new ArrayList<>();
		definitions.add(new Definition(CoreAttributeName.EMAIL));
		definitions.add(new Definition(CoreAttributeName.HOME_REALM));

		AttributesSelection attributesSelection = new AttributesSelection();
		attributesSelection.setDefinitions(definitions);

		return attributesSelection;
	}

	private StateData givenState(String rpIssuerId) {
		var spStateData = StateData.builder().id("spSessionId").issuer(rpIssuerId).build();
		return StateData.builder().id("sessionId").spStateData(spStateData).build();
	}

	private void assertContent(MockHttpServletResponse response, String expectedStatus, List<String> expectedContent)
			throws UnsupportedEncodingException {
		// the result is an HTML page with a form including the encoded SamlResponse and the RelayState
		// send form back to referrer (which is XML encoded)
		// the checks simple, they only have to handle what we produce, not generic HTML
		var encodedSloUrl = SLO_URL.replace(":", "&#x3a;").replace("/", "&#x2f;");
		var responseContent = response.getContentAsString();
		assertThat(responseContent, containsString("action=\"" + encodedSloUrl + '"'));
		for (var content : expectedContent) {
			assertThat(responseContent, containsString(content));
		}
		// response and relay state are encoded in a form fields
		var samlResponseField = "name=\"" + SamlIoUtil.SAML_RESPONSE_NAME + '"';
		assertThat(responseContent, containsString(samlResponseField));
		assertThat(responseContent, containsString("value=\"" + RELAY_STATE + '"'));
		var encodedResponse = responseContent.replace("\n", "").replaceAll("^.*" + samlResponseField + " value=\"",
				"").replaceAll("\".*$", "");
		var request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setParameter(SamlIoUtil.SAML_RESPONSE_NAME, encodedResponse);
		var messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
		var logoutResponse = (LogoutResponse) messageContext.getMessage();
		assertThat(logoutResponse.getDestination(), is(SLO_URL));
		assertThat(logoutResponse.getStatus().getStatusCode().getValue(), is(expectedStatus));

		// cookie returned by mock must be set on response
		assertThat(response.getCookies(), is(not(nullValue())));
		assertThat(response.getCookies().length, is(1));
		assertThat(response.getCookies()[0].getName(), is(COOKIE_NAME));
		assertThat(response.getCookies()[0].getValue(), is(""));
	}

	private LogoutRequest setupLogoutRequestMockData(
			MockHttpServletRequest request, boolean statePresent, ArtifactBindingMode mode) {
		// matching RPs
		var issuer = "myIssuer";
		var ssoGroup = "mySsoGroup";
		var ssoGroup2 = "mySsoGroup2";
		var sso = buildSso(ssoGroup);
		var sso2 = buildSso(ssoGroup2);
		// for invalid binding test:
		var artifactBinding = ArtifactBinding.builder().inboundMode(mode).build();
		var saml = Saml.builder().artifactBinding(artifactBinding).build();
		var secPol = SecurityPolicies.builder().requireSignedLogoutRequest(false).requireSignedResponse(false).build();
		var relyingParties = new ArrayList<RelyingParty>();
		var relyingPartySso = RelyingParty.builder().id("X-ENTERPRISE").sso(sso).saml(saml).securityPolicies(secPol).build();
		relyingParties.add(relyingPartySso);
		relyingParties.add(RelyingParty.builder().id("X-ENTERPRISE").sso(sso).saml(saml).securityPolicies(secPol).build());
		// simulate corner case if two SSO groups are matching
		var relyingPartySso2 = RelyingParty.builder().id("X-R").sso(sso2).saml(saml).securityPolicies(secPol).build();
		relyingParties.add(relyingPartySso2);
		doReturn(relyingParties).when(ssoService).getRelyingPartiesForSamlSlo(issuer, REFERRER);
		doReturn(SLO_URL).when(ssoService).computeSamlSingleLogoutUrl(eq(REFERRER), any());

		// states and cookies
		var sessionIndex = "mySessionIndex";
		var ssoSessionId = "mySsoSessionId";
		var spStateData = buildSpStateData();
		var ssoParticipants = Set.of(new SsoSessionParticipant(issuer, "cpIssuer", "acsUrl", null, null));
		var stateData = statePresent ? buildStateData(ssoGroup, sessionIndex, spStateData, ssoParticipants, ssoSessionId) : null;
		var stateData2 = statePresent ? buildStateData(ssoGroup2, sessionIndex, spStateData, ssoParticipants, null) : null;
		var cookie = new Cookie(COOKIE_NAME, "value");
		var expCookie = new Cookie(COOKIE_NAME, "");
		var cookie2 = new Cookie(COOKIE_NAME2, "value");
		doAnswer(invocation -> {
			setCookiesToExpire(invocation.getArguments(), List.of(expCookie));
			return Optional.ofNullable(stateData);
		}).when(ssoService).logoutRelyingParty(issuer,
				List.of(sessionIndex), relyingPartySso, new Cookie[] { cookie, cookie2 },
				SsoService.SloState.builder().build());
		// validation and logout
		doReturn(Optional.ofNullable(stateData2)).when(ssoService).logoutRelyingParty(issuer,
				List.of(sessionIndex), relyingPartySso2, new Cookie[] { cookie, cookie2 },
				SsoService.SloState.builder().build());
		var logoutRequest = SamlFactory.createRequest(LogoutRequest.class, issuer);
		var sessionIndexObj = OpenSamlUtil.buildSamlObject(SessionIndex.class);
		sessionIndexObj.setValue(sessionIndex);
		logoutRequest.getSessionIndexes().add(sessionIndexObj);
		var nameId = SamlFactory.createNameId("name1@localhost", NameIDType.EMAIL, null);
		logoutRequest.setNameID(nameId);

		var notification = new SloNotification(new SloResponse());
		notification.setEncodedUrl(SLO_URL);
		doReturn(new SecurityChecks()).when(trustBrokerProperties).getSecurity();

		doReturn(new SloResponseParameters(Collections.emptyMap(), false))
				.when(ssoService).buildSloResponseParameters(relyingPartySso, REFERRER, Collections.emptySet(), nameId, null, null);

		request.setCookies(cookie, cookie2);
		request.addHeader(HttpHeaders.REFERER, REFERRER);
		return logoutRequest;
	}

	// allow position of argument SloState to change
	private static void setCookiesToExpire(Object[] arguments, List<Cookie> cookies) {
		if (arguments != null) {
			for (var argument : arguments) {
				if (argument instanceof SsoService.SloState sloState)
					sloState.setCookiesToExpire(cookies);
			}
		}
	}

	private static StateData buildSpStateData() {
		return StateData.builder().id("spSessionId").assertionConsumerServiceUrl("http://localhost/consumer").build();
	}

	private static Sso buildSso(String ssoGroup) {
		return Sso.builder().enabled(true).groupName(ssoGroup).sloUrl("http://localhost/logout").build();
	}

	private static StateData buildStateData(String ssoGroup, String sessionIndex, StateData spStateData,
			Set<SsoSessionParticipant> ssoParticipants, String ssoSessionId) {
		return StateData.builder()
				.id("mySessionId")
				.sessionIndex(sessionIndex)
				.spStateData(spStateData)
				.ssoState(SsoState.builder().ssoGroupName(ssoGroup).ssoParticipants(ssoParticipants).build())
				.ssoSessionId(ssoSessionId)
				.build();
	}

}
