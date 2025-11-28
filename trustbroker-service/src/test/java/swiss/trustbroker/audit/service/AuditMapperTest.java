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

package swiss.trustbroker.audit.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static swiss.trustbroker.common.saml.util.CoreAttributeName.CLAIMS_NAME;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.dto.OidcAuditData;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.sessioncache.dto.AccessRequestSessionState;
import swiss.trustbroker.sessioncache.dto.AccessRequestState;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.WebSupport;

@ExtendWith(MockitoExtension.class)
class AuditMapperTest {

	public static final String TEST_ISSUER = "myIssuer";

	public static final String TEST_DESTINATION = "myDestination";

	public static final String TEST_REQUEST_ID = "myId";

	public static final String TEST_NAME = "myName";

	public static final String TEST_CLAIMS_NAME = "myClaimsName";

	public static final String TEST_CLAIMS_NAME2 = "myClaimsName2";

	public static final String TEST_SESSION_ID = "mySessionId";

	public static final String TEST_FIRST_NAME = "myFirstName";

	public static final String TEST_EMAIL = "test@trustbroker.swiss";

	@Mock
	private TrustBrokerProperties trustBrokerProperties;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
		new CoreAttributeInitializer().init();
	}

	@Test
	void testMapFromNull() {
		// validate that there are no NPEs
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom((CpResponse) null)
				.mapFrom((AuthnRequest) null)
				.mapFrom((HttpServletRequest) null)
				.mapFrom((StateData) null)
				.mapFrom(new StateData()) // no CpResponse DTO
				.mapFromDefinitions(null, AuditDto.AttributeSource.CP_RESPONSE)
				.mapFromDefinitions(Collections.emptyMap(), AuditDto.AttributeSource.SAML_RESPONSE)
				.mapFrom((AccessRequestSessionState) null)
				.build();
		assertThat(auditDto.getEventType(), nullValue());
	}

	@Test
	void testMapFromCpResponseDtoInbound() {
		var cpResponse = new CpResponse();
		cpResponse.setIssuer(TEST_ISSUER);
		cpResponse.setDestination(TEST_DESTINATION);
		cpResponse.setAttribute(CLAIMS_NAME.getNamespaceUri(), TEST_CLAIMS_NAME);
		cpResponse.setAttribute(CLAIMS_NAME.getName(), TEST_CLAIMS_NAME2);
		cpResponse.setAttribute(CoreAttributeName.EMAIL.getNamespaceUri(), TEST_EMAIL);
		cpResponse.setAttribute(CoreAttributeName.FIRST_NAME.getName(), TEST_FIRST_NAME);
		cpResponse.setAttribute(CoreAttributeName.HOME_REALM.getName(), "dropped");
		cpResponse.setOriginalAttributes(new HashMap<>(cpResponse.getAttributes())); // simulate saving incoming CP attrs
		cpResponse.removeAttributes(CoreAttributeName.HOME_REALM.getName()); // simulate CP attr filtering
		// result not mapped inbound:
		cpResponse.setResult(Definition.ofName(CoreAttributeName.NAME_ID), List.of("ignoredValue"));

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(cpResponse)
				.build();

		assertThat(auditDto.getEventType(), is(EventType.RESPONSE));
		assertThat(auditDto.getDestination(), is(TEST_DESTINATION));
		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
		assertThat(auditDto.getResponseAttributes(), is(not(nullValue())));
		assertThat(auditDto.getResponseAttributes().size(), is(5));
		var truncatedClaimsName = DefinitionUtil.truncateNamespace(CLAIMS_NAME.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedClaimsName),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME, CLAIMS_NAME.getNamespaceUri(),
								AuditDto.AttributeSource.CP_RESPONSE, ClaimSource.CP.name(), null))));
		assertThat(auditDto.getResponseAttributes().get(CLAIMS_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME2, null,
						AuditDto.AttributeSource.CP_RESPONSE, ClaimSource.CP.name(), null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.FIRST_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_FIRST_NAME, null,
						AuditDto.AttributeSource.CP_RESPONSE, ClaimSource.CP.name(), null))));
		var truncatedEmail = DefinitionUtil.truncateNamespace(CoreAttributeName.EMAIL.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedEmail),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_EMAIL, CoreAttributeName.EMAIL.getNamespaceUri(),
						AuditDto.AttributeSource.CP_RESPONSE, ClaimSource.CP.name(), null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.HOME_REALM.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of("dropped", null,
						AuditDto.AttributeSource.DROPPED_RESPONSE, ClaimSource.CP.name(), null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.NAME_ID.getName()),
				is(nullValue()));
	}

	@Test
	void testMapFromCpResponseDtoOutbound() {
		var cpResponse = new CpResponse();
		cpResponse.setIssuer(TEST_ISSUER);
		cpResponse.setDestination(TEST_DESTINATION);
		cpResponse.setResult(new Definition(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()), List.of(TEST_CLAIMS_NAME));
		cpResponse.setResult(Definition.ofName(CoreAttributeName.CLAIMS_NAME), List.of(TEST_CLAIMS_NAME2));
		var nameId = "myNameId";
		cpResponse.setResult(new Definition(CoreAttributeName.NAME_ID.getNamespaceUri()), List.of(nameId));
		cpResponse.setResult(Definition.ofName(CoreAttributeName.FIRST_NAME), List.of(TEST_FIRST_NAME));
		var authLevel = "normalverified";
		cpResponse.setAuthLevel(authLevel);
		var emails = List.of("mail1@trustbroker.swiss", "mail2@trustbroker.swiss");
		cpResponse.setResult(Definition.ofName(CoreAttributeName.EMAIL), emails);
		// attributes not mapped outbound:
		cpResponse.setAttribute(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName(), "ignoredValue");

		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(cpResponse)
				.build();

		assertThat(auditDto.getEventType(), is(EventType.RESPONSE));
		assertThat(auditDto.getDestination(), is(TEST_DESTINATION));
		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
		assertThat(auditDto.getResponseAttributes(), is(not(nullValue())));
		assertThat(auditDto.getResponseAttributes().size(), is(5));
		var truncatedClaimsName = DefinitionUtil.truncateNamespace(CLAIMS_NAME.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedClaimsName),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME, CLAIMS_NAME.getNamespaceUri(),
								AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CLAIMS_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME2, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.FIRST_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_FIRST_NAME, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		var truncatedNameId = DefinitionUtil.truncateNamespace(CoreAttributeName.NAME_ID.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedNameId),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(nameId,
						CoreAttributeName.NAME_ID.getNamespaceUri(), AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.EMAIL.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(emails, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName()),
				is(nullValue()));
		assertThat(auditDto.getAuthLevel(), is(authLevel));
	}

	@Test
	void testMapFromAuthnRequest() {
		var issuer = new IssuerBuilder().buildObject();
		issuer.setValue(TEST_ISSUER);
		var authnRequest = new AuthnRequestBuilder().buildObject();
		authnRequest.setIssuer(issuer);
		authnRequest.setDestination(TEST_DESTINATION);
		var acsUrl = "myACSUrl";
		authnRequest.setAssertionConsumerServiceURL(acsUrl);
		authnRequest.setID(TEST_REQUEST_ID);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(authnRequest)
				.build();

		assertThat(auditDto.getEventType(), is(EventType.AUTHN_REQUEST));
		assertThat(auditDto.getDestination(), is(TEST_DESTINATION));
		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
		assertThat(auditDto.getAssertionConsumerUrl(), is(acsUrl));
		assertThat(auditDto.getMessageId(), is(TEST_REQUEST_ID));
		assertThat(auditDto.getConversationId(), is(TraceSupport.getOwnTraceParent()));
	}

	@Test
	void testMapFromLogoutRequest() {
		var issuer = new IssuerBuilder().buildObject();
		issuer.setValue(TEST_ISSUER);
		var logoutRequest = new LogoutRequestBuilder().buildObject();
		logoutRequest.setIssuer(issuer);
		logoutRequest.setID(TEST_REQUEST_ID);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(logoutRequest)
				.build();

		assertThat(auditDto.getEventType(), is(EventType.LOGOUT_REQUEST));
		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
	}

	@Test
	void testMapFromHttpRequest() {
		var network = new NetworkConfig();
		doReturn(network).when(trustBrokerProperties).getNetwork();

		var request = new MockHttpServletRequest();
		var url = "/myUrl";
		var entryHost = "entryHost";
		var userAgent = "myUserAgent";
		var deviceId = "myXDevId";
		var traceParent = "00-000102030405060708090a0b0c0d0e0f-0102030405060708-01";
		var requestId = "000102030405060708090a0b0c0d0e0f";
		request.addHeader(WebUtil.HTTP_HEADER_X_FORWARDED_FOR, "myClientIp");
		request.addHeader(AuditMapper.HTTP_HEADER_X_FORWARDED_HOST, entryHost);
		request.addHeader(HttpHeaders.USER_AGENT, userAgent);
		request.addHeader(network.getNetworkHeader(), "myNetwork");
		request.addHeader(WebSupport.HTTP_HEADER_DEVICE_ID, deviceId);
		request.addHeader(HttpHeaders.HOST, "myEntryHost");
		request.addHeader(HttpHeaders.REFERER, "myReferer");
		TraceSupport.setHttpTraceIdHeaderName(TraceSupport.HTTP_REQUEST_ID); // ensure the value is set in this thread
		request.addHeader(TraceSupport.getHttpTraceIdHeaderName(), requestId);
		request.addHeader(TraceSupport.W3C_TRACEPARENT, traceParent);
		request.setRequestURI(url);

		TraceSupport.setMdcTraceContext(request);
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFromThreadContext()
				.mapFrom(request)
				.build();
		TraceSupport.clearMdcTraceContext();

		assertThat(auditDto.getUrl(), is("http://myEntryHost" + url));
		assertThat(auditDto.getClientType(), is(userAgent));
		assertThat(auditDto.getTraceId(), startsWith(requestId)); // just the trace part
		assertThat(auditDto.getEntryId(), is(entryHost));
		assertThat(auditDto.getDeviceId(), is(deviceId));
	}

	@Test
	void testMapFromStateData() {
		var ssoGroup = "group1";
		var ssoQoa = "Qoa60"; // format irrelevant for this test
		var establishedTime = Timestamp.from(Instant.now());
		var arDurationSecs = 10L;
		var arSentTime = Timestamp.from(establishedTime.toInstant().plusSeconds(2));
		var arCompletedTime = Timestamp.from(arSentTime.toInstant().plusSeconds(arDurationSecs));
		var loginDurationSecs = 20L;
		var loginCompletedTime = Timestamp.from(establishedTime.toInstant().plusSeconds(loginDurationSecs));
		var expirationTime = Timestamp.from(establishedTime.toInstant().plusSeconds(100));

		var ssoState = SsoState.builder()
				.ssoGroupName(ssoGroup)
				.ssoQoa(ssoQoa)
				.ssoParticipants(Set.of(
						new SsoSessionParticipant("p1", "cp1", "acs1", "client1", "sess1"),
						new SsoSessionParticipant("p2", "cp2", "acs2", "client2", "sess2")))
				.build();
		var lifecycle = Lifecycle.builder()
				.lifecycleState(LifecycleState.ESTABLISHED)
				.expirationTime(expirationTime)
				.ssoEstablishedTime(establishedTime)
				.reauthTime(loginCompletedTime)
				.build();

		var arResponseId = "respId1";
		var ar = AccessRequestSessionState.builder()
										  .state(AccessRequestState.INITIATED)
										  .mode("INTERACTIVE")
										  .initTime(establishedTime)
										  .sentTime(arSentTime)
										  .completedTime(arCompletedTime)
										  .responseId(arResponseId)
										  .build();

		var spLifeCycle = Lifecycle.builder()
				.initTime(establishedTime)
				.build();

		var spStateData = StateData.builder()
				.id("spStateId")
				.lifecycle(spLifeCycle)
				.build();

		var stateId = "myStateId";
		var deviceId = "myDeviceId";
		var stateData = StateData.builder()
				.issuer("myIssuerFromSess")
				.id(stateId)
				.deviceId(deviceId)
				.ssoState(ssoState)
				.accessRequest(ar)
				.lifecycle(lifecycle)
				.spStateData(spStateData)
				.build();
		var cpResponse = new CpResponse();
		cpResponse.setDestination(TEST_DESTINATION);
		var issuerFromMessage = "myIssuerFromMessage";
		cpResponse.setIssuer(issuerFromMessage);
		stateData.setCpResponse(cpResponse);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.build();

		assertThat(auditDto.getIssuer(), is(issuerFromMessage));
		assertThat(auditDto.getSessId(), is(stateId));
		assertThat(auditDto.getDeviceIdAccepted(), is(deviceId));
		assertThat(auditDto.getDestination(), is(TEST_DESTINATION));
		assertThat(auditDto.getSsoGroupName(), is(ssoGroup));
		assertThat(auditDto.getSsoParticipantCount(), is(2));
		assertThat(auditDto.getSsoQoa(), is(ssoQoa));
		assertThat(auditDto.getSsoEstablishedTime(), is(establishedTime));
		assertThat(auditDto.getArState(), is("INITIATED"));
		assertThat(auditDto.getArMode(), is("INTERACTIVE"));
		assertThat(auditDto.getArResponseId(), is(arResponseId));
		assertThat(auditDto.getArDurationSecs(), is(arDurationSecs));
		assertThat(auditDto.getExpirationTime(), is(expirationTime));
		assertThat(auditDto.getLoginDurationSecs(), is(loginDurationSecs));
	}

	@Test
	void testMapOverwriteWithNonNull() {
		// StateData is set last but does not set issuer anymore
		String cpStateIssuer = "cpStateIssuer";
		String rpStateIssuer = "rpStateIssuer";
		var stateData = StateData.builder()
				.id(TEST_REQUEST_ID)
				.issuer(cpStateIssuer)
				.spStateData(StateData.builder().id(TEST_REQUEST_ID).issuer(rpStateIssuer).build())
				.build();
		var cpResponse = new CpResponse();
		String responseIssuer = "responseIssuer";
		cpResponse.setIssuer(responseIssuer);
		stateData.setCpResponse(cpResponse);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.build();

		assertThat(auditDto.getIssuer(), is(responseIssuer));
		assertThat(auditDto.getCpIssuer(), is(cpStateIssuer));
		assertThat(auditDto.getRpIssuer(), is(rpStateIssuer));
	}

	@Test
	void testMapNoOverwriteWithNull() {
		// StateData is set last, no issuer set on that one:
		var stateData = StateData.builder()
				.id(TEST_REQUEST_ID)
				.build();
		var cpResponse = new CpResponse();
		cpResponse.setIssuer(TEST_ISSUER);
		stateData.setCpResponse(cpResponse);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.build();

		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
	}

	@Test
	void testMapFromResponse() {
		testMapFromResponse(new ResponseBuilder().buildObject(), EventType.RESPONSE);
	}

	@Test
	void testMapFromLogoutResponse() {
		testMapFromResponse(new LogoutResponseBuilder().buildObject(), EventType.LOGOUT_RESPONSE);
	}

	private void testMapFromResponse(StatusResponseType response, EventType type) {
		var issuer = new IssuerBuilder().buildObject();
		issuer.setValue(TEST_ISSUER);
		response.setIssuer(issuer);
		response.setDestination(TEST_DESTINATION);
		response.setID(TEST_REQUEST_ID);

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(response)
				.build();

		assertThat(auditDto.getEventType(), is(type));
		assertThat(auditDto.getMessageId(), is(TEST_REQUEST_ID));
		assertThat(auditDto.getDestination(), is(TEST_DESTINATION));
		assertThat(auditDto.getIssuer(), is(TEST_ISSUER));
		assertThat(auditDto.getConversationId(), is(nullValue())); // a conversation is based on state (authnrequest.ID)
	}

	@Test
	void testMapFromDefinitions() {
		var homeNames = List.of("home1", "home2");
		var emails = List.of("myEmail1@domain", "myEmail2@domain");
		Map<Definition, List<String>> attributes = new HashMap<>();
		attributes.put(new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri()), List.of(TEST_FIRST_NAME));
		attributes.put(Definition.ofName(CoreAttributeName.CLAIMS_NAME), List.of(TEST_CLAIMS_NAME2));
		attributes.put(new Definition(CoreAttributeName.CLAIMS_NAME.getNamespaceUri()), List.of(TEST_CLAIMS_NAME));
		attributes.put(Definition.ofName(CoreAttributeName.NAME), List.of(TEST_NAME));
		attributes.put(new Definition(CoreAttributeName.NAME.getNamespaceUri()), null); // null ignored
		attributes.put(Definition.ofName(CoreAttributeName.SSO_SESSION_ID), List.of(TEST_SESSION_ID));
		attributes.put(Definition.ofNames(CoreAttributeName.EMAIL), emails);
		attributes.put(Definition.ofName(CoreAttributeName.HOME_NAME), homeNames);
		var cidName = "cid";
		var cidValues = List.of("cid1", "cid2");
		attributes.put(Definition.builder().name(cidName).cid(true).build(), cidValues);
		var unmappedShort = "some-unmapped-attribute";
		var unmapped = "http://schemas.xmlsoap.org/ws/2024/03/test/" + unmappedShort;
		var unmappedValue = "unmapped-attribute-value";
		attributes.put(Definition.builder().name(unmapped).build(), List.of(unmappedValue));
		var unmappedValueShort = "unmapped-attribute-value-short";
		attributes.put(Definition.builder().name(unmappedShort).build(), List.of(unmappedValueShort));

		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFromDefinitions(attributes, AuditDto.AttributeSource.CP_RESPONSE)
				.build();

		assertThat(auditDto.getResponseAttributes(), is(not(nullValue())));
		assertThat(auditDto.getResponseAttributes().size(), is(9));
		var truncatedFirstName = DefinitionUtil.truncateNamespace(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedFirstName),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_FIRST_NAME, CoreAttributeName.FIRST_NAME.getNamespaceUri(),
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.CLAIMS_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME2, null,
								AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		var truncatedClaimsName = DefinitionUtil.truncateNamespace(CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedClaimsName),
				is(AuditDto.ResponseAttributeValues.of(
					AuditDto.ResponseAttributeValue.of(TEST_CLAIMS_NAME, CoreAttributeName.CLAIMS_NAME.getNamespaceUri(),
							AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(TEST_NAME, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.EMAIL.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(emails, CoreAttributeName.EMAIL.getNamespaceUri(),
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.HOME_NAME.getName()),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(homeNames, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(cidName),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(cidValues, null,
						AuditDto.AttributeSource.CP_RESPONSE, null, true))));
		assertThat(auditDto.getResponseAttributes().get(unmapped), is(nullValue()));
		assertThat(auditDto.getResponseAttributes().get(unmappedShort),
				is(AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(unmappedValueShort, null,
								AuditDto.AttributeSource.CP_RESPONSE, null, null),
						AuditDto.ResponseAttributeValue.of(unmappedValue, unmapped,
								AuditDto.AttributeSource.CP_RESPONSE, null, null))
				));
	}

	@Test
	void mapResponse() {
		var issuer = TEST_ISSUER;
		var subject = "subjectNameId";
		var destination = "myDest";
		var response = SamlFactory.createResponse(Response.class, issuer);
		var responseParams = ResponseParameters.builder()
											   .issuerId(issuer)
											   .rpAuthnRequestId("authnRequest")
											   .nameId(subject)
											   .federationServiceIssuerId(issuer)
											   .rpClientName("client")
											   .recipientId("recipient")
											   .subjectValiditySeconds(600)
											   .audienceValiditySeconds(400)
											   .skinnyAssertionStyle(OpenSamlUtil.SKINNY_ALL)
											   .build();
		response.getAssertions()
				.add(ResponseFactory.createSamlAssertion(
						CpResponse.builder().build(),
						ConstAttributes.builder().build(),
						null, responseParams, null));
		response.setDestination(destination);
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(response)
				.build();
		assertThat(auditDto.getIssuer(), is(issuer));
		assertThat(auditDto.getDestination(), is(destination));
		assertThat(auditDto.getPrincipal(), is(subject));
	}

	@Test
	void mapLogoutResponse() {
		var issuer = TEST_ISSUER;
		var message = "statusMsg";
		var response = SamlFactory.createResponse(LogoutResponse.class, issuer);
		var statusMessage = new StatusMessageBuilder().buildObject();
		statusMessage.setValue(message);
		var statusCode = new StatusCodeBuilder().buildObject();
		statusCode.setValue(StatusCode.RESPONDER);
		var nestedStatusCode = new StatusCodeBuilder().buildObject();
		nestedStatusCode.setValue(StatusCode.INVALID_ATTR_NAME_OR_VALUE);
		statusCode.setStatusCode(nestedStatusCode);
		var status = new StatusBuilder().buildObject();
		status.setStatusMessage(statusMessage);
		status.setStatusCode(statusCode);
		response.setStatus(status);
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(response)
				.build();
		assertThat(auditDto.getIssuer(), is(issuer));
		assertThat(auditDto.getStatusMessage(), is(message));
		assertThat(auditDto.getStatus(), is(StatusCode.RESPONDER));
		assertThat(auditDto.getNestedStatus(), is(StatusCode.INVALID_ATTR_NAME_OR_VALUE));
	}

	@Test
	void mapAssertion() {
		// simulate some CP response stuff
		var firstName = "TestFirstName";
		var middleName = "Middle";
		var lastName = "Last";
		Map<Definition, List<String>> userDetails = new Hashtable<>();
		userDetails.put(Definition.ofNames(CoreAttributeName.FIRST_NAME), List.of(firstName));
		userDetails.put(Definition.ofName(CoreAttributeName.NAME), List.of(middleName, lastName));
		var cpResponse = CpResponse.builder()
								   .nameIdFormat("unknown-nameid-format")
								   .userDetails(userDetails)
								   .build();
		// have a minimal assertion mapped to audit output
		var responseParams = ResponseParameters.builder()
											   .issuerId(TEST_ISSUER)
											   .federationServiceIssuerId(TEST_ISSUER)
											   .subjectValiditySeconds(20)
											   .audienceValiditySeconds(10)
											   .build();

		var assertion = ResponseFactory.createSamlAssertion( cpResponse, null, cpResponse.getContextClasses(),
				responseParams, null);
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFromRstResponseAssertion(assertion)
				.build();
		// verify (audit DTO attributes list is somewhat inaccessible)
		assertThat(auditDto.getEventType(), equalTo(EventType.RST_RESPONSE));
		assertThat(auditDto.getResponseAttributes().size(), equalTo(2));
		var truncatedFirstName = DefinitionUtil.truncateNamespace(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		assertThat(auditDto.getResponseAttributes().get(truncatedFirstName), is(
				AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(firstName, CoreAttributeName.FIRST_NAME.getNamespaceUri(),
								AuditDto.AttributeSource.SAML_RESPONSE, null, null))));
		assertThat(auditDto.getResponseAttributes().get(CoreAttributeName.NAME.getName()), is(
				AuditDto.ResponseAttributeValues.of(
						AuditDto.ResponseAttributeValue.of(List.of(middleName, lastName),
								null, AuditDto.AttributeSource.SAML_RESPONSE, null, null))));
	}

	@Test
	void mapFromOidc() {
		var clientId = "oidcClient1";
		var redirectUrl = "https://localhost/redirectUrl";
		var ssoSessionId = "ssoSession1";
		var oidcData = OidcAuditData.builder()
									.oidcClientId(clientId)
									.ssoSessionId(ssoSessionId)
									.oidcLogoutUrl(redirectUrl)
									.build();
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(oidcData)
				.build();
		assertThat(auditDto.getEventType(), equalTo(EventType.OIDC_LOGOUT));
		assertThat(auditDto.getOidcClientId(), equalTo(clientId));
		assertThat(auditDto.getSsoSessionId(), equalTo(ssoSessionId));
		assertThat(auditDto.getDestination(), equalTo(redirectUrl));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,CP_RESPONSE,CP_RESPONSE",
			"null,DROPPED_RESPONSE,DROPPED_RESPONSE",
			"CP,null,CP_RESPONSE",
			"CP,DROPPED_RESPONSE,DROPPED_RESPONSE",
			"IDM,CP_RESPONSE,IDM_RESPONSE"
	}, nullValues = "null")
	void mapSourceTest(String querySource, String source, String expected) {

		AuditDto.AttributeSource existingSource = source == null ? null : AuditDto.AttributeSource.valueOf(source);
		AuditDto.AttributeSource expectedSource= expected == null ? null : AuditDto.AttributeSource.valueOf(expected);

		assertEquals(expectedSource, AuditMapper.mapSource(querySource, existingSource));
	}

}
