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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.metrics.service.MetricsService;

@SpringBootTest(classes = AuditService.class)
@ExtendWith(SpringExtension.class)
class AuditServiceTest {

	@MockitoBean
	private AuditLogger mockLogger;

	@MockitoBean
	private AuditLogFilter mockFilter;

	@MockitoBean
	private MetricsService metricsService;

	@Autowired
	private AuditService auditService;

	@BeforeEach
	void setUp() {
		doReturn(false).when(mockFilter).isAdditionalAuditingEnabled();
		doReturn(false).when(mockFilter).suppressAttribute(any(), any());
		doReturn(false).when(mockFilter).suppressField(any(), any());
		when(mockLogger.createAuditLogBuilder(anyString()))
				.thenAnswer(invocation -> new AuditLogBuilder(mockFilter, invocation.getArgument(0)));
	}

	@Test
	void testLogInboundAuthnRequest() {
		// DEBUG AuthnRequest from RP
		AuditDto auditDto = buildDto(EventType.AUTHN_REQUEST);
		auditService.logInboundFlow(auditDto);
		verify(mockLogger, times(1)).log(eq(EventType.AUTHN_REQUEST), eq(true), startsWith("AuthnRequest:"));
		verify(mockLogger, times(1)).log(eq(EventType.AUTHN_REQUEST), eq(true), contains("event=authnrequest"));
	}

	@Test
	void testLogOutboundAuthnRequest() {
		// DEBUG AuthnRequest to CP
		AuditDto auditDto = buildDto(EventType.AUTHN_REQUEST);
		auditService.logOutboundFlow(auditDto);
		verify(mockLogger, times(1)).log(eq(EventType.AUTHN_REQUEST), eq(false), startsWith("AuthnRequest:"));
		verify(mockLogger, times(1)).log(eq(EventType.AUTHN_REQUEST), eq(false), contains("event=authnrequest"));
	}

	@Test
	void testLogInboundSamlResponse() {
		// DEBUG Response from CP
		AuditDto auditDto = buildDto(EventType.RESPONSE);
		auditService.logInboundFlow(auditDto);
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(true), startsWith("AuthnResponse:"));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(true), contains("event=response"));
	}

	@Test
	void testLogOutboundSamlResponse() {
		// INFO Response to RP
		AuditDto auditDto = buildDto(EventType.RESPONSE);
		auditService.logOutboundFlow(auditDto);
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false), startsWith("AuthnResponse:"));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false), contains("event=response"));
		// network topology
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false), contains("clientIP=\"127.0.0.99\""));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false), contains("clientNetwork=EXTRANET"));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false), contains("clientType=\"MS Edge\""));
		// most important INFO business attributes
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("rpIssuer=\"urn:trustbroker:rp\""));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("issuer=\"http://xtb.trustbroker.swiss\""));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("cpIssuer=\"urn:trustbroker:cp\""));
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("HomeRealm=\"urn:trustbroker:home")); // (FQ-name) skipped and DEBUG not enabled anyway
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("ClaimsName=\"user.12345")); // (FQ-name) skipped and DEBUG not enabled anyway
	}

	@Test
	void testAnySsoSessionId() {
		AuditDto auditDto = buildDto(EventType.RESPONSE);
		auditService.logOutboundFlow(auditDto);
		verify(mockLogger, times(1)).log(eq(EventType.RESPONSE), eq(false),
				contains("SsoSessionId=\"sso-uuid\""));
	}

	@Test
	void testReferrerExtraction() {
		assertEquals("http://localhost", AuditMapper.extractReferrer("http://localhost"));
		assertEquals("https://localhost", AuditMapper.extractReferrer("https://localhost"));
		assertEquals("https://localhost:443", AuditMapper.extractReferrer("https://localhost:443"));
		assertEquals("https://localhost:443/", AuditMapper.extractReferrer("https://localhost:443/"));
		assertEquals("https://localhost:443", AuditMapper.extractReferrer("https://localhost:443?query"));
		assertEquals("https://localhost:443", AuditMapper.extractReferrer("https://localhost:443?query"));
		assertEquals("https://localhost:443/", AuditMapper.extractReferrer("https://localhost:443/;data"));
		assertEquals("https://localhost:443/", AuditMapper.extractReferrer("https://localhost:443/%20data"));
		assertEquals("https://localhost:443/sub1", AuditMapper.extractReferrer("https://localhost:443/sub1?query"));
		assertEquals("https://localhost:443/sub1/", AuditMapper.extractReferrer("https://localhost:443/sub1/?query"));
		assertEquals("https://localhost:443/sub1/sub2", AuditMapper.extractReferrer("https://localhost:443/sub1/sub2?query"));
		assertEquals("https://my.trustbroker.swiss/very-long-url-that-could-be-atoken-or...",
				AuditMapper.extractReferrer(
						"https://my.trustbroker.swiss/very-long-url-that-could-be-atoken-or-url-encoded-data"));
	}

	private AuditDto buildDto(EventType type) {
		// data reflects RP authenticating via Trustbroker on CP
		return AuditDto.builder()
					   .eventType(type)
					   .clientIP("127.0.0.99")
					   .clientType("MS Edge")
					   .clientNetwork("EXTRANET")
					   .issuer("http://xtb.trustbroker.swiss") // Trustbroker
					   .cpIssuer("urn:trustbroker:cp") // CP
					   .rpIssuer("urn:trustbroker:rp")  // RP
					   .conversationId("samlRequestIdAndSamlResponseInResponseTo")
					   .destination("https://xtb.trustbroker.swiss/api/v1/saml/")
					   .assertionConsumerUrl("https://rp.trustbroker.swiss/acs")
					   .responseAttributes(Map.of(
						CoreAttributeName.HOME_REALM.getName(), AuditDto.ResponseAttributeValues.of(
								   AuditDto.ResponseAttributeValue.of(
										   "urn:trustbroker:home", CoreAttributeName.HOME_REALM.getNamespaceUri(),
										   AuditDto.AttributeSource.CP_RESPONSE, null, true)),
						CoreAttributeName.CLAIMS_NAME.getName(), AuditDto.ResponseAttributeValues.of(
									   AuditDto.ResponseAttributeValue.of(
											   "user.12345", CoreAttributeName.CLAIMS_NAME.getNamespaceUri(),
											   AuditDto.AttributeSource.CP_RESPONSE, null, true)),
						CoreAttributeName.SSO_SESSION_ID.getName(), AuditDto.ResponseAttributeValues.of(
									   AuditDto.ResponseAttributeValue.of(
											   "sso-uuid", CoreAttributeName.SSO_SESSION_ID.getNamespaceUri(),
											   AuditDto.AttributeSource.CP_RESPONSE, null, true))
						))
					   .build();
	}

}
