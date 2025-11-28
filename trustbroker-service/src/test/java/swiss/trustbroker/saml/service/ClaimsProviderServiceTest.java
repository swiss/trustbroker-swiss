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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.oidc.client.service.AuthorizationCodeFlowService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = ClaimsProviderService.class)
class ClaimsProviderServiceTest {

	@Autowired
	private ClaimsProviderService claimsProviderService;

	@MockitoBean
	private StateCacheService stateCacheService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	ArtifactCacheService artifactCacheService;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private VelocityEngine velocityEngine;

	@MockitoBean
	private AuditService auditService;

	@MockitoBean
	private QoaMappingService qoaMappingService;

	@MockitoBean
	private SamlOutputService samlOutputService;

	@MockitoBean
	private AuthorizationCodeFlowService authorizationCodeFlowService;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void setUp() {
		var securityChecks = new SecurityChecks();
		when(trustBrokerProperties.getSecurity()).thenReturn(securityChecks);
	}

	void createAuthnContextTest() {
		var stateData = givenStateWithQoa();

		RequestedAuthnContext authnContext = claimsProviderService.createAuthnContext(stateData,
				new QoaSpec(QoaComparison.MINIMUM, stateData.getRpContextClasses()));

		assertNotNull(authnContext);
		assertNotNull(authnContext.getAuthnContextClassRefs());
		assertEquals(givenRpQoas().size(), authnContext.getAuthnContextClassRefs().size());
		assertEquals(QoaComparison.MINIMUM.getValue(), authnContext.getComparison().toString());
	}

	@ParameterizedTest
	@MethodSource
	void useArtifactBinding(ArtifactBindingMode mode, Boolean rpSessionInit, Boolean cpSessionInit, boolean result) {
		var claimsParty = Optional.<ClaimsParty>empty();
		if (mode != null) {
			claimsParty = Optional.of(givenClaimsParty());
			claimsParty.get().setSaml(
					Saml.builder()
							.artifactBinding(ArtifactBinding.builder().outboundMode(mode).build())
							.build());
		}
		var stateData = (rpSessionInit != null || cpSessionInit != null) ? givenState() : null;
		if (stateData != null) {
			stateData.getSpStateData().setRequestBinding(
					Boolean.TRUE.equals(rpSessionInit) ? SamlBinding.ARTIFACT : SamlBinding.POST);
			stateData.setRequestBinding(Boolean.TRUE.equals(cpSessionInit) ? SamlBinding.ARTIFACT : SamlBinding.POST);
		}
		assertThat(ClaimsProviderService.useArtifactBinding(claimsParty, stateData), is(result));
	}

	static Object[][] useArtifactBinding() {
		return new Object[][] {
				{ null, null, null, false },
				{ null, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, null, null, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, Boolean.FALSE, Boolean.TRUE, false },
				{ ArtifactBindingMode.REQUIRED, null, null, true },
				{ ArtifactBindingMode.REQUIRED, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.REQUIRED, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.REQUIRED, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, null, null, false },
				{ ArtifactBindingMode.SUPPORTED, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, Boolean.FALSE, Boolean.TRUE, false },
				{ ArtifactBindingMode.SUPPORTED, Boolean.FALSE, Boolean.FALSE, false },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.TRUE, false },
				{ ArtifactBindingMode.SUPPORTED, null, null, false }
		};
	}

	@Test
	void sendAuthnRequestToCp() {
		var stateData = givenState();
		var relayState = "relay1";
		stateData.setRelayState(relayState);
		var spstateData = stateData.getSpStateData();
		spstateData.setRequestBinding(SamlBinding.ARTIFACT);
		var rpIssuer = "rpIssuer1";
		var referrer = "https://localhost:2222/sp";
		spstateData.setIssuer(rpIssuer);
		spstateData.setReferer(referrer);
		var contextClass = SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN;
		spstateData.setContextClasses(List.of(contextClass));
		var customIssuer = "customIssuerId";

		var cpIssuer = "cpIssuerId";
		var ssoUrl = "https://localhost/sso";
		var cp = ClaimsParty.builder()
				.id(cpIssuer)
				.ssoUrl(ssoUrl)
				.authnRequestIssuerId(customIssuer)
				.saml(
						Saml.builder().artifactBinding(
								ArtifactBinding.builder().outboundMode(ArtifactBindingMode.SUPPORTED).build()
						).build()
				)
				.securityPolicies(
						SecurityPolicies.builder()
										.delegateOrigin(true)
										.forceAuthn(true)
										.build()
				)
				.build();
		doReturn(Optional.of(cp)).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(cpIssuer);
		doReturn(cp).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(cpIssuer, null);

		var samlProperties = new SamlProperties();
		var acsUrl = "https://localhost:1234/consumer";
		samlProperties.setConsumerUrl(acsUrl);
		doReturn(samlProperties).when(trustBrokerProperties).getSaml();

		var credential = SamlTestBase.dummyCredential();
		var encodingParams = EncodingParameters.builder().useArtifactBinding(true).build();
		var request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.REFERER, referrer);
		var response = new MockHttpServletResponse();

		// mock
		var requestCaptor = ArgumentCaptor.forClass(AuthnRequest.class);
		var relyingParty = RelyingParty.builder().id(rpIssuer).rpSigner(credential).build();
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referrer);
		doReturn(new QoaConfig(null, rpIssuer))
				.when(qoaMappingService).getQoaConfiguration(spstateData, relyingParty);
		doNothing().when(samlOutputService).sendRequest(requestCaptor.capture(),
				eq(credential), eq(relayState), eq(ssoUrl), eq(response), eq(encodingParams), eq(DestinationType.CP));
		var auditCaptor = ArgumentCaptor.forClass(AuditDto.class);
		doNothing().when(auditService).logOutboundFlow(auditCaptor.capture());
		doReturn(new QoaSpec(QoaComparison.EXACT, List.of(contextClass)))
				.when(qoaMappingService).mapRequestQoasToOutbound(any(), any(),
						argThat(qc -> rpIssuer.equals(qc.issuerId())),
						argThat(qc -> cpIssuer.equals(qc.issuerId())));

		// run
		claimsProviderService.sendAuthnRequestToCp(request, response, stateData, cp);

		// verify request
		var authnRequest = requestCaptor.getValue();

		assertThat(authnRequest.getID(), is(stateData.getId()));
		assertThat(authnRequest.getIssueInstant(), is(not(nullValue())));
		assertThat(authnRequest.getIssuer(), is(not(nullValue())));
		assertThat(authnRequest.getIssuer().getValue(), is(customIssuer));
		assertThat(authnRequest.getDestination(), is(ssoUrl));
		assertThat(authnRequest.getNameIDPolicy(), is(not(nullValue())));
		assertThat(authnRequest.getNameIDPolicy().getFormat(), is(NameIDType.UNSPECIFIED));
		assertThat(authnRequest.getDestination(), is(ssoUrl));
		assertThat(authnRequest.isForceAuthn(), is(true));

		// context class
		assertThat(authnRequest.getRequestedAuthnContext(), is(not(nullValue())));
		assertThat(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs(), hasSize(1));
		assertThat(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getURI(), is(contextClass));

		// delegateOrigin
		assertThat(authnRequest.getScoping(), is(not(nullValue())));
		assertThat(authnRequest.getScoping().getRequesterIDs(), hasSize(1));
		assertThat(authnRequest.getScoping().getRequesterIDs().get(0).getURI(), is(rpIssuer));

		// verify audit
		var auditDto = auditCaptor.getValue();
		assertThat(auditDto.getDestination(), is(ssoUrl));
		assertThat(auditDto.getSessId(), is(stateData.getId()));
		assertThat(auditDto.getRpIssuer(), is(rpIssuer));
		assertThat(auditDto.getReferrer(), is(referrer));

		// script hook
		verify(scriptService).processCpOnRequest(cpIssuer, authnRequest);
	}

	private StateData givenStateWithQoa() {
		var stateData = new StateData();
		var spStateData = new StateData();
		spStateData.setComparisonType(QoaComparison.MINIMUM);
		spStateData.setContextClasses(givenRpQoas());
		stateData.setSpStateData(spStateData);
		stateData.setComparisonType(QoaComparison.MINIMUM);
		return stateData;
	}

	private List<String> givenRpQoas() {
		List<String> qoas = new ArrayList<>();
		qoas.add(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		qoas.add(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT);

		return qoas;
	}

	private ClaimsParty givenClaimsParty() {
		return ClaimsParty.builder().id("cpId").build();
	}

	private StateData givenState() {
		var spStateData = StateData.builder().id("spSessionId").build();
		return StateData.builder().id("sessionId").spStateData(spStateData).build();
	}

}
