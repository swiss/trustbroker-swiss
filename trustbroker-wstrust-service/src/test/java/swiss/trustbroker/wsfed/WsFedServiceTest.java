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

package swiss.trustbroker.wsfed;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.service.AuthenticationService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.wsfed.dto.WsFedAction;
import swiss.trustbroker.wsfed.service.WsFedService;
import swiss.trustbroker.wsfed.util.WsFedUtil;

@SpringBootTest
@ContextConfiguration(classes = { WsFedService.class })
@TestPropertySource(properties="trustbroker.config.wsfed.enabled=true")
class WsFedServiceTest {

	private static final String REFERRER = "https://wsfed.trustbroker.swiss/";

	private static final String REPLY_URL = REFERRER + "reply";

	private static final String RP_ID = "rpIssuer1";

	private static final String CONTEXT = "myContext";

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private AuthenticationService authenticationService;

	@MockitoBean
	private RelyingPartyService relyingPartyService;


	@MockitoBean
	private List<OutputService> outputServices;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private WsFedService wsFedService;

	@BeforeAll
	static void opensamlSetup() {
		SamlInitializer.initSamlSubSystem();
	}

	@ParameterizedTest
	@MethodSource
	void isWsFed(HttpMethod method, String action, boolean expected) {
		var request = new MockHttpServletRequest();
		request.setMethod(method.name());
		if (action != null) {
			request.setParameter(WsFedUtil.ACTION, action);
		}
		assertThat(wsFedService.isWsFed(request), is(expected));
	}

	static Object[][] isWsFed() {
		return new Object[][] {
				// invalid
				{ HttpMethod.GET, null, false },
				{ HttpMethod.GET, "unknown", false },
				{ HttpMethod.PUT, WsFedAction.ACTION_SIGN_IN.getAction(), false },
				// valid
				{ HttpMethod.GET, WsFedAction.ACTION_SIGN_IN.getAction(), true },
				{ HttpMethod.GET, WsFedAction.ACTION_SIGN_IN.getAction(), true },
				{ HttpMethod.GET, WsFedAction.ACTION_SIGN_OUT.getAction(), true },
				{ HttpMethod.POST, WsFedAction.ACTION_SIGN_OUT_LEGACY.getAction(), true },
		};
	}

	@Test
	void processWsFedSignInRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setParameter(WsFedUtil.ACTION, WsFedAction.ACTION_SIGN_IN.getAction());
		request.setParameter(WsFedUtil.REALM, RP_ID);
		request.setParameter(WsFedUtil.REPLY, REPLY_URL);
		request.setParameter(WsFedUtil.CONTEXT, CONTEXT);
		request.setParameter(WsFedUtil.REFRESH, WsFedUtil.FORCE_AUTHN);
		request.addHeader(HttpHeaders.REFERER, REFERRER);
		var response = new MockHttpServletResponse();
		mockRelyingParty(RP_ID, REFERRER);

		var result = wsFedService.processWsFedRequest(request, response, outputServices);

		assertThat(result, is(nullValue()));
		ArgumentCaptor<AuthnRequest> authnRequestCaptor = ArgumentCaptor.forClass(AuthnRequest.class);
		ArgumentCaptor<SignatureContext> signatureContextCaptor = ArgumentCaptor.forClass(SignatureContext.class);
		verify(authenticationService, times(1))
				.handleAuthnRequest(
						eq(outputServices), authnRequestCaptor.capture(),  eq(CONTEXT), eq(request), eq(response),
						signatureContextCaptor.capture());
		var authnRequest = authnRequestCaptor.getValue();
		assertThat(authnRequest, is(not(nullValue())));
		assertThat(authnRequest.getIssuer().getValue(), is(RP_ID));
		assertThat(authnRequest.getID(), is(not(CONTEXT))); // only used in response
		assertThat(authnRequest.isForceAuthn(), is(Boolean.TRUE));
		assertThat(authnRequest.getAssertionConsumerServiceURL(), is(REPLY_URL));
		var signatureContext = signatureContextCaptor.getValue();
		assertThat(signatureContext, is(not(nullValue())));
		assertThat(signatureContext.getBinding(), is(SamlBinding.WS_FED));
		assertThat(signatureContext.isRequireSignature(), is(false));
	}

	@Test
	void processWsFedSignOutRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setParameter(WsFedUtil.ACTION, WsFedAction.ACTION_SIGN_OUT.getAction());
		request.setParameter(WsFedUtil.REPLY, REPLY_URL);
		request.addHeader(HttpHeaders.REFERER, REFERRER);
		var response = new MockHttpServletResponse();
		mockRelyingPartyReplyUrl(RP_ID, REPLY_URL);

		var result = wsFedService.processWsFedRequest(request, response, outputServices);

		assertThat(result, is(REPLY_URL));
		ArgumentCaptor<LogoutRequest> logoutRequestCaptor = ArgumentCaptor.forClass(LogoutRequest.class);
		ArgumentCaptor<SignatureContext> signatureContextCaptor = ArgumentCaptor.forClass(SignatureContext.class);
		verify(relyingPartyService, times(1))
				.handleLogoutRequest(eq(outputServices), logoutRequestCaptor.capture(), eq(null), eq(request),
						eq(response), signatureContextCaptor.capture());
		var logoutRequest = logoutRequestCaptor.getValue();
		assertThat(logoutRequest, is(not(nullValue())));
		assertThat(logoutRequest.getIssuer().getValue(), is(RP_ID));
		var signatureContext = signatureContextCaptor.getValue();
		assertThat(signatureContext, is(not(nullValue())));
		assertThat(signatureContext.getBinding(), is(SamlBinding.WS_FED));
		assertThat(signatureContext.isRequireSignature(), is(false));
	}

	private RelyingParty mockRelyingParty(String requestIssuer, String referrer) {
		var relyingParty = givenRelyingParty(requestIssuer);
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, referrer, true)).thenReturn(relyingParty);
		return relyingParty;
	}

	private RelyingParty mockRelyingPartyReplyUrl(String requestIssuer, String replyUrl) {
		var relyingParty = givenRelyingParty(requestIssuer);
		when(relyingPartySetupService.getRelyingPartiesByAcsUrlMatch(replyUrl)).thenReturn(List.of(relyingParty));
		return relyingParty;
	}
	private static RelyingParty givenRelyingParty(String requestIssuer) {
		return RelyingParty.builder()
						   .id(requestIssuer)
						   .acWhitelist(givenAcWhitelist(List.of(REPLY_URL)))
						   .build();
	}

	private static AcWhitelist givenAcWhitelist(List<String> acUrls) {
		return AcWhitelist.builder()
						  .acUrls(acUrls)
						  .build();
	}
}
