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

package swiss.trustbroker.oidc.session;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest(classes = OidcSessionSupportTest.class)
class OidcSessionSupportTest {

	private static final String OIDC_CLIENT_ID = "client1";

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private SsoService ssoService;

	private NetworkConfig network;

	@BeforeEach
	void setup() {
		network = new NetworkConfig();
	}

	@AfterEach
	void tearDown() {
		HttpExchangeSupport.end();
	}

	@Test
	void testOidcCookieSessionTracking() {
		var request = new MockHttpServletRequest();
		request.setCookies(
				new Cookie("BSESSION", "GLOBAL"),
				new Cookie("BSESSION_XTB-TEST-CLIENT", "SESS1"),
				new Cookie("BSESSION_XTB-TEST-CLIENT2", "SESS2")
		);

		var cookie1 = OidcSessionSupport.getOidcCookie(request, "XTB-test-client", network);
		assertNotNull(cookie1);
		assertThat(cookie1.getValue(), equalTo("SESS1"));

		var cookie2 = OidcSessionSupport.getOidcCookie(request, "XTB-test-client2", network);
		assertNotNull(cookie1);
		assertThat(cookie2.getValue(), equalTo("SESS2"));
	}

	@Test
	void testCookieBasedSessionId() {
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);

		// federated login on XTB, client_id in path
		var clientId  = "XTB-test-client";
		var expectedSession = "TEST-cookie-session";
		request.setParameter("client_id", clientId);
		request.setCookies(new Cookie("BSESSION_" + clientId.toUpperCase(), expectedSession));
		var sessId = OidcSessionSupport.getOidcSessionId(request, null, network);
		assertThat(sessId, equalTo(expectedSession));
	}

	@Test
	void testSamlExchangeClientId() {
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);

		var clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, nullValue());

		// federated login on XTB, client_id in path
		var expected = "TEST-saml-request";
		request.setRequestURI(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH + expected);
		clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));

		// federated login on XTB, client_id in path
		expected = "TEST-saml-response";
		request.setRequestURI(ApiSupport.SPRING_SAML_FEDERATION_CTXPATH + expected);
		clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));
	}

	@Test
	void testTokenAudience() throws JOSEException {
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);

		// POST access_token on /userinfo
		var expected = "TEST-userinfo";
		var token = givenToken(expected);
		request.addParameter(OidcUtil.ACCESS_INTROSPECT, token);
		var clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));

		// POST token on /introspect
		expected = "TEST-introspect";
		token = givenToken(expected);
		request.addParameter(OidcUtil.TOKEN_INTROSPECT, token);
		clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));

		// POST token on /introspect
		expected = "TEST-id_token_hint";
		token = givenToken(expected);
		request.addParameter(OidcUtil.ID_TOKEN_HINT, token);
		clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));

		// HTTP headers
		expected = "TEST-bearer";
		token = givenToken(expected);
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
		clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));
	}

	@Test
	void testQueryClientId() {
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);

		// client_id in query
		var expected = "TEST-query";
		request.addParameter("client_id", expected);
		var clientId = OidcSessionSupport.getOidcClientId(request, null, network);
		assertThat(clientId, equalTo(expected));
	}

	@Test
	void testOidcClientIdFromHttpParams() {
		var request = new MockHttpServletRequest();
		HttpExchangeSupport.begin(request, null);
		var expected = "TEST-client";
		var client = OidcClient.builder().id(expected).build();
		var redirectUrl = "https://localhost/client";
		request.setParameter(OidcUtil.LOGOUT_REDIRECT_URI, redirectUrl);
		doReturn(List.of(client)).when(relyingPartyDefinitions).getOidcClientsByPredicate(any());
		var clientId = OidcSessionSupport.getOidcClientIdFromHttpParams(request, relyingPartyDefinitions, network);
		assertThat(clientId, equalTo(expected));
	}

	@Test
	void testOidcClientIdFromRealmPath() {
		var request = new MockHttpServletRequest();
		var redirectUrl = "http://localhost:8080";
		var requestUri = "/realms/realm2/protocol/openid-connect/logout";
		request.setRequestURI(requestUri);
		request.setParameter(OidcUtil.LOGOUT_REDIRECT_URI, redirectUrl);
		HttpExchangeSupport.begin(request, null);

		var client1 = OidcClient.builder()
								.id("client1")
								.realm("realm1")
								.redirectUris(AcWhitelist.builder()
														 .acUrls(List.of(redirectUrl))
														 .build())
								.build();
		var client2 = OidcClient.builder()
								.id("client2")
								.realm("realm2")
								.redirectUris(AcWhitelist.builder()
														 .acUrls(List.of(redirectUrl))
														 .build())
								.build();
		// ambiguous
		var oidcClients = Map.of(
				"1", Pair.of(givenRelyingParty("1"), client1),
				"2", Pair.of(givenRelyingParty("2"), client2)
		);
		var relyingParties = RelyingPartyDefinitions.builder()
													.oidcConfigurations(oidcClients)
													.build();
		var clientId = OidcSessionSupport.getOidcClientIdFromHttpParams(request, relyingParties, network);
		assertThat(clientId, equalTo("client2"));
	}

	@ParameterizedTest
	@MethodSource
	void testGetCookieSameSite(boolean withClient, String policySameSite, String redirectUri,
			String logoutRedirectUri, String perimeterUrl, String propertySameSite, String expected) {
		var client = withClient ? OidcClient.builder().id("id").build() : null;
		if (client != null) {
			client.getOidcSecurityPolicies().setSessionCookieSameSite(policySameSite);
		}
		var request = new MockHttpServletRequest();
		request.setSecure(redirectUri != null && redirectUri.startsWith("https"));
		request.setParameter(OidcUtil.REDIRECT_URI, redirectUri);
		request.setParameter(OidcUtil.LOGOUT_REDIRECT_URI, logoutRedirectUri);
		var properties = new TrustBrokerProperties();
		properties.setPerimeterUrl(perimeterUrl);
		properties.setCookieSameSite(propertySameSite);
		var result = OidcSessionSupport.getCookieSameSite(Optional.ofNullable(client), request, properties);
		assertThat(result, is(expected));
	}

	static Object[][] testGetCookieSameSite() {
		return new Object[][] {
				{ false, null, null, null, null, null, null },
				{ false, null, null, null, null, WebUtil.COOKIE_SAME_SITE_LAX,
						WebUtil.COOKIE_SAME_SITE_LAX }, // fallback propertySameSite
				{ false, null, "https://sub.trustbroker.swiss", null, "https://auth.trustbroker.swiss", null,
						WebUtil.COOKIE_SAME_SITE_STRICT }, // same site redirectUrl
				{ true, null, "https://localhost", "https://sub.trustbroker.swiss", "https://auth.trustbroker.swiss", null,
						WebUtil.COOKIE_SAME_SITE_STRICT }, // same site logoutRedirectUrl
				{ true, null, null, "https://sub.trustbroker.swiss", "https://auth.trustbroker.swiss",
						WebUtil.COOKIE_SAME_SITE_DYNAMIC, WebUtil.COOKIE_SAME_SITE_STRICT }, // same site logoutRedirectUrl
				{ false, null, "https://localhost", null, "https://auth.trustbroker.swiss", WebUtil.COOKIE_SAME_SITE_LAX,
						WebUtil.COOKIE_SAME_SITE_NONE }, // cross site redirectUrl
				{ true, WebUtil.COOKIE_SAME_SITE_LAX, "https://localhost", null, "https://localhost", null,
						WebUtil.COOKIE_SAME_SITE_LAX }, // client policySameSite
		};
	}

	@Test
	void testCreateOidcClientCookie() {
		var request = new MockHttpServletRequest();
		var properties = new TrustBrokerProperties();
		var oidc = new OidcProperties();
		oidc.setSessionCookie(false);
		properties.setOidc(oidc);
		var clientId = "client-1";
		var client = OidcClient.builder().id(clientId).build();
		var ttlMinutes = 10;
		int ttlSecs = ttlMinutes * 60;
		var httpOnly = true;
		var name = OidcSessionSupport.OIDC_SESSION_COOKIE_NAME_PREFIX + "CLIENT-1";
		client.getOidcSecurityPolicies().setSessionTimeToLiveMin(ttlMinutes);
		client.getOidcSecurityPolicies().setSessionCookieSameSite(WebUtil.COOKIE_SAME_SITE_LAX);
		var cookieValue = "session1";
		doReturn(Optional.of(client)).when(relyingPartyDefinitions).getOidcClientConfigById(clientId, properties);

		var cookie = OidcSessionSupport.createOidcCookie(clientId, name, cookieValue, httpOnly,
				request, relyingPartyDefinitions, properties);

		assertThat(cookie.getName(), is(name));
		assertThat(cookie.getValue(), is(cookieValue));
		assertThat(cookie.getMaxAge(), is(ttlSecs));
		assertThat(cookie.isHttpOnly(), is(httpOnly));
		assertThat(cookie.getSecure(), is(true));
		assertThat(cookie.getDomain(), is(nullValue()));
		assertThat(cookie.getPath(), is("/"));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(WebUtil.COOKIE_SAME_SITE_LAX));

		var cookie2 = OidcSessionSupport.createOidcClientCookie(clientId, cookieValue, ttlSecs, true,
				WebUtil.COOKIE_SAME_SITE_LAX);

		assertThat(cookie2, is(equalTo(cookie)));

		var cookie3 = OidcSessionSupport.createOidcSsoSessionCookie(clientId, cookieValue,
				request, relyingPartyDefinitions, properties);

		assertThat(cookie3.getName(), is(OidcSessionSupport.OIDC_SSO_SESSION_COOKIE_NAME_PREFIX + clientId));
		assertThat(cookie3.getValue(), is(cookieValue));
		assertThat(cookie3.getMaxAge(), is(ttlSecs));
		assertThat(cookie3.isHttpOnly(), is(false));  // fixed value
		assertThat(cookie3.getSecure(), is(true));
		assertThat(cookie3.getDomain(), is(nullValue()));
		assertThat(cookie3.getPath(), is("/"));
		assertThat(cookie3.getAttribute(WebUtil.COOKIE_SAME_SITE), is(WebUtil.COOKIE_SAME_SITE_LAX));

	}

	@Test
	void testGetSsoStateDataForClientFromSession() {
		var stateData = givenSsoState(Collections.emptySet());
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		HttpExchangeSupport.begin(request, response);
		HttpExchangeSupport.getRunningHttpExchange().setSsoState(stateData);
		var relyingParty = givenRelyingParty(null);

		var result = OidcSessionSupport.getSsoStateDataForClient(ssoService, request, relyingParty, OIDC_CLIENT_ID);

		assertThat(result, is(stateData));
		verifyNoInteractions(ssoService);
	}

	@Test
	void testAcrValuesStepup() {
		var request = new MockHttpServletRequest();
		var session = new TomcatSession(null);
		session.setStateData(StateData.builder().id("1").build());
		request.setSession(session);
		assertThat(OidcSessionSupport.isAcrValuesStepUpRequired(request, session, "TestClient"), is(false));
		request.setParameter("acr_values", "acr1 acr2");
		OidcSessionSupport.rememberAcrValues(request);
		assertThat(OidcSessionSupport.isAcrValuesStepUpRequired(request, session, "TestClient"), is(false));
		request.setParameter("acr_values", "acr3");
		assertThat(OidcSessionSupport.isAcrValuesStepUpRequired(request, session, "TestClient"), is(true));
	}

	@ParameterizedTest
	@MethodSource
	void testGetSsoStateDataForClientFromSso(Set<SsoSessionParticipant> participants1,
			Set<SsoSessionParticipant> participants2, boolean expectState) {
		var stateData1 = givenSsoState(participants1);
		var stateData2 = givenSsoState(participants2);
		var request = new MockHttpServletRequest();
		var relyingParty = givenRelyingParty(null);
		var cookie = new Cookie("session", "sid1");
		request.setCookies(cookie);

		doReturn(List.of(stateData1, stateData2)).when(ssoService)
												 .findValidStatesFromCookies(relyingParty, new Cookie[] { cookie });

		var result = OidcSessionSupport.getSsoStateDataForClient(ssoService, request, relyingParty, OIDC_CLIENT_ID);

		if (expectState) {
			assertThat(result, is(stateData1));
		}
		else {
			assertThat(result, is(nullValue()));
		}
	}

	static Object[][] testGetSsoStateDataForClientFromSso() {
		return new Object[][] {
				// no matching participant:
				{
					Collections.emptySet(),
					Collections.emptySet(),
					false
				},
				// single matching participant:
				{
					Set.of(SsoSessionParticipant.builder().oidcSessionId("osid").oidcClientId(OIDC_CLIENT_ID).build()),
					Collections.emptySet(),
					true
				},
				// multiple matching participants:
				{
					Set.of(SsoSessionParticipant.builder().oidcSessionId("osid1").oidcClientId(OIDC_CLIENT_ID).build()),
					Set.of(SsoSessionParticipant.builder().oidcSessionId("osid2").oidcClientId(OIDC_CLIENT_ID).build()),
					false
				}
		};
	}

	private static StateData givenSsoState(Set<SsoSessionParticipant> ssoParticipants) {
		var stateData = StateData.builder()
								 .id("SessionId1")
								 .lifecycle(Lifecycle.builder().lifecycleState(LifecycleState.ESTABLISHED).build())
								 .build();
		stateData.initializedSsoState().setSsoParticipants(ssoParticipants);
		return stateData;
	}

	private static RelyingParty givenRelyingParty(String id) {
		return RelyingParty.builder()
						   .id(id != null ? id : "rp1")
						   .build();
	}

	private String givenToken(String clientId) throws JOSEException {
		var rsa = new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS).keyID("kid1").generate();
		var signer = new RSASSASigner(rsa);
		var claimsSet = new JWTClaimsSet.Builder()
				.subject("testuser")
				.issuer("http://localhost:8080")
				.audience(clientId)
				.claim("sid", "SESS-JWT-SID") // LATER
				.claim("session_state", "SESS-JWT-STATE") // LATER
				.expirationTime(new Date(new Date().getTime() + 60 * 1000))
				.build();
		var signedJwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.getKeyID()).build(),
				claimsSet);
		signedJwt.sign(signer);
		return signedJwt.serialize();
	}

}
