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

package swiss.trustbroker.sso.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static swiss.trustbroker.util.SessionTimeConfiguration.EXPIRATION_INSTANT_SSO;
import static swiss.trustbroker.util.SessionTimeConfiguration.START_INSTANT;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.FingerprintCheck;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.SloMode;
import swiss.trustbroker.federation.xmlconfig.SloProtocol;
import swiss.trustbroker.federation.xmlconfig.SloResponse;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.SsoParticipant;
import swiss.trustbroker.saml.dto.SsoParticipants;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.dto.SloNotification;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.SessionTimeConfiguration;

@SpringBootTest
@ContextConfiguration(classes = { SessionTimeConfiguration.class, SsoService.class, AssertionConsumerService.class})
class SsoServiceTest {

	private static final String ACS = "acs";

	private static final String OIDC_PREFIX = "oidc_";

	private static final String SLO_URL = "https://slo1.localdomain";

	private static final String SLO_URL_ENCODED = "https&#x3a;&#x2f;&#x2f;slo1.localdomain";

	private enum MockQoa {

		MOBILE_ONE_FACTOR_UNREGISTERED(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, 10),
		PASSWORD_PROTECTED_TRANSPORT(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, 20),
		SOFTWARE_TIME_SYNC_TOKEN(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN, 30),
		NOMAD_TELEPHONY(SamlContextClass.NOMAD_TELEPHONY, 30),
		KERBEROS(SamlContextClass.KERBEROS, 40),
		SOFTWARE_PKI(SamlContextClass.SOFTWARE_PKI, 50),
		MOBILE_TWO_FACTOR_CONTACT(SamlContextClass.MOBILE_TWO_FACTOR_CONTACT, 50),
		TIME_SYNC_TOKEN(SamlContextClass.TIME_SYNC_TOKEN, 50),
		SMART_CARD_PKI(SamlContextClass.SMART_CARD_PKI, 60),
		UNSPECIFIED(SamlContextClass.UNSPECIFIED, -1),
		STRONGEST_POSSIBLE("urn:qoa:strongest_possible", -2),
		AUTH_LEVEL_NORMAL("auth:normal", 30),
		AUTH_LEVEL_STRONG("auth:strong", 50);

		private final String name;

		private final int order;

		MockQoa(String name, int order) {
			this.name = name;
			this.order = order;
		}

		public String getName() {
			return name;
		}

		public int getOrder() {
			return order;
		}

		static MockQoa forLevel(int order) {
			if (order <= UNSPECIFIED.order) {
				return UNSPECIFIED;
			}
			var result = Arrays.stream(MockQoa.values())
					.filter(qoa -> qoa.getOrder() == order)
					.findFirst();
			return result.orElse(UNSPECIFIED);
		}

		static MockQoa forName(String name) {
			if (name == null) {
				return UNSPECIFIED;
			}
			var result = Arrays.stream(MockQoa.values())
					.filter(qoa -> qoa.getName().equals(name))
					.findFirst();
			return result.orElse(UNSPECIFIED);
		}
	}

	private static final String DEVICE_ID = "deviceId";

	private static final String SESSION_ID = "sessionId";

	private static final String RELYING_PARTY_ID = "relyingParty1";

	private static final String OTHER_RELYING_PARTY_ID = "relyingParty2";

	private static final String CP_ISSUER_ID = "issuerId";

	private static final String CP_IMG = "cpImg";

	private static final String CP_SHORTCUT = "cpShortcut";

	private static final String CP_COLOR = "cpColor";

	private static final String AUTHN_REQUEST_ID = "authId";

	private static final String SSO_GROUP = "SSO.Group.Name";

	private static final String SUBJECT_NAME_ID = "Subject.NameID";

	private static final String CP_ISSUER_ID_COOKIE = "CP.Issuer.ID";

	private static final String ISSUER = "xtb";

	private static final String OIDC_SESSION_ID = "oidcSession1";

	private static final String ACS_URL = "https://localhost/acs";

	private static final String ISS_SID_ENCODED = "&#x3f;iss&#x3d;" + ISSUER + "&amp;sid&#x3d;" + OIDC_SESSION_ID;

	private static final String ACS_URL_ENCODED = "https&#x3a;&#x2f;&#x2f;localhost&#x2f;acs";

	private static final String PERIMERTER_URL = "https://login.trustbroker.swiss/auth";

	private static final String MISMATCH_ACS_URL = "https://other.localdomain/acs";

	private static final String DESTINATION = "https://localhost/dest";

	private static final String DESTINATION_ENCODED = "https&#x3a;&#x2f;&#x2f;localhost&#x2f;dest";

	private static final String PREFIXED_SSO_GROUP = SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX + SSO_GROUP;

	// Python: base64.b64encode(hashlib.sha256(b"SSO.Group.Name_CP|CP.Issuer.ID|Subject.NameID").digest()).replace("/", "_")
	private static final String COOKIE_NAME =
			PREFIXED_SSO_GROUP + '_' + CP_ISSUER_ID_COOKIE + "_nsASW3ZO4H3p9cmztv3q2Tpao2iNyiDn7EMjxhRFxnI";

	private static final String SESSION_INDEX = "sessionIndex1";

	// alternative cookie with same RP/CP but different subject
	// Python: base64.b64encode(hashlib.sha256(b"SSO.Group.Name|CP.Issuer.ID|Alt.Subject.NameID").digest()).replace("/", "_")
	private static final String COOKIE_NAME_WITH_ALT_SUBJECT =
			PREFIXED_SSO_GROUP + '_' + CP_ISSUER_ID_COOKIE + "_9M6UOVrmuebvR73cA6010xZp+1TnjuIEF4dgkf+AE1Q";

	// Python: base64.b64encode(hashlib.sha256(b"SSO.Group.Name_CP|issuerId|Subject.NameID").digest()).replace("/", "_")
	private static final String COOKIE_NAME_WITH_CP =
			PREFIXED_SSO_GROUP + '_' + CP_ISSUER_ID + "__1LYhTzirnofz_UT5dI9Nyns1MFwsozo6fQkTzHHCvc";

	private static final String COOKIE_NAME_IMPLICIT = PREFIXED_SSO_GROUP; // name in session

	private static final SsoService.SsoCookieNameParams SSO_GROUP_PARAMS = SsoService.SsoCookieNameParams.of(SSO_GROUP);

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	private StateCacheService stateCacheService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private Element mockSignature;

	// for AssertionConsumerService:
	@MockitoBean
	private ScriptService scriptService;

	// for AssertionConsumerService:
	@MockitoBean
	private AuditService auditService;

	// for AssertionConsumerService:
	@MockitoBean
	private AnnouncementService announcementService;

	// for AssertionConsumerService:
	@MockitoBean
	private HrdService hrdService;

	@MockitoBean
	private QoaMappingService qoaService;

	@Autowired
	private AssertionConsumerService assertionConsumerService;

	@Autowired
	private Clock clock;

	@Autowired
	private SsoService ssoService;

	@BeforeAll
	static void setUp() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void generateCookieWithGroup() {
		var lifeTime = 1000;
		Cookie cookie = ssoService.generateCookie(SSO_GROUP_PARAMS, SESSION_ID, lifeTime, true, WebUtil.COOKIE_SAME_SITE_STRICT);
		validateCookie(cookie, true, PREFIXED_SSO_GROUP, lifeTime, SESSION_ID, WebUtil.COOKIE_SAME_SITE_STRICT);
	}

	@Test
	void generateCookieWithFullName() {
		var lifeTime = 10000;
		var sessionId = "anotherSessionId";
		Cookie cookie = ssoService.generateCookie(buildCookieParams(), sessionId, lifeTime, false, WebUtil.COOKIE_SAME_SITE_NONE);
		validateCookie(cookie, false, COOKIE_NAME, lifeTime, sessionId, WebUtil.COOKIE_SAME_SITE_NONE);
	}

	@ParameterizedTest
	@MethodSource
	void generateCookieWithFullNameFromState(boolean sessionCookie, boolean implicit) {
		var lifeTime = 10000;
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var secure = true;
		ssoStateData.getSsoState().setMaxSessionTimeSecs(lifeTime);
		ssoStateData.getSsoState().setImplicitSsoGroup(implicit);
		ssoStateData.setIssuer(CP_ISSUER_ID);
		ssoStateData.setSubjectNameId(SUBJECT_NAME_ID);
		doReturn(sessionCookie).when(trustBrokerProperties).isUseSessionCookieForSso();
		doReturn(secure).when(trustBrokerProperties).isSecureBrowserHeaders();
		var ssoGroup = buildSsoGroup();
		doReturn(ssoGroup).when(relyingPartySetupService).getSsoGroupConfig(SSO_GROUP);
		var cookie = ssoService.generateCookie(ssoStateData);
		validateCookie(cookie, secure, implicit ? COOKIE_NAME_IMPLICIT : COOKIE_NAME_WITH_CP, sessionCookie ? -1 : lifeTime,
				SESSION_ID, WebUtil.COOKIE_SAME_SITE_NONE);
		var expiredCookie = ssoService.generateExpiredCookie(ssoStateData);
		validateCookie(expiredCookie, secure, implicit ? COOKIE_NAME_IMPLICIT : COOKIE_NAME_WITH_CP, 0, "", null);
	}

	static Boolean[][] generateCookieWithFullNameFromState() {
		return new Boolean[][] {
			{ false, true }, { true, false } // unrelated flags, no need for all combinations
		};
	}

	private static void validateCookie(Cookie cookie, boolean secure, String implicit, int sessionCookie, String sessionId,
			String sameSite) {
		assertThat(cookie.getSecure(), is(secure));
		assertThat(cookie.getName(), is(implicit));
		assertThat(cookie.getMaxAge(), is(sessionCookie)); // lifeTime is considered reflecting SSO lifetime
		assertThat(cookie.getValue(), is(sessionId));
		assertThat(cookie.isHttpOnly(), is(true));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(sameSite));
	}

	@Test
	void findValidStateFromCookiesWithGroupNoStateData() {
		doReturn(Optional.empty()).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SSO_GROUP_PARAMS, cookies, null);
		assertThat(state.isPresent(), is(false));
	}

	@Test
	void findValidStateFromCookiesWithGroupNoSpStateData() {
		var stateData = StateData.builder().id(SESSION_ID).build();
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SSO_GROUP_PARAMS, cookies, null);
		assertThat(state.isPresent(), is(false));
	}

	@Test
	void findValidStateFromCookiesWithGroup() {
		buildStateWithSpState(SESSION_ID);
		var cookies = new Cookie[] {
				new Cookie("unrelated", "whatever"),
				new Cookie(COOKIE_NAME, SESSION_ID),
				new Cookie("foo", "bar")
		};
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SSO_GROUP_PARAMS, cookies, null);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateFromCookiesWithAnyGroup() {
		buildStateWithSpState(SESSION_ID);
		var cookies = new Cookie[] {
				new Cookie(SSO_GROUP, "wrong"),
				new Cookie(COOKIE_NAME, SESSION_ID),
				new Cookie("foo", "bar")
		};
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SsoService.SsoCookieNameParams.ANY, cookies, null);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateFromCookiesWithImplicitGroup() {
		var rpId = "https://example.trustbroker.swiss/rp1";
		var rp = buildRelyingParty(rpId, false);
		var stateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(rpId));
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookieParams = ssoService.getCookieImplicitSsoGroupName(rp);
		var cookieName = ssoService.generateCookieName(cookieParams, false);
		assertThat(cookieName, matchesPattern("[^:/]*[.][^:/]*")); // character replacement
		var cookies = new Cookie[] { new Cookie(cookieName, SESSION_ID) };
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(rp, cookies);
		assertThat(state.isPresent(), is(true));
	}

	@Test
	void findValidStateFromCookiesWithImplicitGroupFallbackToSso() {
		var rp = buildRelyingParty(RELYING_PARTY_ID, true);
		var cp = buildClaimsParty(CP_ISSUER_ID_COOKIE);
		var stateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		// existing regular SSO session, but not implicit cookie
		var cookieParams = ssoService.getCookieSsoGroupName(rp, cp);
		var cookieName = ssoService.generateCookieName(cookieParams, false);
		var cookies = new Cookie[] { new Cookie(cookieName, SESSION_ID) };
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(rp, cookies);
		assertThat(state.isPresent(), is(true));
	}

	@Test
	void getFullSsoGroupName() {
		var name = SsoService.SsoCookieNameParams.of("").getFullSsoGroupName();
		assertThat(name, is(""));
		name = SsoService.SsoCookieNameParams.of("", CP_ISSUER_ID_COOKIE, SUBJECT_NAME_ID).getFullSsoGroupName();
		assertThat(name, is(""));
		name = SsoService.SsoCookieNameParams.of(SSO_GROUP, CP_ISSUER_ID_COOKIE, null).getFullSsoGroupName();
		assertThat(name, is(SSO_GROUP + '_' + CP_ISSUER_ID_COOKIE));
		name = SsoService.SsoCookieNameParams.of(SSO_GROUP, CP_ISSUER_ID_COOKIE, SUBJECT_NAME_ID).getFullSsoGroupName();
		assertThat(name, is(SSO_GROUP + '_' + CP_ISSUER_ID_COOKIE));
	}

	@Test
	void findValidStateFromCookiesWithFullName() {
		var stateData = buildStateWithSpState(SESSION_ID);
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookies = new Cookie[] {
				new Cookie(PREFIXED_SSO_GROUP + "_other", SESSION_ID),
				new Cookie("other.sso", "session"),
				new Cookie(COOKIE_NAME, SESSION_ID),
				new Cookie("something", "else")
		};
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(buildCookieParams(), cookies, null);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateFromCookiesWithSubject() {
		var stateData = buildStateWithSpState(SESSION_ID);
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookies = new Cookie[] {
				new Cookie(COOKIE_NAME_WITH_ALT_SUBJECT, "altSessionId"),
				new Cookie(COOKIE_NAME, SESSION_ID)
		};
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID_COOKIE);
		var state = ssoService.findValidStateFromCookies(rp, cp, SUBJECT_NAME_ID, cookies);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateFromCookiesWithRpCp() {
		var stateData = buildStateWithSpState(SESSION_ID);
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var cookies = new Cookie[] {
				new Cookie("other.sso", "session"),
				new Cookie(PREFIXED_SSO_GROUP + '_' + CP_ISSUER_ID, SESSION_ID)
		};

		var relyingParty = buildRelyingParty(true);
		relyingParty.getSso().setGroupName(SSO_GROUP);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var state = ssoService.findValidStateFromCookies(relyingParty, claimsParty, cookies);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateFromCookiesWithGroupEncoded() {
		buildStateWithSpState(SESSION_ID);
		// ^ is technically valid for a cookie name (so Cookie accepts it), but we encode it to _
		var groupNameToBeEncoded = "SSO^Group";
		var cookies = new Cookie[] {
				new Cookie(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX + groupNameToBeEncoded, "invalid"),
				new Cookie(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX + "SSO_Group", SESSION_ID)
		};
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SsoService.SsoCookieNameParams.of(groupNameToBeEncoded), cookies, null);
		assertThat(state.isPresent(), is(true));
		assertThat(state.get().getId(), is(SESSION_ID));
	}

	@Test
	void findValidStateNoCookies() {
		var state = ssoService.findValidStateFromCookiesAndRelyingParty(SsoService.SsoCookieNameParams.of(SSO_GROUP, null, null), null, null);
		assertThat(state.isPresent(), is(false));
	}

	@Test
	void findAllValidStatesFromCookies() {
		var sessionId1 = "sessionId1";
		var stateData1 = buildStateWithSpState(sessionId1);
		var sessionId2 = "sessionId2";
		var stateData2 = buildStateWithSpState(sessionId2);
		var cookies = new Cookie[] {
				new Cookie(PREFIXED_SSO_GROUP + "_other", sessionId1),
				new Cookie("other.sso", "session"),
				new Cookie(COOKIE_NAME, sessionId2),
				new Cookie("something", "else")
		};
		var states = ssoService.findAllValidStatesFromCookies(cookies);
		assertThat(states.size(), is(2));
		assertThat(states, containsInAnyOrder(stateData1, stateData2));
	}

	@Test
	void findAllValidStatesNoCookies() {
		var state = ssoService.findAllValidStatesFromCookies(null);
		assertThat(state.size(), is(0));
	}

	@Test
	void filterStatesTest() {
		var stateData = buildStateWithSpState(SESSION_ID);
		var relyingParty = buildRelyingParty(true);
		var rpId = relyingParty.getId();

		assertTrue(ssoService.filterStates(relyingParty).apply(Collections.emptyMap()).isEmpty());

		stateData.getSpStateData().setIssuer(rpId);
		assertTrue(ssoService.filterStates(relyingParty).apply(Map.of("any", stateData)).isPresent());

		stateData.getSpStateData().setIssuer(rpId + "x");
		stateData.setSsoState(SsoState.builder().ssoParticipants(Set.of(SsoSessionParticipant.builder().rpIssuerId(rpId).build())).build());
		assertTrue(ssoService.filterStates(relyingParty).apply(Map.of("any", stateData)).isPresent());

		stateData = buildStateWithSpState(SESSION_ID);
		stateData.getSpStateData().setIssuer(rpId + "x");
		assertTrue(ssoService.filterStates(relyingParty).apply(Map.of("any", stateData)).isEmpty());

		var claimsProvider = ClaimsProvider.builder().relyingPartyAlias(rpId + "x").build();
		var claimsProviderMappings = ClaimsProviderMappings.builder().claimsProviderList(List.of(claimsProvider)).build();
		relyingParty.setClaimsProviderMappings(claimsProviderMappings);
		assertTrue(ssoService.filterStates(relyingParty).apply(Map.of("any", stateData)).isPresent());
	}

	private static SsoService.SsoCookieNameParams buildCookieParams() {
		return SsoService.SsoCookieNameParams.of(SSO_GROUP, CP_ISSUER_ID_COOKIE, SUBJECT_NAME_ID);
	}

	private StateData buildStateWithSpState(String sessionId) {
		var spStateData = StateData.builder()
				.id(AUTHN_REQUEST_ID)
				.lastConversationId(AUTHN_REQUEST_ID)
				.issuer(RELYING_PARTY_ID)
				.assertionConsumerServiceUrl(ACS + RELYING_PARTY_ID)
				.build();
		var stateData = StateData.builder().id(sessionId)
				.ssoSessionId("sso-test")
				.cpResponse(CpResponse.builder().issuer("Test-CP-Issuer-ID").build())
				.spStateData(spStateData).build();
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(sessionId, SsoService.class.getSimpleName());
		return stateData;
	}

	private static StateData buildStateWithDeviceId(String deviceId) {
		return StateData.builder().id(SESSION_ID).deviceId(deviceId).build();
	}

	private static CpResponse buildCpResponseWithContextClasses(List<String> contextClasses) {
		return CpResponse.builder().contextClasses(contextClasses).build();
	}

	private static StateData buildStateWithCpResponseContextClasses(List<String> contextClasses) {
		var cpResponse = buildCpResponseWithContextClasses(contextClasses);
		return StateData.builder().id(SESSION_ID).cpResponse(cpResponse).build();
	}

	private StateData buildStateForAuthnRequest(AuthnRequest authnRequest) {
		// this state is just a container for what is read in SSOService.skipCpAuthentication, everything else does not matter
		var stateData = buildStateWithSpState(authnRequest.getID());
		stateData.getSpStateData().setId(authnRequest.getID());
		stateData.getSpStateData().setContextClasses(OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest));
		stateData.setSignedAuthnRequest(authnRequest.isSigned());
		stateData.setSignedAuthnRequest(true);
		return stateData;
	}

	private StateData buildStateForSso(String sessionId, String deviceId, Set<String> ssoRps) {
		var stateData = buildStateWithSpState(sessionId);
		stateData.setDeviceId(deviceId);
		var ssoState = stateData.initializedSsoState();
		if (ssoRps != null) {
			var ssoParticipants = buildSsoParticipants(ssoRps);
			ssoState.setSsoParticipants(ssoParticipants);
		}
		ssoState.setSsoGroupName(SSO_GROUP);
		stateData.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		stateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(clock.instant()));
		// same for CP request and response
		stateData.setIssuer(CP_ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().issuer(CP_ISSUER_ID).build());
		doReturn(Optional.of(stateData)).when(stateCacheService).findValidState(sessionId, SsoService.class.getSimpleName());
		return stateData;
	}

	private static Set<SsoSessionParticipant> buildSsoParticipants(Set<String> ssoRps) {
		return ssoRps.stream()
				.map(SsoServiceTest::buildSsoSessionParticipant)
				.collect(Collectors.toSet());
	}

	private static SsoSessionParticipant buildSsoSessionParticipant(String relyingPartyId) {
		var result = SsoSessionParticipant.builder()
										  .cpIssuerId(CP_ISSUER_ID)
										  .assertionConsumerServiceUrl(ACS + relyingPartyId)
										  .build();
		if (relyingPartyId.startsWith("oidc")) {
			result.setOidcClientId(relyingPartyId);
		}
		else {
			result.setRpIssuerId(relyingPartyId);
		}
		return result;
	}

	private static Set<SsoSessionParticipant> buildSsoParticipantsByAcUrls(Set<String> acUrls) {
		return acUrls.stream()
				.map(acUrl -> new SsoSessionParticipant(RELYING_PARTY_ID, CP_ISSUER_ID, acUrl, null, null))
				.collect(Collectors.toSet());
	}

	private static SsoState buildSsoStateByAcUrls(String ssoGroupName, Set<String> acUrls) {
		return SsoState.builder()
					   .ssoParticipants(buildSsoParticipantsByAcUrls(acUrls))
					   .ssoGroupName(ssoGroupName)
					   .build();
	}

	private static StateData buildStateDataByAuthnReq() {
		var spStateData = StateData.builder()
				.id(AUTHN_REQUEST_ID)
				.issuer(RELYING_PARTY_ID)
				.referer("https://localhost")
				.lastConversationId(AUTHN_REQUEST_ID)
				.assertionConsumerServiceUrl(ACS + RELYING_PARTY_ID)
				.build();
		return StateData.builder()
				.id(SESSION_ID)
				.issuer(CP_ISSUER_ID)
				.spStateData(spStateData)
				.signedAuthnRequest(true)
				.build();
	}

	private ClaimsProvider mockClaimsProvider(String issuerId) {
		var claimsParty =
				ClaimsProvider.builder().id(issuerId).img(CP_IMG).shortcut(CP_SHORTCUT).color(CP_COLOR).build();
		doReturn(claimsParty).when(relyingPartySetupService).getClaimsProviderById(any(), eq(CP_ISSUER_ID));
		return claimsParty;
	}

	private RelyingParty buildRelyingParty(String id, boolean ssoEnabled) {
		return RelyingParty.builder()
				.id(id)
				.sso(Sso.builder().enabled(ssoEnabled).groupName(ssoEnabled ? SSO_GROUP : null).build())
				.securityPolicies(SecurityPolicies.builder().build())
				.qoa(mockRpQoa())
				.build();
	}

	private Qoa mockRpQoa() {
		return Qoa.builder()
				  .classes(List.of(
						  AcClass.builder()
								 .order(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel())
								 .contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName())
								 .build()))
				  .build();
	}

	private RelyingParty buildRelyingParty(boolean ssoEnabled) {
		return buildRelyingParty(RELYING_PARTY_ID, ssoEnabled);
	}

	private ClaimsParty buildClaimsParty(String issuerId) {
		return ClaimsParty.builder()
				.id(issuerId)
				.build();
	}

	private static SsoGroup buildSsoGroup() {
		return SsoGroup.builder()
					   .maxCachingTimeMinutes(2)
					   .maxIdleTimeMinutes(1)
					   .maxSessionTimeMinutes(3)
					   .name(SSO_GROUP)
					   .build();
	}

	private static SsoGroup buildSsoGroup(String name, String sessionCookieSameSite) {
		return SsoGroup.builder()
					   .name(name)
					   .sessionCookieSameSite(sessionCookieSameSite)
					   .build();
	}

	private AuthnRequest buildAuthnRequest(String issuerId, String id, boolean signed) {
		var authnRequest = new AuthnRequestBuilder().buildObject();
		authnRequest.setIssuer(new IssuerBuilder().buildObject());
		authnRequest.getIssuer().setValue(issuerId);
		authnRequest.setID(id);
		authnRequest.setRequestedAuthnContext(new RequestedAuthnContextBuilder().buildObject());
		if (signed) {
			// last step, other setters can clear dom
			mockedSignatureDom(authnRequest);
		}
		return authnRequest;
	}

	private void mockedSignatureDom(AuthnRequest authnRequest) {
		// make AbstractSignableXMLObject.isSigned true (avoids having to build the whole signature)
		doReturn(Node.ELEMENT_NODE).when(mockSignature).getNodeType();
		doReturn(SignatureConstants.XMLSIG_NS).when(mockSignature).getNamespaceURI();
		doReturn(Signature.DEFAULT_ELEMENT_LOCAL_NAME).when(mockSignature).getLocalName();
		doReturn(mockSignature).when(mockSignature).getFirstChild();
		authnRequest.setDOM(mockSignature);
		assertThat(authnRequest.isSigned(), is(true));
	}

	@Test
	void validFingerprint() {
		for (var fingerprintCheck : FingerprintCheck.values()) {
			var stateData = buildStateWithDeviceId(DEVICE_ID);
			var result = ssoService.validateFingerprint(DEVICE_ID, stateData, fingerprintCheck);
			assertThat(result, is(true));
		}
	}

	@ParameterizedTest
	@CsvSource(value = {
			"deviceId,,STRICT,false",
			"deviceId,null,STRICT,false",
			"null,incoming,STRICT,false",
			"deviceId,incoming,STRICT,false",
			"deviceId,incoming,OPTIONAL,true",
			"one.two.three,one.two.three,LAX,true",
			"one.wrong.other,one.two.three,LAX,true",
			"other.wrong.three,one.two.three,LAX,true",
			"null,null,LAX,false",
			",,LAX,false",
			"one,null,LAX,false",
			"null,one,LAX,false",
			"deviceId,incoming,LAX,false",
			"one.two,one.two.three,LAX,false"
	}, nullValues = "null")
	void fingerprintMismatch(String deviceId, String incomingDeviceId, FingerprintCheck fingerprintCheck, boolean expected) {
		var stateData = buildStateWithDeviceId(deviceId);
		var result = ssoService.validateFingerprint(incomingDeviceId, stateData, fingerprintCheck);
		assertThat(result, is(expected));
	}

	@Test
	void noQuaContextClass() {
		var stateData = buildStateWithCpResponseContextClasses(List.of("foo", "bar", "somethingElse"));
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		var qoaConfig = mockQoaConfig();
		mockQoaService(null, null, qoaConfig, null);
		var result = ssoService.getQoaLevelFromContextClassesOrAuthLevel(stateData, new QoaConfig(qoaConfig, "testId"));
		assertThat(result.getName(), is(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED));
	}

	@Test
	void singleQuaContextClass() {
		var qoa20 = getQoa(20);
		var stateData = buildStateWithCpResponseContextClasses(List.of("foo", qoa20, "bar"));
		var qoaConfig = mockQoaConfig();
		mockQoaService(null, null, qoaConfig, null);
		var result = ssoService.getQoaLevelFromContextClassesOrAuthLevel(stateData,  new QoaConfig(qoaConfig, "testId"));
		assertThat(result.getName(), is(qoa20));
	}

	@Test
	void singleMultipleContextClasses() {
		var qoa9 = getQoa(9); // check that implementation doesn't rely on two digits
		var qoa20 = getQoa(20);
		var qoa30 = getQoa(30);
		var qoa40 = getQoa(40);
		var qoaConfig = mockQoaConfig();
		mockQoaService(null, null, qoaConfig, null);
		var stateData = buildStateWithCpResponseContextClasses(
				List.of("foo", qoa30, qoa40, qoa9, qoa20, "bar"));
		var result = ssoService.getQoaLevelFromContextClassesOrAuthLevel(stateData,  new QoaConfig(qoaConfig, "testId"));
		assertThat(result.getName(), is(qoa40));
	}

	private static String getQoa(Integer value) {
		return value != null ? MockQoa.forLevel(value).getName() : null;
	}

	private static CustomQoa getQoaCustom(Integer value) {
		if (value != null) {
			MockQoa mockQoa = MockQoa.forLevel(value);
			return new CustomQoa(mockQoa.getName(), value);
		}
		else {
			return CustomQoa.UNDEFINED_QOA;
		}
	}

	@Test
	void getSsoGroupNameNoSso() {
		var relyingParty = RelyingParty.builder().build();
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var result = ssoService.getCookieSsoGroupName(relyingParty, claimsParty);
		assertThat(result,
				is(SsoService.SsoCookieNameParams.of(SsoService.SsoCookieNameParams.DEFAULT_SSO_GROUP, CP_ISSUER_ID, null)));
	}

	@Test
	void getSsoGroupNameSsoDisabled() {
		var sso = Sso.builder().enabled(false).build();
		var relyingParty = RelyingParty.builder().sso(sso).build();
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var result = ssoService.getCookieSsoGroupName(relyingParty, claimsParty);
		assertThat(result,
				is(SsoService.SsoCookieNameParams.of(SsoService.SsoCookieNameParams.DEFAULT_SSO_GROUP, CP_ISSUER_ID, null)));
	}

	@Test
	void getSsoGroupNameSsoEmptyGroup() {
		var sso = Sso.builder().enabled(true).groupName("").build();
		var relyingParty = RelyingParty.builder().sso(sso).build();
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var result = ssoService.getCookieSsoGroupName(relyingParty, claimsParty);
		assertThat(result,
				is(SsoService.SsoCookieNameParams.of(SsoService.SsoCookieNameParams.DEFAULT_SSO_GROUP, CP_ISSUER_ID, null)));
	}

	@Test
	void encodeCookieName() {
		// XTB_COOKIE_PREFIX must not change when encoding, we search by the prefix
		var result = ssoService.encodeCookieName(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX +
				"group-Name_https://cp.urn?replace=()[]{}<>@,;\\\"");
		assertThat(result, is(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX +
				"group-Name_https___cp.urn_replace______________"));
	}

	@Test
	void generateCookieName() {
		var result = ssoService.generateCookieName(SsoService.SsoCookieNameParams.of("SSO_Group-Name"), true);
		assertThat(result, is(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX + "SSO_Group-Name"));
	}

	@Test
	void generateCookieNameFull() {
		var cpId = "http://cp.urn/?a=b";
		var result = ssoService.generateCookieName(
				SsoService.SsoCookieNameParams.of("SSO_Group-Name", cpId,"me@test"),false);
		// Python: base64.b64encode(hashlib.sha256(b"SSO_Group-Name|http://cp.urn/?a=b|me@test").digest()).replace("/", "_")
		assertThat(result, is(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX +
				"SSO_Group-Name_http___cp.urn__a_b_qmw5VsQtBKRr6As0ZsbcMMjYT95dbHnXek4vfmLnQ3g"));
	}

	@Test
	void generateCookieNameFullGroupOnly() {
		var result = ssoService.generateCookieName(
				SsoService.SsoCookieNameParams.of("Group.name", "http://a.org","subject"),true);
		assertThat(result, is(SsoService.SsoCookieNameParams.XTB_COOKIE_PREFIX +
				"Group.name_http___a.org"));
	}

	@Test
	void getSsoGroupNameSsoNotYetEncoded() {
		var groupName = "group-Name";
		var sso = Sso.builder().enabled(true).groupName(groupName).build();
		var cpId = "https://cp.urn";
		var claimsParty = buildClaimsParty(cpId);
		var relyingParty = RelyingParty.builder().sso(sso).build();
		var result = ssoService.getCookieSsoGroupName(relyingParty, claimsParty);
		assertThat(result, is(SsoService.SsoCookieNameParams.of(groupName, cpId, null)));
	}

	@Test
	void getSsoGroupNameSso() {
		var group = "groupName";
		var sso = Sso.builder().enabled(true).groupName(group).build();
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = RelyingParty.builder().sso(sso).build();
		var result = ssoService.getCookieSsoGroupName(relyingParty, claimsParty);
		assertThat(result, is(SsoService.SsoCookieNameParams.of(group, CP_ISSUER_ID, null)));
	}

	@Test
	void logoutValidSsoParticipantTwoCookies() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var cookies = new Cookie[] {
				new Cookie(PREFIXED_SSO_GROUP, SESSION_ID),
				new Cookie(COOKIE_NAME, SESSION_ID)
		};
		var result = ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, DEVICE_ID, RELYING_PARTY_ID);
		assertThat(result.size(), is(2));
		var cookieNames = result.stream().map(Cookie::getName).toList();
		assertThat(cookieNames, containsInAnyOrder(PREFIXED_SSO_GROUP, COOKIE_NAME));
		for (var cookie : result) {
			assertThat(cookie.getValue(), is(""));
			assertThat(cookie.getMaxAge(), is(0));
		}
		verify(stateCacheService).invalidate(ssoStateData, SsoService.class.getSimpleName());
	}

	@Test
	void logoutValidSsoParticipantTwoSessions() {
		var sessionId1 = "sessionId1";
		var ssoStateData1 = buildStateForSso(sessionId1, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var sessionId2 = "sessionId2";
		var ssoStateData2 = buildStateForSso(sessionId2, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var cookies = new Cookie[] {
				new Cookie(PREFIXED_SSO_GROUP, sessionId1),
				new Cookie(COOKIE_NAME, sessionId2)
		};
		var result = ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, DEVICE_ID, RELYING_PARTY_ID);
		assertThat(result.size(), is(2));
		var cookieNames = result.stream().map(Cookie::getName).toList();
		assertThat(cookieNames, containsInAnyOrder(PREFIXED_SSO_GROUP, COOKIE_NAME));
		for (var cookie : result) {
			assertThat(cookie.getValue(), is(""));
			assertThat(cookie.getMaxAge(), is(0));
		}
		verify(stateCacheService).invalidate(ssoStateData1, SsoService.class.getSimpleName());
		verify(stateCacheService).invalidate(ssoStateData2, SsoService.class.getSimpleName());
	}

	@Test
	void logoutUnknownSsoParticipant() {
		buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID, OTHER_RELYING_PARTY_ID));
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, DEVICE_ID, "invalidRp");
		assertThat(result.isEmpty(), is(true));
	}

	@Test
	void logoutSsoInvalidDeviceId() {
		buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		assertThrows(RequestDeniedException.class,
				() -> ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, "invalidDevice", RELYING_PARTY_ID));
	}

	@Test
	void logoutMissingSsoSessionCookie() {
		var cookies = new Cookie[] { new Cookie("foo", "bar") };
		var result = ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, "anyDevice", "anyRp");
		assertThat(result.isEmpty(), is(true));
	}

	@Test
	void logoutUnknownSsoSession() {
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.logoutSsoParticipantById(SSO_GROUP_PARAMS, cookies, "anyDevice", "anyRp");
		assertThat(result.isEmpty(), is(true));
	}

	@Test
	void logoutSsoParticipantByState() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID, OTHER_RELYING_PARTY_ID));
		assertThat(ssoService.internalLogoutSsoParticipant(ssoStateData, RELYING_PARTY_ID), is(RELYING_PARTY_ID));

		verify(stateCacheService).invalidate(ssoStateData, SsoService.class.getSimpleName());
	}

	@Test
	void logoutSessionNotEstablished() {
		var stateData = buildStateWithSpState(SESSION_ID);
		assertThat(ssoService.internalLogoutSsoParticipant(stateData, RELYING_PARTY_ID), is(nullValue()));

		// still invalidated
		verify(stateCacheService).invalidate(stateData, SsoService.class.getSimpleName());
	}

	@Test
	void logoutSsoParticipantByStateWrongRp() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		assertThat(ssoService.internalLogoutSsoParticipant(ssoStateData, "otherRp"), is(nullValue()));

		// still invalidated
		verify(stateCacheService).invalidate(ssoStateData, SsoService.class.getSimpleName());
	}

	@ParameterizedTest
	@MethodSource
	void matchSsoParticipant(String issuer,Set<String> participantIds, String expected) {
		var participants = buildSsoParticipants(participantIds);
		doReturn(true).when(trustBrokerProperties).isPepIssuerMatchingEnabled(any());
		doReturn("urn:test:").when(trustBrokerProperties).getSloPepIssuerIdPrefix();
		doReturn(new String[] { "-ENTERPRISE", "-PRIVATE" }).when(trustBrokerProperties).getSloIssuerIdDropPatterns();
		assertThat(ssoService.matchSessionParticipant(participants, issuer), is(expected));
	}

	static Object[][] matchSsoParticipant() {
		return new Object[][] {
				// invalid:
				{ "", Set.of("once", "two", "three"), null },
				// direct match:
				{ "issuerTwo", Set.of("issuerOne", "issuerTwo", "issuerThree"), "issuerTwo" },
				// drop pattern only applied for proper prefix:
				{ "otherIssuer:X-PRIVATE", Set.of("otherIssuer:X"), null },
				// drop pattern:
				{ "urn:test:TESTRP", Set.of("none-PRIVATE", "that-ENTERPRISE,matches"), null },
				// drop pattern:
				{ "urn:test:TESTRP", Set.of("other", "urn:test:TESTRP-PRIVATE"),
						"urn:test:TESTRP-PRIVATE" },
				// drop pattern:
				{ "urn:test:TESTRP", Set.of("urn:test:TESTRP-ENTERPRISE", "x", "y", "z"),
						"urn:test:TESTRP-ENTERPRISE" },
				// only one pattern:
				{ "urn:test:TESTRP", Set.of("urn:test:TESTRP-ENTERPRISE-PRIVATE"), null }
		};
	}

	@Test
	void mismatchSessionIndices() {
		assertThat(ssoService.matchSessionIndices(List.of("otherIndex"), "sessionIndex"), is(false));
	}

	@Test
	void matchSessionIndices() {
		var indexId = "sessionIndex";
		assertThat(ssoService.matchSessionIndices(List.of(indexId), indexId), is(true));
	}

	@Test
	void matchNullSessionIndices() {
		assertThat(ssoService.matchSessionIndices(null, "anyIndex"), is(true));
	}

	@Test
	void matchEmptySessionIndices() {
		var indexId = "sessionIndex";
		assertThat(ssoService.matchSessionIndices(List.of(""), indexId), is(true));
	}

	@Test
	void ssoParticipantsToBeNotifiedOfLogout() {
		var result = SsoService.ssoParticipantsToBeNotifiedOfLogout(
				Set.of(buildSsoSessionParticipant(RELYING_PARTY_ID),
						buildSsoSessionParticipant(OTHER_RELYING_PARTY_ID)), RELYING_PARTY_ID);
		assertThat(result, is(List.of(buildSsoSessionParticipant(OTHER_RELYING_PARTY_ID))));
	}

	@Test
	void logoutSsoParticipantForLogoutRequest() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(CP_ISSUER_ID, OTHER_RELYING_PARTY_ID));
		var sso = Sso.builder().enabled(true).logoutNotifications(true).build();
		var relyingParty = RelyingParty.builder().sso(sso).build();
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(CP_ISSUER_ID, null, true);

		var result = ssoService.logoutSsoParticipantForLogoutRequest(CP_ISSUER_ID, null, ssoStateData);

		assertThat(result, hasSize(1));
		assertThat(result.get(0).getRpIssuerId(), is(OTHER_RELYING_PARTY_ID));
	}

	@Test
	void getSsoParticipants() {
		var participants = Set.of(RELYING_PARTY_ID);
		mockClaimsProvider(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, participants);
		var startTime = Timestamp.from(START_INSTANT);
		var expirationTime = Timestamp.from(EXPIRATION_INSTANT_SSO);
		ssoStateData.getLifecycle().setSsoEstablishedTime(startTime);
		ssoStateData.getLifecycle().setExpirationTime(expirationTime);
		mockClaimsProvider(CP_ISSUER_ID);
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.getSsoParticipants(SSO_GROUP_PARAMS, cookies, DEVICE_ID);
		assertThat(result.getSsoGroupName(), is(SSO_GROUP));
		assertThat(result.getSsoEstablishedTime(), is(startTime));
		assertThat(result.getExpirationTime(), is(expirationTime));
		var expectedParticipants = Set.of(
				new SsoParticipant(RELYING_PARTY_ID, CP_ISSUER_ID, CP_IMG, CP_SHORTCUT, CP_COLOR));
		assertThat(result.getParticipants(), is(expectedParticipants));
	}

	@Test
	void getSsoParticipantsFingerprintMismatch() {
		buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		mockClaimsProvider(CP_ISSUER_ID);
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.getSsoParticipants(SSO_GROUP_PARAMS, cookies, "otherDeviceId");
		assertThat(result, is(SsoParticipants.UNDEFINED));
	}

	@Test
	void getAllSsoParticipants() {
		var sessionId1 = "sessionId1";
		var ssoStateData1 = buildStateForSso(sessionId1, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var subject1 = "subject1";
		ssoStateData1.setSubjectNameId(subject1);
		var sessionId2 = "sessionId2";
		var ssoStateData2 = buildStateForSso(sessionId2, DEVICE_ID, Set.of(OIDC_PREFIX + OTHER_RELYING_PARTY_ID));
		var subject2 = "subject2";
		ssoStateData2.setSubjectNameId(subject2);
		// filtered out because of device ID mismatch:
		var sessionId3 = "sessionId3";
		buildStateForSso(sessionId3, "otherDeviceId", Set.of("rp3"));
		var cookies = new Cookie[] {
				new Cookie(COOKIE_NAME, sessionId1), new Cookie(PREFIXED_SSO_GROUP, sessionId2),
				new Cookie(PREFIXED_SSO_GROUP + "another", sessionId3)
		};
		mockClaimsProvider(CP_ISSUER_ID);
		var result = ssoService.getAllSsoParticipants(cookies, DEVICE_ID);
		assertThat(result.size(), is(2));
		assertThat(result.stream().map(SsoParticipants::getSsoSubject).toList(), containsInAnyOrder(subject1, subject2));
		assertThat(result.stream().flatMap(p -> p.getParticipants().stream()).collect(Collectors.toSet()),
				containsInAnyOrder(new SsoParticipant(RELYING_PARTY_ID, CP_ISSUER_ID, CP_IMG, CP_SHORTCUT, CP_COLOR),
						new SsoParticipant(OIDC_PREFIX + OTHER_RELYING_PARTY_ID + SsoService.SSO_DISPLAY_OIDC_MARKER,
								CP_ISSUER_ID, CP_IMG, CP_SHORTCUT, CP_COLOR)));
	}

	@Test
	void addSsoParticipantToSession() {
		var rps = new String[] { RELYING_PARTY_ID, OTHER_RELYING_PARTY_ID};
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(rps[0]));
		ssoService.addSsoParticipantToSession(SSO_GROUP, ssoStateData, rps[1], ACS + rps[1]);
		assertThat(ssoStateData.getSsoState().getSsoParticipants().stream().map(SsoSessionParticipant::getRpIssuerId).toList(),
				containsInAnyOrder(rps));
	}

	@Test
	void addSsoParticipantToSessionNoSso() {
		var state = StateData.builder().id(SESSION_ID).build();
		assertThrows(TechnicalException.class, () -> ssoService.addSsoParticipantToSession(SSO_GROUP, state, CP_ISSUER_ID, ACS + CP_ISSUER_ID));
	}

	@Test
	void addSsoParticipantToSessionWrongGroup() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(CP_ISSUER_ID));
		assertThrows(RequestDeniedException.class, () -> ssoService.addSsoParticipantToSession("otherGroup", ssoStateData, "any", "acsany"));
	}

	@Test
	void validateSsoState() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		ssoStateData.getSsoState().setSsoQoa(SamlTestBase.Qoa.KERBEROS.getName());
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10)).when(qoaService).extractQoaLevel(any(),any());
		doReturn(List.of(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10))).when(qoaService).extractQoaLevels(any(),any());
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(true));
	}

	@Test
	void validateSsoStateRpNoSso() {
		var relyingParty = buildRelyingParty(false);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateRpNoSsoGroup() {
		var relyingParty = buildRelyingParty(true);
		relyingParty.getSso().setGroupName(null);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateSessionNoSso() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateWithSpState(SESSION_ID);
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateSessionNoParticipants() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Collections.emptySet());
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateSessionGroupMismatch() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		relyingParty.getSso().setGroupName("anotherGroup");
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateAuthnRequestUnsigned() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		stateDataByAuthnReq.setSignedAuthnRequest(false);
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateFreshAuthnRequestId() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		ssoStateData.addCompletedAuthnRequest(AUTHN_REQUEST_ID);
		ssoStateData.getSsoState().setSsoQoa(SamlTestBase.Qoa.KERBEROS.getName());
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		// replay attack scenario: already completed AuthnRequest validated again
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10)).when(qoaService).extractQoaLevel(any(),any());
		doReturn(List.of(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10))).when(qoaService).extractQoaLevels(any(),any());
		// normal scenario: second AuthnRequest differs
		var otherRequest = "otherRequestId";
		stateDataByAuthnReq.getSpStateData().setId(otherRequest);
		stateDataByAuthnReq.getSpStateData().setLastConversationId(otherRequest);
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(true));
	}

	@Test
	void validateSsoStateIssuerMismatch() {
		var relyingParty = buildRelyingParty(true);
		var cpIssuer = "otherCp";
		var claimsParty = buildClaimsParty(cpIssuer);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				cpIssuer), is(false));
	}

	@Test
	void validateSsoStateIssuerMatchInputOnly() {
		var relyingParty = buildRelyingParty(true);
		var cpIssuer = "inputCp";
		var claimsParty = buildClaimsParty(cpIssuer);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		ssoStateData.getSsoState().setSsoQoa(SamlTestBase.Qoa.KERBEROS.getName());
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10)).when(qoaService).extractQoaLevel(any(),any());
		doReturn(List.of(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10))).when(qoaService).extractQoaLevels(any(),any());
		// simulate case where CP ID in input is not equal to what the CP returns
		ssoStateData.setIssuer(cpIssuer);
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				cpIssuer), is(true));
	}

	@Test
	void validateSsoStateIssuerMatchReturnOnly() {
		var relyingParty = buildRelyingParty(true);
		var cpIssuer = "returnedCp";
		var claimsParty = buildClaimsParty(cpIssuer);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		ssoStateData.getSsoState().setSsoQoa(SamlTestBase.Qoa.KERBEROS.getName());
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10)).when(qoaService).extractQoaLevel(any(),any());
		doReturn(List.of(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), 10))).when(qoaService).extractQoaLevels(any(),any());
		// simulate case where CP ID in input is not equal to what the CP returns
		ssoStateData.getCpResponse().setIssuer(cpIssuer);
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				cpIssuer), is(true));
	}

	@Test
	void validateSsoStateQoaMismatch() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		ssoStateData.getSpStateData().setContextClasses(List.of(SamlContextClass.KERBEROS));
		ssoStateData.getSsoState().setSsoQoa(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN);
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		mockQoaService(relyingParty, claimsParty, null, null);
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	private void mockQoaService(RelyingParty relyingParty, ClaimsParty claimsParty, Qoa qoaConfig, List<String> expectedQuoas) {
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		var mobileOneFactorUnregisteredName = SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName();
		var kerberosName = SamlTestBase.Qoa.KERBEROS.getName();

		doReturn(true).when(qoaService).isStrongestPossible(MockQoa.STRONGEST_POSSIBLE.getName());
		doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1)).when(qoaService).getUnspecifiedLevel();
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel()))
				.when(qoaService).getDefaultLevel();
		doReturn(new CustomQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel())).when(qoaService).extractQoaLevel(mobileOneFactorUnregisteredName, null);
		doReturn(new CustomQoa(SamlTestBase.Qoa.KERBEROS.getName(), SamlTestBase.Qoa.KERBEROS.getLevel())).when(qoaService).extractQoaLevel(kerberosName, null);
		doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), SamlTestBase.Qoa.UNSPECIFIED.getLevel())).when(qoaService).extractQoaLevel(SamlTestBase.Qoa.UNSPECIFIED.getName(), null);
		doReturn(new CustomQoa(SamlTestBase.Qoa.SOFTWARE_PKI.getName(), SamlTestBase.Qoa.SOFTWARE_PKI.getLevel())).when(qoaService).extractQoaLevel("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI", null);

		if (relyingParty != null) {
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel(null, relyingParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), SamlTestBase.Qoa.UNSPECIFIED.getLevel()))
					.when(qoaService).extractQoaLevel("urn:oasis:names:tc:SAML:2.0:ac:classes:INVALID", relyingParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), SamlTestBase.Qoa.UNSPECIFIED.getLevel()))
					.when(qoaService).extractQoaLevel("somethingElse", relyingParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.AUTH_GUEST.getName(), SamlTestBase.Qoa.AUTH_GUEST.getLevel()))
					.when(qoaService).extractQoaLevel(SamlTestBase.Qoa.AUTH_GUEST.getName(), relyingParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel(null, relyingParty.getQoaConfig());
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_NORMAL.getName(), MockQoa.AUTH_LEVEL_NORMAL.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_NORMAL.getName(), relyingParty.getQoaConfig());
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_STRONG.getName(), MockQoa.AUTH_LEVEL_STRONG.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_STRONG.getName(), relyingParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevelFromAuthLevel(null, relyingParty.getQoaConfig());
			if (expectedQuoas != null) {
				doReturn(mockQoaList(expectedQuoas))
						.when(qoaService).extractQoaLevels(expectedQuoas, relyingParty.getQoaConfig());
				for (var qoa : expectedQuoas) {
					doReturn(new CustomQoa(qoa, 20)).when(qoaService).extractQoaLevel(qoa, null);
				}
			}
		}
		var qoa = new QoaConfig(qoaConfig, "testId");
		if (qoa.hasConfig()) {
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel(null, qoa);
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel("foo", qoa);
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel("bar", qoa);
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), SamlTestBase.Qoa.UNSPECIFIED.getLevel()))
					.when(qoaService).extractQoaLevel("somethingElse", qoa);
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_NORMAL.getName(), MockQoa.AUTH_LEVEL_NORMAL.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_NORMAL.getName(), qoa);
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_STRONG.getName(), MockQoa.AUTH_LEVEL_STRONG.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_STRONG.getName(), qoa);
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevelFromAuthLevel(null, qoa);
		}
		if (claimsParty != null) {
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevel(null, claimsParty.getQoaConfig());
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_NORMAL.getName(), MockQoa.AUTH_LEVEL_NORMAL.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_NORMAL.getName(), claimsParty.getQoaConfig());
			doReturn(new CustomQoa(MockQoa.AUTH_LEVEL_STRONG.getName(), MockQoa.AUTH_LEVEL_STRONG.getOrder()))
					.when(qoaService).extractQoaLevelFromAuthLevel(MockQoa.AUTH_LEVEL_STRONG.getName(), claimsParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1))
					.when(qoaService).extractQoaLevelFromAuthLevel(null, claimsParty.getQoaConfig());
			doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), SamlTestBase.Qoa.UNSPECIFIED.getLevel()))
					.when(qoaService).extractQoaLevel("somethingElse", claimsParty.getQoaConfig());
		}

		MockQoa[] values = MockQoa.values();
		for (MockQoa mockQoa : values) {
			if (relyingParty != null) {
				doReturn(new CustomQoa(mockQoa.name, mockQoa.order))
						.when(qoaService)
						.extractQoaLevel(mockQoa.name, relyingParty.getQoaConfig());
			}
			if (claimsParty != null) {
				doReturn(new CustomQoa(mockQoa.name, mockQoa.order))
						.when(qoaService).extractQoaLevel(mockQoa.name, claimsParty.getQoaConfig());
			}
			if (qoa.hasConfig()) {
				doReturn(new CustomQoa(mockQoa.name, mockQoa.order))
						.when(qoaService).extractQoaLevel(mockQoa.name, qoa);
			}
		}
	}

	private List<CustomQoa> mockQoaList(List<String> expectedQoas) {
		List<CustomQoa> result = new ArrayList<>();
		for (String qoa : expectedQoas) {
			MockQoa mockQoa = MockQoa.forName(qoa);
			result.add(new CustomQoa(qoa, mockQoa.getOrder()));
		}

		return result;
	}

	private QualityOfAuthenticationConfig givenGlobalQoa() {
		Map<String, Integer> qoaMap = new HashMap<>();
		qoaMap.put(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(),
				SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel());
		qoaMap.put(SamlTestBase.Qoa.SOFTWARE_PKI.getName(),
				SamlTestBase.Qoa.SOFTWARE_PKI.getLevel());
		qoaMap.put(SamlTestBase.Qoa.KERBEROS.getName(),
				SamlTestBase.Qoa.KERBEROS.getLevel());
		QualityOfAuthenticationConfig qoa = new QualityOfAuthenticationConfig();
		qoa.setMapping(qoaMap);
		qoa.setStrongestPossible("urn:qoa:strongest_possible");
		qoa.setDefaultQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName());
		return qoa;
	}

	@Test
	void validateSsoStateSessionFingerprintInvalid() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, "otherDevice", Set.of(relyingParty.getId()));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void validateSsoStateSessionStateInvalid() {
		var relyingParty = buildRelyingParty(true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(relyingParty.getId()));
		ssoStateData.setLifecycle(Lifecycle.builder().lifecycleState(LifecycleState.EXPIRED).build());
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		doReturn(new CustomQoa(SamlTestBase.Qoa.KERBEROS.getName(), 40)).when(qoaService).extractQoaLevel(any(),any());
		assertThat(ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, DEVICE_ID,
				CP_ISSUER_ID), is(false));
	}

	@Test
	void findValidStateAndCookiesToExpire() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.findValidStateAndCookiesToExpire(SsoService.SsoCookieNameParams.of(SSO_GROUP), cookies,
				RelyingParty.builder().id(RELYING_PARTY_ID).build());
		assertThat(result.isPresent(), is(true));
		assertThat(result.get().getCookiesToExpire().size(), is(1));
		assertThat(result.get().getCookiesToExpire().get(0).getName(), is(PREFIXED_SSO_GROUP));
		assertThat(result.get().getCookiesToExpire().get(0).getValue(), is(""));
		assertThat(result.get().getCookiesToExpire().get(0).getMaxAge(), is(0));
		assertThat(result.get().getStateData(), is(ssoStateData));
	}

	@Test
	void findValidStateAndCookiesToExpireMissingSession() {
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.findValidStateAndCookiesToExpire(SsoService.SsoCookieNameParams.of("otherGroup"), cookies, null);
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findValidStateAndCookiesToExpireNoSso() {
		buildStateWithSpState(SESSION_ID);
		var cookies = new Cookie[] { new Cookie(PREFIXED_SSO_GROUP, SESSION_ID) };
		var result = ssoService.findValidStateAndCookiesToExpire(SsoService.SsoCookieNameParams.of(SSO_GROUP), cookies,
				RelyingParty.builder().id("RpId").build());
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void skipCpAuthenticationExpired() {
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
		var result = ssoService.skipCpAuthentication(null, null, null, stateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationNoSso() {
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.getLifecycle().setLifecycleState(LifecycleState.INIT);
		var result = ssoService.skipCpAuthentication(null, null, null, stateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationNoParticipants() {
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		var result = ssoService.skipCpAuthentication(null, null, null, stateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationForceAuth() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		stateDataByAuthnReq.setForceAuthn(true);
		stateDataByAuthnReq.setSignedAuthnRequest(true);
		var result = ssoService.skipCpAuthentication(null, null, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void allowSsoJoinForUnsignedRequest() {
		var relyingParty = buildRelyingParty(true);
		relyingParty.setSecurityPolicies(SecurityPolicies.builder().requireSignedAuthnRequestForSsoJoin(false).build());
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		stateDataByAuthnReq.setSignedAuthnRequest(false);
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.JOIN));
	}

	@Test
	void allowSsoJoinForUnsignedRequestFallback() {
		var relyingParty = buildRelyingParty(true);
		relyingParty.setSecurityPolicies(SecurityPolicies.builder().requireSignedAuthnRequest(false).build());
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		stateDataByAuthnReq.setSignedAuthnRequest(false);
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.JOIN));
	}

	@Test
	void skipCpAuthenticationForUnsignedRequest() {
		var relyingParty = buildRelyingParty(true);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		stateDataByAuthnReq.setSignedAuthnRequest(false);
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationReplayAuthn() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		ssoStateData.addCompletedAuthnRequest(AUTHN_REQUEST_ID);
		ssoStateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(START_INSTANT));
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, AUTHN_REQUEST_ID, true);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		var result = ssoService.skipCpAuthentication(null, null, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationUnsignedAuthn() {
		var relyingParty = buildRelyingParty(true);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		ssoStateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(START_INSTANT));
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, AUTHN_REQUEST_ID, false);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		stateDataByAuthnReq.setSignedAuthnRequest(false);
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@Test
	void skipCpAuthenticationTimeFromProperties() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, ssoStateData.getSpStateData().getId(), true);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		RelyingParty relyingParty = buildRelyingParty(false);
		relyingParty.setQoa(null);
		mockQoaService(relyingParty, null,null, null);
		// MaxCachingTimeSecs is 0 in state
		doReturn(90).when(trustBrokerProperties).getSsoSessionLifetimeSec();
		// SSO established in the past, within caching time
		ssoStateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(START_INSTANT.minusSeconds(60)));
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.JOIN));
	}

	@Test
	void skipCpAuthenticationNoTimestamp() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, ssoStateData.getSpStateData().getId(), true);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		ssoStateData.getLifecycle().setSsoEstablishedTime(null);
		var result = ssoService.skipCpAuthentication(null, null, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.IGNORE));
	}

	@ParameterizedTest
	@MethodSource
	void skipCpAuthenticationTimeout(int secondsBeforeNow, String expected) {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, ssoStateData.getSpStateData().getId(), true);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		// SSO established in the past
		ssoStateData.getLifecycle().setSsoEstablishedTime(
				Timestamp.from(START_INSTANT.minusSeconds(secondsBeforeNow)));
		ssoStateData.getSsoState().setMaxCachingTimeSecs(120);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(false);
		relyingParty.setQoa(null);
		mockQoaService(relyingParty, claimsParty, null, null);
		var result = ssoService.skipCpAuthentication(null, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.valueOf(expected)));
	}

	static Object[] skipCpAuthenticationTimeout() {
		return new Object[][] {
				{ 60, SsoService.SsoSessionOperation.JOIN.name() },
				{ 120, SsoService.SsoSessionOperation.JOIN.name() },
				{ 121, SsoService.SsoSessionOperation.IGNORE.name() },
				{ 180, SsoService.SsoSessionOperation.IGNORE.name() }
		};
	}

	@ParameterizedTest
	@MethodSource
	void skipCpAuthenticationQoa(int sessionQoa, int requestQoa, String expected) {
		var issuerId = "issuerId";
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		ssoStateData.getSpStateData().setIssuer(issuerId);
		setSessionQoa(sessionQoa, ssoStateData);
		ssoStateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(START_INSTANT));
		ssoStateData.getSsoState().setMaxCachingTimeSecs(120);
		var authnRequest = buildAuthnRequest(issuerId, ssoStateData.getSpStateData().getId(), true);
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());

		setRequestQoa(requestQoa, authnRequest);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		relyingParty.setQoa(null);
		mockQoaService(relyingParty, claimsParty, null, null);
		var result = ssoService.skipCpAuthentication(claimsParty, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(SsoService.SsoSessionOperation.valueOf(expected)));
	}

	static Object[] skipCpAuthenticationQoa() {
		return new Object[][] {
				{ 0, 40, SsoService.SsoSessionOperation.STEPUP.name() },
				{ 20, 40, SsoService.SsoSessionOperation.STEPUP.name() },
				{ 30, 40, SsoService.SsoSessionOperation.STEPUP.name() },
				{ 40, 40, SsoService.SsoSessionOperation.JOIN.name() },
				{ 60, 40, SsoService.SsoSessionOperation.JOIN.name() },
				{ 20, 0, SsoService.SsoSessionOperation.JOIN.name() }
		};
	}

	private void setRequestQoa(int requestQoa, AuthnRequest authnRequest) {
		if (requestQoa > 0) {
			var higher = new AuthnContextClassRefBuilder().buildObject();
			higher.setURI(getQoa(60)); // higher than any requested
			authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().add(higher);
			var qoaHigh = new AuthnContextClassRefBuilder().buildObject();
			qoaHigh.setURI(getQoa(requestQoa));
			authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().add(qoaHigh);
			// just some other context class
			var anyContext = new AuthnContextClassRefBuilder().buildObject();
			anyContext.setURI("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
			authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().add(anyContext);
			// re-apply mock after changes
			mockedSignatureDom(authnRequest);
		}
	}

	private void setSessionQoa(int sessionQoa, StateData stateData) {
		if (sessionQoa > 0) {
			stateData.getCpResponse().setContextClasses(List.of(getQoa(sessionQoa), "somethingElse"));
		}
	}

	@ParameterizedTest
	@MethodSource
	void skipCpAuthentication(SsoService.SsoSessionOperation expected) {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var ssoLastConv = "lastConvSso";
		ssoStateData.setLastConversationId(ssoLastConv);
		var authnRequest = buildAuthnRequest("myIssuer", ssoStateData.getSpStateData().getId(), true);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());

		// enforce expected result of skipCpAuthentication
		if (expected == SsoService.SsoSessionOperation.IGNORE) {
			ssoStateData.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
		}
		else {
			setSessionQoa(30, ssoStateData);
			int requestQoa = 20;
			if (expected == SsoService.SsoSessionOperation.STEPUP) {
				requestQoa = 40;
			}
			setRequestQoa(requestQoa, authnRequest);
		}

		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		var authLastConv = "lastConvAuth";
		stateDataByAuthnReq.setLastConversationId(authLastConv);
		mockQoaService(relyingParty, claimsParty, null, List.of("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
				"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));
		var result = ssoService.skipCpAuthentication(claimsParty, relyingParty, stateDataByAuthnReq, ssoStateData);
		assertThat(result, is(expected));
		verify(stateCacheService, times(0)).invalidate(stateDataByAuthnReq, "Test");
		verify(stateCacheService, times(0)).save(ssoStateData, "Test");
		assertThat(ssoStateData.getLastConversationId(), is(ssoLastConv));
	}

	static SsoService.SsoSessionOperation[] skipCpAuthentication() {
		return SsoService.SsoSessionOperation.values();
	}

	@ParameterizedTest
	@CsvSource(value = {
			// initiate (AuthnRequest side)
			"null,null,true", // unknown QoA, nothing expected
			"null,10,false",
			"0,10,false",
 			"null,40,true", // if no session, anything goes to continue to CP
			// join cases
			"10,null,true", // no session so QoA level is treated as sufficient for initial authentication
			"20,null,true", // nothing required, already have sso min level? we should
			"40,null,true", // dito
			"10,10,false",
			"20,20,true",
			"30,30,true",
			"40,40,true",
			"50,50,true",
			"60,60,true",
			// step-up cases
			"10,20,false",
			"20,30,false",
			"30,40,false",
			"40,50,false",
			"50,60,false",
			// step-down cases
			"10,0,false",
			"20,10,true",
			"30,20,true",
			"40,30,true",
			"50,40,true",
			"60,50,true"
	}, nullValues = "null")
	void isQoaLevelSufficient(Integer sessionQoa, Integer requestQoa, boolean expectedResult) {
		var expectedQoa = getQoa(requestQoa);
		var assuredQoa = getQoa(sessionQoa);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		mockDefaultProperties();
		List<String> requestQoas = expectedQoa != null ? List.of(expectedQoa) : Collections.emptyList();
		mockQoaService(relyingParty, claimsParty, null, requestQoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(
				claimsParty, relyingParty,
				requestQoas,
				Optional.ofNullable(assuredQoa),
				"TEST-Session");
		assertThat(resultSufficient, is(expectedResult));
	}

	@ParameterizedTest
	@CsvSource({"0", "10", "20", "30", "40", "50", "60"})
	void isQoaEnoughForSso(Integer requestQoa) {
		var relyingParty = buildRelyingParty(true);
		var expectedQoa = getQoa(requestQoa);
		var minQoa = 30; // global default, we test the ROP override here
		CustomQoa qoaCustom = getQoaCustom(requestQoa);
		CustomQoa qoaKnownCustom = getQoaCustom(null);
		doReturn(minQoa).when(trustBrokerProperties).getSsoMinQoaLevel();
		doReturn(givenGlobalQoa().getMapping()).when(trustBrokerProperties).getQoaMap();
		doReturn(new CustomQoa("any", requestQoa)).when(qoaService).extractQoaLevel(expectedQoa, relyingParty.getQoaConfig());
		doReturn(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.getName(), -1)).when(qoaService).extractQoaLevel(null,
				relyingParty.getQoaConfig());
		doReturn(false).when(qoaService).isStrongestPossible(any());
		var result = ssoService.isQoaEnoughForSso(relyingParty, List.of(qoaCustom), qoaKnownCustom,Optional.empty());
		assertThat(result, is (requestQoa >= minQoa));
	}

	@ParameterizedTest
	@MethodSource
	void isSessionQoaEnoughForSsoOnStepUp(String sessionQoa, int sessionQoaLevel, boolean expectedResult) {
		var relyingParty = buildRelyingParty(true);
		CustomQoa qoaCustom = getQoaCustom(10);
		CustomQoa qoaKnownCustom = getQoaCustom(sessionQoaLevel);
		var minQoa = 30; // global default, we test the ROP override here
		doReturn(minQoa).when(trustBrokerProperties).getSsoMinQoaLevel();
		mockQoaService(relyingParty, null, null, null);
		var result = ssoService.isQoaEnoughForSso(relyingParty,  List.of(qoaCustom), qoaKnownCustom, Optional.of(sessionQoa));
		assertThat(result, is (sessionQoaLevel >= minQoa));
		assertThat(result, is (expectedResult));
	}

	static Object[][] isSessionQoaEnoughForSsoOnStepUp() {
		return new Object[][] {
				{ MockQoa.MOBILE_ONE_FACTOR_UNREGISTERED.name, MockQoa.MOBILE_ONE_FACTOR_UNREGISTERED.order, false },
				{ MockQoa.PASSWORD_PROTECTED_TRANSPORT.name, MockQoa.PASSWORD_PROTECTED_TRANSPORT.order, false },
				{ MockQoa.SOFTWARE_TIME_SYNC_TOKEN.name, MockQoa.SOFTWARE_TIME_SYNC_TOKEN.order, true },
				{ MockQoa.NOMAD_TELEPHONY.name, MockQoa.NOMAD_TELEPHONY.order, true },
				{ MockQoa.KERBEROS.name, MockQoa.KERBEROS.order, true },
				{ MockQoa.SOFTWARE_PKI.name, MockQoa.SOFTWARE_PKI.order, true },
				{ MockQoa.MOBILE_TWO_FACTOR_CONTACT.name, MockQoa.MOBILE_TWO_FACTOR_CONTACT.order, true },
				{ MockQoa.TIME_SYNC_TOKEN.name, MockQoa.TIME_SYNC_TOKEN.order, true },
				{ MockQoa.SMART_CARD_PKI.name, MockQoa.SMART_CARD_PKI.order, true },
				{ "urn:oasis:names:tc:SAML:2.0:ac:classes:INVALID", -1, false }
		};
	}

	@Test
	void isQoaEnoughForSsoConfiguredPerRelyingParty() {
		var relyingParty = buildRelyingParty(true);
		var minQoa = 20;
		CustomQoa qoaKnownCustom = getQoaCustom(null);
		doReturn(minQoa).when(trustBrokerProperties).getSsoMinQoaLevel();
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		relyingParty.getSecurityPolicies().setSsoMinQoaLevel(20);
		mockQoaConfig();

		var result = ssoService.isQoaEnoughForSso(relyingParty, List.of(getQoaCustom(30)), qoaKnownCustom,Optional.empty()); // 2-fa
		assertThat(result, is (true));
		result = ssoService.isQoaEnoughForSso(relyingParty, List.of(getQoaCustom(20)), qoaKnownCustom,Optional.empty()); // password
		assertThat(result, is (true));
		result = ssoService.isQoaEnoughForSso(relyingParty, List.of(getQoaCustom(10)), qoaKnownCustom, Optional.empty()); // guest
		assertThat(result, is (false));
	}

	@Test
	void isQoaLevelInsufficientMixed() {
		// from an actual AuthnRequest
		var expectedQuoas = List.of(SamlContextClass.NOMAD_TELEPHONY,
				SamlContextClass.SOFTWARE_PKI, SamlContextClass.KERBEROS, SamlContextClass.TIME_SYNC_TOKEN,
				SamlContextClass.MOBILE_TWO_FACTOR_CONTACT, SamlContextClass.SMART_CARD_PKI);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(20)) , // mapped to PASSWORD_PROTECTED_TRANSPORT
				"SSO-2");
		assertThat(resultSufficient, is(false));
	}

	@Test
	void isQoaLevelSufficientMixedContained() {
		var expectedQuoas = List.of(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN,
				SamlContextClass.SOFTWARE_PKI, SamlContextClass.KERBEROS, SamlContextClass.TIME_SYNC_TOKEN,
				SamlContextClass.MOBILE_TWO_FACTOR_CONTACT, SamlContextClass.SMART_CARD_PKI);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		mockDefaultProperties();
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(30)), // mapped to SOFTWARE_TIME_SYNC_TOKEN - contained in expectedQuoas
				"SSO-3");
		assertThat(resultSufficient, is(true));
	}

	@Test
	void isQoaLevelSufficientMixedNotContained() {
		var expectedQuoas = List.of(SamlContextClass.MOBILE_TWO_FACTOR_CONTACT,
				SamlContextClass.TIME_SYNC_TOKEN, SamlContextClass.SMART_CARD_PKI);
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		mockDefaultProperties();
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(50)), // mapped to SOFTWARE_PKI - not contained in expectedQoas
				"SSO-4");
		assertThat(resultSufficient, is(true));
	}

	@Test
	void isQoaLevelSufficientStrongestPossible() {
		var expectedQuoas = List.of(MockQoa.STRONGEST_POSSIBLE.getName());
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		claimsParty.setAuthLevel(MockQoa.AUTH_LEVEL_NORMAL.getName());
		var relyingParty = buildRelyingParty(true);
		mockDefaultProperties();
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(20)), "SSO-5");
		assertThat(resultSufficient, is(false));
		resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(30)), "SSO-5");
		assertThat(resultSufficient, is(true));
	}

	@Test
	void isQoaLevelSufficientStrongestPossibleWithFallback() {
		var expectedQuoas = List.of(MockQoa.STRONGEST_POSSIBLE.getName());
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		claimsParty.setAuthLevel(MockQoa.AUTH_LEVEL_NORMAL.getName());
		claimsParty.setStrongestPossibleAuthLevel(MockQoa.AUTH_LEVEL_STRONG.getName());
		var relyingParty = buildRelyingParty(true);
		mockDefaultProperties();
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(40)), "SSO-6");
		assertThat(resultSufficient, is(false));
		resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(50)), "SSO-6");
		assertThat(resultSufficient, is(true));
	}

	@Test
	void isQoaLevelSufficientStrongestPossibleWithoutAuthLevel() {
		var expectedQuoas = List.of(MockQoa.STRONGEST_POSSIBLE.getName());
		var claimsParty = buildClaimsParty(CP_ISSUER_ID);
		var relyingParty = buildRelyingParty(true);
		mockDefaultProperties();
		mockQoaService(relyingParty, claimsParty, null, expectedQuoas);
		var resultSufficient = ssoService.isQoaLevelSufficient(claimsParty, relyingParty, expectedQuoas,
				Optional.of(getQoa(10)), "SSO-6");
		//  always false as StrongestPossible is not known
		assertThat(resultSufficient, is(false));
	}

	@Test
	void updateQoaInSession() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var qoa40 = getQoa(40);
		var qoa30 = getQoa(30);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		// start without a value
		ssoStateData.getSsoState().setSsoQoa(null);
		mockQoaService(rp, cp, null, null);

		// update to 40
		var cpResponse = buildCpResponseWithContextClasses(List.of(getQoa(20), qoa40, qoa30));
		ssoStateData.setCpResponse(cpResponse);
		assertThat(ssoService.updateQoaInSession(rp, cp, ssoStateData), is(true));
		assertThat(ssoStateData.getSsoState().getSsoQoa(), is(qoa40));

		// lower to 30
		cpResponse = buildCpResponseWithContextClasses(List.of(getQoa(10), qoa30));
		ssoStateData.setCpResponse(cpResponse);
		assertThat(ssoService.updateQoaInSession(rp, cp, ssoStateData), is(true));
		assertThat(ssoStateData.getSsoState().getSsoQoa(), is(qoa30));

		// no change
		cpResponse = buildCpResponseWithContextClasses(List.of(qoa40, qoa30, getQoa(20)));
		ssoStateData.setCpResponse(cpResponse);
		assertThat(ssoService.updateQoaInSession(rp, cp, ssoStateData), is(true));
		assertThat(ssoStateData.getSsoState().getSsoQoa(), is(qoa40));

		// update to 60
		var qoa60 = getQoa(60);
		cpResponse = buildCpResponseWithContextClasses(List.of(getQoa(50), qoa60));
		ssoStateData.setCpResponse(cpResponse);
		assertThat(ssoService.updateQoaInSession(rp, cp, ssoStateData), is(true));
		assertThat(ssoStateData.getSsoState().getSsoQoa(), is(qoa60));
	}

	@Test
	void updateSubjectNameIdInSession() {
		var stateData = buildStateDataByAuthnReq();
		assertThrows(TechnicalException.class, () -> SsoService.updateSubjectNameIdInSession(stateData));
		// establishing SSO session
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var cpResponse = ssoStateData.getCpResponse();
		// set original subject name ID
		setNameId(cpResponse, SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		assertNull(stateData.getSubjectNameId());
		SsoService.updateSubjectNameIdInSession(ssoStateData);
		assertThat(ssoStateData.getSubjectNameId(), is(SUBJECT_NAME_ID));
		// update with same subject name ID -> OK
		SsoService.updateSubjectNameIdInSession(ssoStateData);
		assertThat(ssoStateData.getSubjectNameId(), is(SUBJECT_NAME_ID));
		// update with NameId modified after CP response -> OK (+ log)
		setNameId(cpResponse, "otherNameId1", SUBJECT_NAME_ID);
		SsoService.updateSubjectNameIdInSession(ssoStateData);
		assertThat(ssoStateData.getSubjectNameId(), is(SUBJECT_NAME_ID));
		// update with changed original CP response name ID -> NOK
		setNameId(cpResponse, "otherNameId2", "otherNameId2");
		assertThrows(TechnicalException.class, () -> SsoService.updateSubjectNameIdInSession(ssoStateData));
		assertThat(ssoStateData.getSubjectNameId(), is(SUBJECT_NAME_ID));
	}

	@Test
	void isOidcPrincipalAllowedToJoinSsoSession() {
		var oidcPrincipal = "oidcPrincipal";
		var oidcSessionId = "oidcSessionId";
		var stateData = buildStateDataByAuthnReq();
		assertThat(ssoService.isOidcPrincipalAllowedToJoinSsoSession(stateData, oidcPrincipal, oidcSessionId), is(false));

		// established SSO session (minimal flags)
		var cpResponse = CpResponse.builder().build();
		stateData.setCpResponse(cpResponse);
		setNameId(stateData.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		stateData.setSubjectNameId(SUBJECT_NAME_ID);
		stateData.initializedSsoState();
		stateData.setLifecycle(Lifecycle.builder().lifecycleState(LifecycleState.ESTABLISHED).build());

		assertThat(ssoService.isOidcPrincipalAllowedToJoinSsoSession(stateData, oidcPrincipal, oidcSessionId), is(true));

		// no subject name ID change
		setNameId(stateData.getCpResponse(), "otherNameId2", "otherNameId2");
		assertThrows(TechnicalException.class, () ->
				ssoService.isOidcPrincipalAllowedToJoinSsoSession(stateData, oidcPrincipal, oidcSessionId));
	}

	@Test
	void allowSsoForSignedAuthnRequest() {
		var relyingParty = buildRelyingParty(true);
		var stateData = buildStateDataByAuthnReq();
		var result = ssoService.isRelyingPartyOkForSso(relyingParty, stateData);
		assertThat(result, is(true));
	}

	@Test
	void noSsoIfDisabledForRp() {
		var relyingParty = buildRelyingParty(false);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var result = ssoService.isRelyingPartyOkForSso(relyingParty, ssoStateData);
		assertThat(result, is(false));
	}

	@Test
	void noSsoForUnsignedAuthnRequest() {
		var relyingParty = buildRelyingParty(true);
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.setSignedAuthnRequest(null);
		var result = ssoService.isRelyingPartyOkForSso(relyingParty, stateData);
		assertThat(result, is(false));
		stateData.setSignedAuthnRequest(Boolean.FALSE);
		result = ssoService.isRelyingPartyOkForSso(relyingParty, stateData);
		assertThat(result, is(false));
	}

	@Test
	void establishSso() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var stateData = buildStateWithSpState(SESSION_ID);
		var qoa = getQoa(40);
		var cpResponse = buildCpResponseWithContextClasses(List.of(qoa));
		cpResponse.setIssuer("response_cp_issuer");
		stateData.setIssuer(CP_ISSUER_ID);
		setNameId(cpResponse, null, SUBJECT_NAME_ID);
		stateData.setCpResponse(cpResponse);
		var ssoGroup = buildSsoGroup();
		mockSsoEstablished(stateData);
		doReturn(SsoSessionIdPolicy.ALWAYS.toString()).when(trustBrokerProperties).getSsoSessionIdPolicy();
		mockQoaService(rp, cp, null, null);

		ssoService.establishSso(rp, cp, stateData, ssoGroup);

		assertThat(stateData.isSsoEstablished(), is(true));
		var ssoState = stateData.getSsoState();
		assertThat(ssoState.getSsoGroupName(), is(ssoGroup.getName()));
		assertThat(ssoState.getMaxSessionTimeSecs(), is(180));
		assertThat(ssoState.getMaxIdleTimeSecs(), is(60));
		assertThat(ssoState.getMaxCachingTimeSecs(), is(120));
		assertThat(ssoState.getSsoParticipants(),
				is(Set.of(buildSsoSessionParticipant(RELYING_PARTY_ID))));
		assertThat(ssoState.getSsoQoa(), is(qoa));
		assertThat(stateData.getSsoSessionId(), startsWith("sso-"));
		assertThat(stateData.getSubjectNameId(), is(SUBJECT_NAME_ID));

		assertDoesNotThrow(() -> ssoService.ensureSsoState(stateData));
		assertThrows(TechnicalException.class, () -> ssoService.ensureAuthnReqOrImplicitSsoState(stateData));

	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" })
	void establishImplicitSso(boolean preEstablished) {
		var rp = buildRelyingParty(false);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var stateData = buildStateWithSpState(SESSION_ID);
		if (preEstablished) {
			stateData.initializedSsoState();
			stateData.setLifecycle(Lifecycle.builder().lifecycleState(LifecycleState.ESTABLISHED).build());
		}
		setNameId(stateData.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		assertThat(stateData.isSsoEstablished(), is(preEstablished));
		mockSsoEstablished(stateData);
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		mockQoaService(rp, null, null, null);

		ssoService.establishImplicitSso(rp, cp, stateData);

		assertThat(stateData.isSsoEstablished(), is(true));
		assertThat(stateData.initializedSsoState().isImplicitSsoGroup(), is(!preEstablished));

		assertDoesNotThrow(() -> ssoService.ensureSsoState(stateData));
		if (preEstablished) {
			assertThrows(TechnicalException.class, () -> ssoService.ensureAuthnReqOrImplicitSsoState(stateData));
		}
		else {
			assertDoesNotThrow(() -> ssoService.ensureAuthnReqOrImplicitSsoState(stateData));
		}
	}

	private void mockSsoEstablished(StateData stateData) {
		doAnswer(invocation -> {
			StateData param = invocation.getArgument(0);
			param.initializedSsoState();
			param.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
			return null; // void method
		}).when(stateCacheService).ssoEstablished(stateData, SsoService.class.getSimpleName());
	}

	@Test
	void establishSsoQoaTooLow() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.setCpResponse(buildCpResponseWithContextClasses(List.of(getQoa(10))));
		mockDefaultProperties();
		mockQoaService(rp, cp, null, null);
		setNameId(stateData.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);

		ssoService.establishSso(rp, cp, stateData, null);

		assertThat(stateData.isSsoEstablished(), is(false));
	}

	@Test
	void establishSsoQoaMissing() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var stateData = buildStateWithSpState(SESSION_ID);
		setNameId(stateData.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		mockQoaService(rp, null, null, null);
		ssoService.establishSso(rp, cp, stateData, buildSsoGroup());

		assertThat(stateData.isSsoEstablished(), is(false));
	}

	@Test
	void establishSsoQoaTooLowOnJoin() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var ssoGroup = buildSsoGroup();
		mockDefaultProperties();
		mockQoaService(rp, cp, null, null);

		// SSO session with sufficient QOA
		var stateData = buildStateWithSpState(SESSION_ID);
		stateData.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		stateData.initializedSsoState().setSsoQoa(getQoa(30));
		var subjectNameId = "Subject.old";
		stateData.setSubjectNameId(subjectNameId);

		// step-up only resulted in too low QOA
		var cpResponse = buildCpResponseWithContextClasses(List.of(getQoa(10)));
		cpResponse.setIssuer("response_cp_issuer");
		stateData.setIssuer(CP_ISSUER_ID);
		setNameId(cpResponse, subjectNameId, subjectNameId);
		stateData.setCpResponse(cpResponse);

		ssoService.establishSso(rp, cp, stateData, ssoGroup);

		assertThat(stateData.isSsoEstablished(), is(true));
		assertThat(stateData.initializedSsoState().getSsoParticipants(),
				is(Set.of(buildSsoSessionParticipant(RELYING_PARTY_ID))));
		assertThat(stateData.getSubjectNameId(), is(subjectNameId));
	}

	@Test
	void establishSsoIdentityChange() {
		var rp = buildRelyingParty(true);
		var cp = buildClaimsParty(CP_ISSUER_ID);
		var ssoGroup = buildSsoGroup();
		mockDefaultProperties();

		// SSO session with sufficient QOA
		var stateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var subjectNameId = "Subject.old";
		stateData.setSubjectNameId(subjectNameId);

		// step-up only resulted in too low QOA
		var cpResponse = buildCpResponseWithContextClasses(List.of(getQoa(20)));
		cpResponse.setIssuer(CP_ISSUER_ID);
		// test name ID change as well, this only affects the state
		setNameId(cpResponse, "Subject.new", "Subject.new");
		stateData.setCpResponse(cpResponse);

		assertThrows(TechnicalException.class, () -> ssoService.establishSso(rp, cp, stateData, ssoGroup));
	}

	@Test
	void completeDeviceInfo() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, null);
		setNameId(ssoStateData.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		ssoStateData.setIssuer(CP_ISSUER_ID);
		var stateDataByAuthnReq = buildStateDataByAuthnReq();
		var relyingParty = buildRelyingParty(true);
		ssoService.completeDeviceInfoPreservingStateForSso(ssoStateData, stateDataByAuthnReq, relyingParty);
		assertThat(ssoStateData.getCompletedAuthnRequests(), contains(AUTHN_REQUEST_ID));
		var ssoState = ssoStateData.getSsoState();
		assertThat(ssoState.getSsoParticipants(),
				is(Set.of(buildSsoSessionParticipant(relyingParty.getId()))));
		verify(stateCacheService, times(1)).save(ssoStateData, SsoService.class.getSimpleName());
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void copyToSsoStateAndInvalidateAuthnRequestState(boolean implicit) {
		doReturn(new SecurityChecks()).when(trustBrokerProperties).getSecurity();
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
		// ensure the copy includes all the needed fields by comparing with the result of AssertionConsumerService.saveState

		// state generated when saving new AuthnRequest
		var acsUrl1 = "https://acs1";
		var acWhitelist = AcWhitelist.builder().acUrls(List.of(acsUrl1)).build();
		var relyingParty = RelyingParty.builder().id(RELYING_PARTY_ID).acWhitelist(acWhitelist).build();
		var cp = buildClaimsParty(CP_ISSUER_ID);
		mockQoaService(relyingParty, cp, null, null);

		var authnRequest = SamlFactory.createRequest(AuthnRequest.class, RELYING_PARTY_ID);
		authnRequest.setAssertionConsumerServiceURL(acsUrl1);
		authnRequest.setForceAuthn(true);

		var request = new MockHttpServletRequest();
		var relayState1 = "relayState";
		request.addParameter(SamlIoUtil.SAML_RELAY_STATE, relayState1);
		var referer1 = "https://referer1";
		request.addHeader(HttpHeaders.REFERER, referer1);

		var authState = assertionConsumerService.saveState(authnRequest, false, request, relyingParty, Optional.empty(),
				SamlBinding.POST);
		// CpResponse with name ID is required for establishing SSO and copying
		authState.setCpResponse(CpResponse.builder().build());
		setNameId(authState.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		if (implicit) {
			ssoService.establishImplicitSso(relyingParty, cp, authState);
		}

		// SSO state with values that differ from the AuthnRequest
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(CP_ISSUER_ID));
		ssoStateData.getSpStateData().setAssertionConsumerServiceUrl("https://acsoriginal");
		ssoStateData.setSignedAuthnRequest(true); // false on AuthnRequest
		ssoStateData.setLastConversationId("oldconversation");
		ssoStateData.getSpStateData().setLastConversationId(ssoStateData.getLastConversationId());
		ssoStateData.getSpStateData().setId("");
		// copy AuthnRequest based state
		ssoService.copyToSsoStateAndInvalidateAuthnRequestState(authState, ssoStateData);

		// ensure we have a deep copy
		assertNotSame(ssoStateData.getSpStateData(), authState.getSpStateData());
		assertNotSame(ssoStateData.getSpStateData().getLifecycle(), authState.getSpStateData().getLifecycle());

		// values in SpStateData
		// as the object is copied, just check some fields
		assertThat(ssoStateData.getSpStateData().getId(), is(authState.getSpStateData().getId()));
		assertThat(ssoStateData.getSpStateData().getAssertionConsumerServiceUrl(),
				is(authState.getSpStateData().getAssertionConsumerServiceUrl()));
		assertThat(ssoStateData.getSpStateData().getLastConversationId(),
				is(authState.getSpStateData().getLastConversationId()));
		assertThat(ssoStateData.getSpStateData().getLifecycle().getInitTime(),
				is(authState.getSpStateData().getLifecycle().getInitTime()));

		// values set outside SpStateData in AssertionConsumerService.saveState
		assertThat(ssoStateData.getLastConversationId(), is(authState.getLastConversationId()));
		assertThat(ssoStateData.getForceAuthn(), is(authState.getForceAuthn()));
		assertThat(ssoStateData.getSignedAuthnRequest(), is(authState.getSignedAuthnRequest()));
	}

	@Test
	void skipCopyToSsoStateAndInvalidateAuthnRequestState() {
		var authState = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		setNameId(authState.getCpResponse(), SUBJECT_NAME_ID, SUBJECT_NAME_ID);
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		// same ID would in practice mean same session, make them different here, so we can verify the copying was done
		var lastConversation = "conv1";
		authState.setLastConversationId(lastConversation);
		ssoService.copyToSsoStateAndInvalidateAuthnRequestState(authState, ssoStateData);
		assertTrue(authState.isValid());
		assertTrue(ssoStateData.isValid());
		assertThat(authState.getLastConversationId(), is(lastConversation));
		assertThat(ssoStateData.getLastConversationId(), is(lastConversation));
	}

	@Test
	void failCopyToSsoStateAndInvalidateAuthnRequestState() {
		var wrongAuthState = buildStateForSso(SESSION_ID + "2", DEVICE_ID, Set.of(RELYING_PARTY_ID));
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		assertThrows(RequestDeniedException.class,
				() -> ssoService.copyToSsoStateAndInvalidateAuthnRequestState(wrongAuthState, ssoStateData));
	}

	@Test
	void logoutNotificationsEnabled() {
		assertThat(SsoService.logoutNotificationsEnabled(null), is(false));
		var relyingParty = RelyingParty.builder().build();
		assertThat(SsoService.logoutNotificationsEnabled(relyingParty), is(false));
		var sso = Sso.builder().build();
		relyingParty.setSso(sso);
		assertThat(SsoService.logoutNotificationsEnabled(relyingParty), is(false));
		sso.setEnabled(true);
		assertThat(SsoService.logoutNotificationsEnabled(relyingParty), is(false));
		sso.setLogoutNotifications(true);
		assertThat(SsoService.logoutNotificationsEnabled(relyingParty), is(true));
	}

	@Test
	void getRelyingPartiesForSamlSlo() {
		var relyingPartySlo = buildRelyingParty("relyingPartySlo", true);
		relyingPartySlo.getSso().setSloUrl(DESTINATION);
		var relyingPartyNoSso = buildRelyingParty("relyingPartyNoSso", false);
		var relyingPartyNoSlo = buildRelyingParty("relyingPartyNoSlo", false);

		doReturn(List.of(relyingPartySlo, relyingPartyNoSso, relyingPartyNoSlo)).when(relyingPartySetupService)
				.getOrderedRelyingPartiesForSlo(CP_ISSUER_ID, DESTINATION);

		var result = ssoService.getRelyingPartiesForSamlSlo(CP_ISSUER_ID, DESTINATION);

		assertThat(result, contains(relyingPartySlo));
	}

	@Test
	void getNoRelyingPartiesForSlo() {
		doReturn(List.of(buildRelyingParty(false))).when(relyingPartySetupService)
				.getOrderedRelyingPartiesForSlo(CP_ISSUER_ID, DESTINATION);

		assertThrows(RequestDeniedException.class, () -> ssoService.getRelyingPartiesForSamlSlo(CP_ISSUER_ID, DESTINATION));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// original referrer used:
			"null,https://localhost.localdomain/referrer,https://localhost.localdomain/referrer", // fallback to referrer
			"https://localhost/path,null,https://localhost/path", // absolute SLO URL used
			"https://localhost/path,https://localhost.localdomain/referrer,https://localhost/path", // absolute SLO URL used
			"/slo/path,https://localhost/referrer,https://localhost/referrer", // relative SLO URL, referrer with path used
			"/slo/path,https://localhost/,https://localhost/slo/path", // relative SLO URL, referrer without path - merged
			"/slo/path,null,/slo/path", // relative slo URL without referrer
			"null,null,null", // no SLO URL, no referrer
	}, nullValues = "null")
	void computeSamlSingleLogoutUrlFromRp(String sloUrl, String referrer, String expected) {
		var relyingParty = buildRelyingParty(true);
		relyingParty.getSso().setSloUrl(sloUrl);

		var result = ssoService.computeSamlSingleLogoutUrl(referrer, relyingParty);

		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// original referrer used:
			"https://localhost/path,/test,https://localhost/path",
			"https://localhost/x,/test,https://localhost/x",
			"https://localhost/,/,https://localhost/",
			// path replaced:
			"https://localhost/,/test,https://localhost/test",
			"https://localhost,/test,https://localhost/test",
			"https://localhost:443,/test,https://localhost:443/test",
			"http://localhost:8080,/x,http://localhost:8080/x",
			"http://localhost:8080/,/foo/bar,http://localhost:8080/foo/bar",
			"http://localhost:80/,/test,http://localhost:80/test"
	})
	void computeSamlSingleLogoutUrlFromReferrer(String sloUrl, String path, String expected) {
		var relyingParty = buildRelyingParty(true);
		doReturn(path).when(trustBrokerProperties).getSloDefaultSamlDestinationPath();

		var result = ssoService.computeSamlSingleLogoutUrl(sloUrl, relyingParty);

		assertThat(result, is(expected));
	}

	@Test
	void getSloIssuerWithFallback() {
		var fallback = "xtbissuer";
		doReturn(fallback).when(trustBrokerProperties).getIssuer();
		assertThat(ssoService.getSloIssuerWithFallback(null), is(fallback));
		assertThat(ssoService.getSloIssuerWithFallback(""), is(fallback));
		assertThat(ssoService.getSloIssuerWithFallback(CP_ISSUER_ID), is(CP_ISSUER_ID));
	}

	private NameID buildNameId() {
		return SamlFactory.createNameId("name1", NameIDType.UNSPECIFIED, "qual1");
	}

	private SloResponse buildSloResponse(SloProtocol protocol, SloMode mode, String url, String issuer, boolean matchAcUrl) {
		return SloResponse.builder()
				.protocol(protocol)
				.mode(mode)
				.url(url)
				.issuer(issuer)
				.matchAcUrl(matchAcUrl)
				.build();
	}

	@ParameterizedTest
	@CsvSource(value = { "POST,false", "POST,true", "REDIRECT,false", "REDIRECT,true" })
	void buildSamlSloNotification(SamlBinding binding, boolean signed) throws IOException  {
		var relyingParty = buildRelyingParty(true);
		var sloResponse = buildSloResponse(SloProtocol.SAML2, SloMode.NOTIFY_FAIL, DESTINATION, CP_ISSUER_ID, true);
		if (signed) {
			var signatureAlgos =
					swiss.trustbroker.federation.xmlconfig.Signature.builder()
																	.signatureMethodAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1)
																	.canonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
																	.digestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256)
																	.build();
			relyingParty.initializedSaml().setSignature(signatureAlgos);
			sloResponse.setSloSigner(SamlTestBase.dummyCredential());
		}
		sloResponse.setBinding(binding);
		relyingParty.setSecurityPolicies(SecurityPolicies.builder().requireSignedLogoutNotificationRequest(signed).build());
		var nameId = buildNameId();

		var result = ssoService.buildSloNotification(relyingParty, sloResponse, null, nameId, SESSION_ID);

		assertThat(result.getSlo(), is(sloResponse));
		assertThat(result.getEncodedUrl(), is(DESTINATION_ENCODED));
		assertThat(result.getSamlLogoutRequest(), is(not(nullValue())));
		assertThat(result.getSamlRelayState(), is(not(nullValue())));

		var xmlObj = binding == SamlBinding.POST ? SamlIoUtil.decodeSamlPostData(result.getSamlLogoutRequest()) :
				SamlIoUtil.decodeSamlRedirectData(result.getSamlLogoutRequest());
		assertThat(xmlObj, instanceOf(LogoutRequest.class));
		var logoutRequest = (LogoutRequest)xmlObj;
		assertThat(logoutRequest.getIssuer().getValue(), is(CP_ISSUER_ID));
		assertThat(logoutRequest.getDestination(), is(DESTINATION));
		assertThat(logoutRequest.getNameID().getSPNameQualifier(), is(nameId.getSPNameQualifier()));
		assertThat(logoutRequest.getNameID().getValue(), is(nameId.getValue()));
		assertThat(logoutRequest.getNameID().getFormat(), is(nameId.getFormat()));
		if (binding == SamlBinding.POST) {
			assertThat(result.getSamlHttpMethod(), is(HttpMethod.POST.name()));
			assertThat(logoutRequest.isSigned(), is(signed));
		}
		else {
			assertThat(result.getSamlHttpMethod(), is(HttpMethod.GET.name()));
			assertThat(logoutRequest.isSigned(), is(false));
			if (signed) {
				assertThat(result.getSamlRedirectSignature(), is(not(nullValue())));
				assertThat(result.getSamlRedirectSignatureAlgorithm(), is(not(nullValue())));
			}
			else {
				assertThat(result.getSamlRedirectSignature(), is(nullValue()));
				assertThat(result.getSamlRedirectSignatureAlgorithm(), is(nullValue()));
			}
		}
	}

	@Test
	void buildOidcSloNotification() {
		var relyingParty = buildRelyingParty(true);
		var sloResponse = buildSloResponse(SloProtocol.OIDC, SloMode.NOTIFY_FAIL, DESTINATION, CP_ISSUER_ID, true);
		sloResponse.setSessionRequired(true);
		var nameId = buildNameId();

		var result = ssoService.buildSloNotification(relyingParty, sloResponse, null, nameId, SESSION_ID);

		assertThat(result.getSlo(), is(sloResponse));
		assertThat(result.getEncodedUrl(),
				is(DESTINATION_ENCODED + "&#x3f;iss&#x3d;" + CP_ISSUER_ID + "&amp;sid&#x3d;" + SESSION_ID));
		assertThat(result.getSamlLogoutRequest(), is(nullValue()));
		assertThat(result.getSamlRelayState(), is(nullValue()));
	}

	@Test
	void buildHttpSloNotification() {
		var relyingParty = buildRelyingParty(true);
		var sloResponse = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_FAIL, DESTINATION, null, true);
		var nameId = buildNameId();

		var result = ssoService.buildSloNotification(relyingParty, sloResponse, null, nameId, SESSION_ID);

		assertThat(result.getSlo(), is(sloResponse));
		assertThat(result.getEncodedUrl(), is(DESTINATION_ENCODED));
		assertThat(result.getSamlRelayState(), is(nullValue()));
		assertThat(result.getSamlLogoutRequest(), is(nullValue()));
	}

	@Test
	void addSloNotificationsNoSso() {
		var relyingParty = buildRelyingParty(false);
		var nameId = buildNameId();
		var result = new HashMap<SloResponse, SloNotification>();

		ssoService.addSloNotifications(relyingParty, null, true, nameId, SESSION_ID, result);

		assertThat(result, is(anEmptyMap()));
	}

	@Test
	void addSloNotifications() {
		var relyingParty = buildRelyingParty(true);
		relyingParty.setRpSigner(SamlTestBase.dummyCredential());
		var rpSloUrl = "https://rp1.localdomain";
		var sloUrlResponse = buildSloResponse(SloProtocol.SAML2, SloMode.RESPONSE, rpSloUrl, null, false);
		relyingParty.getSso().setSloUrl(rpSloUrl);
		var sloResponseList = relyingParty.getSso().getSloResponse();
		var sloResponseUrl = SLO_URL;
		// filtered because of protocol:
		var sloResponseOidc = buildSloResponse(SloProtocol.OIDC, SloMode.RESPONSE, sloResponseUrl, null, false);
		sloResponseList.add(sloResponseOidc);
		var sloNotificationFail = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_FAIL, DESTINATION, null, false);
		sloResponseList.add(sloNotificationFail);
		var sloNotifyUrl = "https://slo2.localdomain";
		var sloNotificationTry = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, sloNotifyUrl, null, false);
		sloResponseList.add(sloNotificationTry);
		// filtered: same as sloNotificationTry
		var sloNotificationFailDuplicate = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_FAIL, sloNotifyUrl, null, false);
		sloResponseList.add(sloNotificationFailDuplicate);
		// filtered: same as RP sloUrl
		var sloNotificationTryDuplicate = buildSloResponse(SloProtocol.SAML2, SloMode.NOTIFY_TRY, rpSloUrl, null,
				false);
		sloResponseList.add(sloNotificationTryDuplicate);
		// matches ACS URL
		var sloNotificationTryAcMatch = buildSloResponse(SloProtocol.SAML2, SloMode.NOTIFY_TRY, sloResponseUrl + "/test", null,
				true);
		sloResponseList.add(sloNotificationTryAcMatch);
		// filtered: does not match ACS URL
		var sloNotificationTryAcMismatch = buildSloResponse(SloProtocol.SAML2, SloMode.NOTIFY_TRY, rpSloUrl + "/test", null, true);
		sloResponseList.add(sloNotificationTryAcMismatch);
		var nameId = buildNameId();
		var result = new HashMap<SloResponse, SloNotification>();

		ssoService.addSloNotifications(relyingParty, sloResponseUrl, true, nameId, null, result);

		assertThat(result, is(aMapWithSize(4))); // 1 x RESPONSE + 3 notifications
		assertThat(result.keySet(), containsInAnyOrder(sloUrlResponse,
				sloNotificationFail, sloNotificationTry, sloNotificationTryAcMatch));
	}

	@Test
	void addSloNotificationsOidc() {
		doReturn(ISSUER).when(trustBrokerProperties).getIssuer();
		var relyingParty = buildRelyingParty(true);
		relyingParty.getSso().setSloUrl(SLO_URL);
		var sloResponse = SloResponse.builder().protocol(SloProtocol.OIDC).url(SLO_URL).build();
		relyingParty.getSso().setSloResponse(List.of(sloResponse));
		var result = new HashMap<SloResponse, SloNotification>();

		ssoService.addSloNotifications(relyingParty, SLO_URL, true, null, OIDC_SESSION_ID, result);

		assertThat(result, is(aMapWithSize(1))); // 1 x RESPONSE
		assertThat(result.keySet(), contains(sloResponse));
		assertThat(result.get(sloResponse), is(nullValue()));
	}

	@Test
	void addSloNotificationsRedirect() {
		doReturn(ISSUER).when(trustBrokerProperties).getIssuer();
		var relyingParty = buildRelyingParty(true);
		var sloResponse = SloResponse.builder().protocol(SloProtocol.SAML2).binding(SamlBinding.REDIRECT).url(SLO_URL).build();
		relyingParty.getSso().setSloResponse(List.of(sloResponse));
		var result = new HashMap<SloResponse, SloNotification>();

		ssoService.addSloNotifications(relyingParty, SLO_URL, true, null, null, result);

		assertThat(result, is(aMapWithSize(1))); // 1 x RESPONSE
		assertThat(result.keySet(), contains(sloResponse));
		var expectedNotification = new SloNotification(sloResponse);
		expectedNotification.setEncodedUrl(SLO_URL_ENCODED);
		assertThat(result.get(sloResponse), is(expectedNotification));
	}

	@Test
	void createSloNotifications() {
		doReturn(ISSUER).when(trustBrokerProperties).getIssuer();
		var relyingParty = buildRelyingParty(true);
		var sloResponse = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, DESTINATION, null, true);
		relyingParty.getSso().getSloResponse().add(sloResponse);
		var nameId = buildNameId();
		var participantRp1 = buildRelyingParty("participantRp1", true);
		var sloResponse1 = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, DESTINATION + "1", null, true);
		participantRp1.getSso().getSloResponse().add(sloResponse1);
		var sloResponseDuplicate = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, DESTINATION, null, true);
		participantRp1.getSso().getSloResponse().add(sloResponseDuplicate);
		var participantRp2 = buildRelyingParty("participantRp2", true);
		var sloResponse2 = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, DESTINATION + "2", null, true);
		participantRp2.getSso().getSloResponse().add(sloResponse2);
		// ACS URL not matching:
		var sloResponse4 = buildSloResponse(SloProtocol.HTTP, SloMode.NOTIFY_TRY, "https://test.localdomain/sso", null, true);
		participantRp2.getSso().getSloResponse().add(sloResponse4);
		var participantRp3 = buildRelyingParty("participantRp3", true);
		var clientId = participantRp3.getId() + "_client";
		var sloResponse3 = buildSloResponse(SloProtocol.OIDC, SloMode.NOTIFY_TRY, DESTINATION + "3", null, true);
		participantRp3.getSso().getSloResponse().add(sloResponse3);
		var sessionParticipants = Set.of(
				SsoSessionParticipant.builder()
									 .rpIssuerId(participantRp1.getId())
									 .assertionConsumerServiceUrl(DESTINATION)
									 .build(),
				SsoSessionParticipant.builder()
									 .rpIssuerId(participantRp2.getId())
									 .assertionConsumerServiceUrl(DESTINATION)
									 .build(),
				SsoSessionParticipant.builder()
									 .oidcClientId(clientId)
									 .oidcSessionId(OIDC_SESSION_ID)
									 .assertionConsumerServiceUrl(DESTINATION)
									 .build()

		);
		doReturn(participantRp1).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(
				participantRp1.getId(), DESTINATION, true);
		doReturn(participantRp2).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(
				participantRp2.getId(), DESTINATION, true);
		doReturn(participantRp3).when(relyingPartyDefinitions).getRelyingPartyByOidcClientId(
				clientId, null, trustBrokerProperties, true);
		var result = ssoService.createSloNotifications(relyingParty, DESTINATION, sessionParticipants, nameId, SESSION_ID);

		assertThat(result.size(), is(4));
		var resultUrlList = result.values().stream().map(SloNotification::getEncodedUrl).toList();
		assertThat(resultUrlList,
				containsInAnyOrder(DESTINATION_ENCODED, DESTINATION_ENCODED + "1", DESTINATION_ENCODED + "2",
						DESTINATION_ENCODED + "3" + ISS_SID_ENCODED));
	}

	@Test
	void handleLogoutResponse() {
		var httpRequest = new MockHttpServletRequest();
		var response = SamlFactory.createResponse(LogoutResponse.class, RELYING_PARTY_ID);
		var state = buildStateWithSpState(SESSION_ID);
		doReturn(Optional.of(state)).when(stateCacheService).findOptional(SESSION_ID,  SsoService.class.getSimpleName());
		ssoService.handleLogoutResponse(response, SESSION_ID, httpRequest);
		verify(auditService).logInboundFlow(any());
	}

	@ParameterizedTest
	@CsvSource(value = { "null", SESSION_ID }, nullValues = "null")
	void handleLogoutResponseWithoutState(String relayState) {
		var httpRequest = new MockHttpServletRequest();
		var response = SamlFactory.createResponse(LogoutResponse.class, RELYING_PARTY_ID);
		doReturn(Optional.empty()).when(stateCacheService).findOptional(relayState, SsoService.class.getSimpleName());
		ssoService.handleLogoutResponse(response, relayState, httpRequest);
		verify(auditService).logInboundFlow(any());
	}

	@Test
	void ensureAuthnReqOrImplicitSsoState() {
		var authnRequest = buildAuthnRequest(CP_ISSUER_ID, AUTHN_REQUEST_ID, false);
		var stateDataByAuthnReq = buildStateForAuthnRequest(authnRequest);
		assertDoesNotThrow(() -> ssoService.ensureAuthnReqOrImplicitSsoState(stateDataByAuthnReq));
		assertThrows(TechnicalException.class, () -> ssoService.ensureSsoState(stateDataByAuthnReq));
	}

	@Test
	void ensureSsoState() {
		var ssoStateData = buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID));
		assertDoesNotThrow(() -> ssoService.ensureSsoState(ssoStateData));
		assertThrows(TechnicalException.class, () -> ssoService.ensureAuthnReqOrImplicitSsoState(ssoStateData));
	}

	@ParameterizedTest
	@CsvSource(value = {
		"null,null,true,null",
		"null,https://localhost,true,null", // only ACS
		"://,null,true,null", // invalid
		"/logout,null,true,null", // relative without ACS
		"/logout,null,false,null", // relative without ACS - ACS match irrelevant
		"/slo/logout,://,true,null", // relative with invalid ACS
		"/slo/logout,://,false,null", // relative with invalid ACS - ACS match irrelevant
		"https://localhost/logout,://,true,null", // absolute with invalid ACS and ACS match
		"https://localhost/logout,://,false,https://localhost/logout", // absolute with invalid ACS without ACS match
		"https://localhost/logout,null,true,https://localhost/logout", // only SLO
		"/slo/logout,https://localhost/saml/auth,true,https://localhost/slo/logout", // relative
		"https://sso.localdomain/logout,https://localhost/saml/auth,true,null", // host mismatch
		"https://sso.localdomain/slo,https://localhost/saml/auth,false,https://sso.localdomain/slo", // host mismatch ignored
		"http://localhost/logout,https://localhost/saml/auth,true,null", // protocol mismatch
		"https://localhost:4443/logout,https://localhost:4444/saml/auth,true,null", // port mismatch
		"https://localhost:443/logout,https://localhost/saml/auth,true,https://localhost:443/logout", // match
		"https://login.trustbroker.swiss:443/logout,https://login.trustbroker.swiss/saml/auth,"
				+ "true,https://login.trustbroker.swiss:443/logout", // match
		"https://sso.trustbroker.swiss/logout,https://sso.trustbroker.swiss/auth,"
				+ "true,https://sso.trustbroker.swiss/logout" // match
	}, nullValues = "null")
	void calculateSloUrlForAcsUrl(String sloUrl, String acsUrl, boolean matchAcUrl, String expected) {
		var relyingParty = RelyingParty.builder().id(RELYING_PARTY_ID).build();
		var url = SsoService.calculateSloUrlForAcsUrl(relyingParty, sloUrl, acsUrl, matchAcUrl);
		assertThat(url, is(expected));
	}

	@ParameterizedTest
	@MethodSource
	void getSsoSessionParticipantAcsUrl(Set<SsoSessionParticipant> sessionParticipants, String referer, String expected) {
		var relyingParty = RelyingParty.builder().id(RELYING_PARTY_ID).build();
		var url = SsoService.getSsoSessionParticipantAcsUrl(relyingParty, sessionParticipants, referer);
		assertThat(url, is(expected));
	}

	private static Object[][] getSsoSessionParticipantAcsUrl() {
		return new Object[][] {
				{ Collections.emptySet(), null, null },
				// RP not in list:
				{ Set.of(SsoSessionParticipant.builder()
											  .rpIssuerId("rp2")
											  .assertionConsumerServiceUrl(MISMATCH_ACS_URL)
											  .build()), DESTINATION, DESTINATION },
				// RP in list once
				{ Set.of(SsoSessionParticipant.builder()
											  .rpIssuerId(RELYING_PARTY_ID)
											  .assertionConsumerServiceUrl(MISMATCH_ACS_URL)
											  .build()), DESTINATION, MISMATCH_ACS_URL },
				// RP in list twice, use first not matching (LinkedHashSet to have a fixed order for the test)
				{ new LinkedHashSet<>(List.of(SsoSessionParticipant.builder()
																 .rpIssuerId(RELYING_PARTY_ID)
																 .assertionConsumerServiceUrl(MISMATCH_ACS_URL + "/1")
																 .build(),
						SsoSessionParticipant.builder()
											 .rpIssuerId(RELYING_PARTY_ID)
											 .assertionConsumerServiceUrl(MISMATCH_ACS_URL + "/2")
											 .build())), DESTINATION, MISMATCH_ACS_URL + "/1" },
				// RP in list twice, use first matching (LinkedHashSet to have a fixed order for the test)
				{ new LinkedHashSet<>(List.of(SsoSessionParticipant.builder()
											  .rpIssuerId(RELYING_PARTY_ID)
											  .assertionConsumerServiceUrl(MISMATCH_ACS_URL)
											  .build(),
						SsoSessionParticipant.builder()
											 .rpIssuerId("otherRp")
											 .assertionConsumerServiceUrl(DESTINATION + "/other")
											 .build(),
						SsoSessionParticipant.builder()
											  .rpIssuerId(RELYING_PARTY_ID)
											  .assertionConsumerServiceUrl(DESTINATION + "/1")
											  .build(),
						SsoSessionParticipant.builder()
											 .rpIssuerId(RELYING_PARTY_ID)
											 .assertionConsumerServiceUrl(DESTINATION + "/2")
											 .build())), DESTINATION, DESTINATION + "/1" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void testCalculateCookieSameSiteFlag(SsoGroup ssoGroup, String ssoGroupName, SsoState ssoState, String expected) {
		doReturn(PERIMERTER_URL).when(trustBrokerProperties).getPerimeterUrl();
		doReturn(Optional.ofNullable(ssoGroup)).when(relyingPartySetupService).getSsoGroupConfig(ssoGroupName, true);
		var result = ssoService.calculateCookieSameSiteFlag(ssoState);
		assertThat(result, is(expected));
	}

	static Object[][] testCalculateCookieSameSiteFlag() {
		return new Object[][] {
				{
						null, SSO_GROUP, // simulate dynamic SSO group name
						buildSsoStateByAcUrls(SSO_GROUP, Collections.emptySet()),
						WebUtil.COOKIE_SAME_SITE_STRICT // no cross-site
				},
				{
						buildSsoGroup(SSO_GROUP, null), SSO_GROUP,
						buildSsoStateByAcUrls(SSO_GROUP, Collections.emptySet()),
						WebUtil.COOKIE_SAME_SITE_STRICT // no cross-site
				},
				{
						buildSsoGroup(SSO_GROUP, WebUtil.COOKIE_SAME_SITE_DYNAMIC), SSO_GROUP,
						buildSsoStateByAcUrls(SSO_GROUP, Set.of("https://sub.trustbroker.swiss/test",
								"https://trustbroker.swiss/test2", "https://sub.sub.trustbroker.swiss/test3")),
						WebUtil.COOKIE_SAME_SITE_STRICT // same-site
				},
				{
						buildSsoGroup(SSO_GROUP, null), SSO_GROUP,
						buildSsoStateByAcUrls(SSO_GROUP, Set.of("https://foo.trustbroker.swiss/test", MISMATCH_ACS_URL)),
						WebUtil.COOKIE_SAME_SITE_NONE // cross-site
				},
				{
						buildSsoGroup(SSO_GROUP, null), SSO_GROUP,
						buildSsoStateByAcUrls(SSO_GROUP, Set.of(DESTINATION, "https://bar.trustbroker.swiss/test")),
						WebUtil.COOKIE_SAME_SITE_NONE // cross-site
				},
				{
						buildSsoGroup(SSO_GROUP, WebUtil.COOKIE_SAME_SITE_LAX), SSO_GROUP,
						buildSsoStateByAcUrls(SSO_GROUP, Set.of("https://foo.trustbroker.swiss/test", DESTINATION,
								MISMATCH_ACS_URL)),
						WebUtil.COOKIE_SAME_SITE_LAX // sessionCookieSameSite
				}
		};
	}

	@ParameterizedTest
	@CsvSource(value = { "true,false", "true,true", "false,false" }) // false,true makes no sense
	void testLogoutRelyingParty(boolean findState, boolean ssoGroupMismatch) {
		var otherRpId = "relyingParty2";
		var stateData = findState ? buildStateForSso(SESSION_ID, DEVICE_ID, Set.of(RELYING_PARTY_ID, otherRpId)) : null;
		doReturn(Optional.ofNullable(stateData)).when(stateCacheService)
												.findValidState(SESSION_ID, SsoService.class.getSimpleName());
		var relyingParty = buildRelyingParty(true);
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RELYING_PARTY_ID, null, true);
		relyingParty.getSso().setLogoutNotifications(true);
		var sessionCookie = new Cookie(COOKIE_NAME, SESSION_ID);
		var cookies = new Cookie[] { sessionCookie };
		var logoutState = SsoService.SloState.builder().build();
		var otherSsoGroup = "otherGroup";
		if (ssoGroupMismatch) {
			logoutState.setLogoutSsoGroup(otherSsoGroup); // simulate ongoing logout for other group
		}
		var result = ssoService.logoutRelyingParty(RELYING_PARTY_ID, List.of(SESSION_INDEX), relyingParty, cookies, logoutState);
		assertThat(result.isPresent(), is(ssoGroupMismatch));
		assertFalse(logoutState.isResponseSent()); // never set by SsoService
		if (ssoGroupMismatch) {
			assertThat(result.get(), is(stateData));
			assertThat(logoutState.getLogoutSsoGroup(), is(otherSsoGroup)); // unchanged
		}
		else if (findState) {
			assertThat(logoutState.getLogoutSsoGroup(), is(SSO_GROUP)); // set by SsoService
			// cookie of second SSO group must not be cleared
			assertThat(logoutState.getCookiesToExpire(), hasSize(1));
			var expiredCookie = logoutState.getCookiesToExpire().stream()
					.filter(cookie -> cookie.getName().equals(COOKIE_NAME)).findFirst();
			// cookie of first SSO group must always be cleared
			assertTrue(expiredCookie.isPresent());
			assertThat(expiredCookie.get().getValue(), is(""));
			assertThat(expiredCookie.get().getMaxAge(), is(0));
			// notifications must be set
			assertThat(logoutState.getSloNotifications(), hasSize(1));
			var notification = logoutState.getSloNotifications().iterator().next();
			assertThat(notification, is(SsoSessionParticipant
					.builder()
					.rpIssuerId(otherRpId)
					.cpIssuerId(CP_ISSUER_ID)
					.assertionConsumerServiceUrl(ACS + otherRpId)
					.build()));
		}
		if (ssoGroupMismatch || !findState) {
			assertThat(logoutState.getCookiesToExpire(), hasSize(0));
			assertThat(logoutState.getSloNotifications(), hasSize(0));
		}
	}

	@Test
	void testBuildSloResponseParameters() {
		doReturn(ISSUER).when(trustBrokerProperties).getIssuer();
		var rp = buildRelyingParty(true);
		rp.getSso().setSloUrl(DESTINATION);
		var sloResponse = SloResponse.builder().mode(SloMode.NOTIFY_TRY).protocol(SloProtocol.OIDC).url(ACS_URL).build();
		rp.getSso().setSloResponse(List.of(sloResponse));
		var nameId = SamlFactory.createNameId("name1@localhost", NameIDType.EMAIL, null);
		var redirectUrl = MISMATCH_ACS_URL;
		var participant =
				SsoSessionParticipant.builder().rpIssuerId(RELYING_PARTY_ID).assertionConsumerServiceUrl(DESTINATION).build();
		var notifications = Set.of(participant);
		var maxWait = 10;
		doReturn(maxWait).when(trustBrokerProperties).getSloNotificationTimoutMillis();
		var minWait = 20;
		var expectedNotification = new SloNotification(sloResponse);
		expectedNotification.setEncodedUrl(ACS_URL_ENCODED + ISS_SID_ENCODED);
		doReturn(minWait).when(trustBrokerProperties).getSloNotificationMinWaitMillis();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RELYING_PARTY_ID, null);

		var result = ssoService.buildSloResponseParameters(rp, DESTINATION, notifications, nameId, OIDC_SESSION_ID, redirectUrl);

		assertThat(result.useHttpGet(), is(true));
		assertThat(result.velocityParameters(), is(not(nullValue())));
		assertThat(result.velocityParameters().get(VelocityUtil.VELOCITY_PARAM_XTB_HTTP_METHOD), is(HttpMethod.GET.name()));
		assertThat(result.velocityParameters().get(VelocityUtil.VELOCITY_PARAM_ACTION), is(redirectUrl));
		assertThat(result.velocityParameters().get(SsoService.VELOCITY_PARAM_XTB_SLO_MAX_WAIT), is(maxWait));
		assertThat(result.velocityParameters().get(SsoService.VELOCITY_PARAM_XTB_SLO_MIN_WAIT), is(minWait));
		assertThat(result.velocityParameters().get(SsoService.VELOCITY_PARAM_XTB_SLO_WAIT_FOR_COUNT), is(1)); // sloResponse entries
		assertThat(result.velocityParameters().get(SsoService.VELOCITY_PARAM_XTB_SLO_NOTIFICATIONS), is(List.of(expectedNotification)));
		assertThat(result.velocityParameters().get(SsoService.VELOCITY_PARAM_XTB_CONSOLE_DEBUG), is(Boolean.FALSE));
	}

	private static void setNameId(CpResponse cpResponse, String nameId, String originalNameId) {
		cpResponse.setNameId(nameId);
		cpResponse.setOriginalNameId(originalNameId);
		cpResponse.setAttribute(CoreAttributeName.NAME_ID.getNamespaceUri(), nameId);
	}

	private void mockDefaultProperties() {
		doReturn(20).when(trustBrokerProperties).getSsoMinQoaLevel();
		QualityOfAuthenticationConfig qualityOfAuthenticationConfig = new QualityOfAuthenticationConfig();
		doReturn(qualityOfAuthenticationConfig).when(trustBrokerProperties).getQoa();
		when(trustBrokerProperties.getQoa()).thenReturn(givenGlobalQoa());
	}

	private Qoa mockQoaConfig() {
		return Qoa.builder()
				  .classes(mockRpAcClasses())
				  .build();
	}

	private List<AcClass> mockRpAcClasses() {
		List<AcClass> acClasses = new ArrayList<>();
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.KERBEROS.getLevel())
							 .contextClass(SamlTestBase.Qoa.KERBEROS.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.KERBEROS.getLevel())
							 .contextClass(SamlTestBase.Qoa.KERBEROS.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel())
							 .contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.PASSWORD_PROTECTED_TRANSPORT.getLevel())
							 .contextClass(SamlTestBase.Qoa.PASSWORD_PROTECTED_TRANSPORT.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.SOFTWARE_TIME_SYNC_TOKEN.getLevel())
							 .contextClass(SamlTestBase.Qoa.SOFTWARE_TIME_SYNC_TOKEN.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.SOFTWARE_PKI.getLevel())
							 .contextClass(SamlTestBase.Qoa.SOFTWARE_PKI.getName())
							 .build());
		return acClasses;
	}

}
