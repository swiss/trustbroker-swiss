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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class OidcSessionSupport {

	// Cookie used by tomcat/spring-sec to track HTTP sessions (for single client support ok)
	// See also application.yml declaring this one to switch from JSESSIONID default.
	private static final String CONTAINER_SESSION_COOKIE_NAME = "BSESSION";

	// The OIDC session cookie name is derived from this one and encodes the client_id.
	static final String OIDC_SESSION_COOKIE_NAME_PREFIX = "BSESSION_";

	// The OIDC SSO session cookie name is derived from this one and encodes the client_id.
	static final String OIDC_SSO_SESSION_COOKIE_NAME_PREFIX = "BSSO_";

	// use this to cross-check and validate the session
	static final String OIDC_SESSION_CLIENT_ID = OidcUtil.OIDC_CLIENT_ID;

	// we write our ID in the session to cross-check it for established OIDC clients
	private static final String OIDC_SESSION_SESSION_ID = "OIDC_SESSION_SESSION_ID";

	// use as a primary source of error redirecting informing failing RPs
	private static final String OIDC_SESSION_REDIRECT_URI = "OIDC_SESSION_REDIRECT_URI";

	// use as a primary source for client state instead of digging it out from spring-security
	private static final String OIDC_SESSION_CLIENT_STATE = "OIDC_SESSION_CLIENT_STATE";

	// remember SSO session ID, so we can find our way back
	private static final String SAML_SSO_SESSION_ID = "SAML_SSO_SESSION_ID";

	// track authenticated subject FYI mainly
	private static final String SPRING_PRINCIPAL_NAME = "SPRING_PRINCIPAL_NAME";

	// remember session ID source if it's a token
	static final String OIDC_TOKEN_SESSION_SUFFIX= "_TOKEN";

	private OidcSessionSupport() {
	}

	public static String getOidcClientId() {
		return getOidcClientId(null, null, null);
	}

	public static String getOidcClientId(HttpServletRequest request,  RelyingPartyDefinitions relyingPartyDefinitions) {
		return getOidcClientId(request, relyingPartyDefinitions, null);
	}

	// Check HTTP request for all signs of OIDC clients and derive client_id
	// NOTE: Do not refer to session here (otherwise we have a loop finding it)
	public static String getOidcClientId(HttpServletRequest request,
										 RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("No OIDC session support yet");
			return null;
		}

		// check if pereimeter already detected the client_id and cached it
		var source = "HttpExchangeCache";
		var clientId = HttpExchangeSupport.getRunningOidcClientId();
		if (clientId == null && HttpExchangeSupport.isRunningOidcExchange()) {
			log.trace("No OIDC exchange detected on requestUri {}", request.getRequestURI());
			return null;
		}

		// OIDC/SAML federation exchange (on SAML side we work without spring-security using container sessions)
		if (clientId == null) {
			source = ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH;
			clientId = getSamlExchangeClientId();
		}

		// HTTP GET/POST client_id
		if (clientId == null) {
			source = OidcUtil.OIDC_CLIENT_ID;
			clientId = StringUtil.clean(request.getParameter(source));
		}

		// HTTP Authorization Bearer token with aud/azp claim or Basic client_id:secret
		if (clientId == null) {
			source = HttpHeaders.AUTHORIZATION;
			var authHeader = request.getHeader(source);
			clientId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		}

		// HTTP GET /logout id_token_hint
		if (clientId == null) {
			source = OidcUtil.ID_TOKEN_HINT;
			var idTokenHint = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(idTokenHint);
		}

		// HTTP POST /introspect (IETF RFC7662)
		if (clientId == null) {
			source = OidcUtil.TOKEN_INTROSPECT;
			var token = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(token);
		}

		// HTTP POST /userinfo
		if (clientId == null) {
			source = OidcUtil.ACCESS_INTROSPECT;
			var accessToken = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(accessToken);
		}

		// HTTP POST /token
		if (clientId == null) {
			source = OidcUtil.OIDC_REFRESH_TOKEN;
			var refreshToken = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(refreshToken);
		}

		// check our cookie containing the client_id (multiple cookies might match)
		if (clientId == null && relyingPartyDefinitions != null) {
			clientId = getClientIdFromOidcCookie(request, relyingPartyDefinitions, networkConfig);
		}

		// best effort only
		if (clientId == null && relyingPartyDefinitions != null) {
			source = "HTTP";
			clientId = getOidcClientIdFromHttpParams(request, relyingPartyDefinitions, networkConfig);
		}

		if (clientId == null) {
			source = "NONE";
		}
		log.trace("Found OIDC client_id={} from source={} path={} called from {}",
				clientId, source, request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
		return clientId;
	}

	// Guessing client_id from other HTTP parameters (not according to OIDC spec)
	public static String getOidcClientIdFromHttpParams(HttpServletRequest request,
													   RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {

		// LATER OidcSession can be found by AuthorizationToken but in supportedFrameAncestors() the clientId can be wrong because for Opaque token authorization
		// HTTP GET/POST request_url
		var source = "request_url";
		var realm = OidcUtil.getRealmFromRequestUrl(request.getRequestURL().toString());
		Set<String> clientIds = new LinkedHashSet<>();
		if (realm != null) {
			getClientIdByRealm(relyingPartyDefinitions, realm, clientIds);
		}

		// HTTP GET/POST redirect_uri
		var url = getRedirectUri(request);
		if (clientIds.isEmpty()) {
			source = OidcUtil.REDIRECT_URI;
			realm = OidcUtil.getRealmFromRequestUrl(request.getRequestURI());
			clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);
		}

		// HTTP Referer matching to Client config (multiple clients might match)
		if (clientIds.isEmpty()) {
			source = HttpHeaders.REFERER;
			url = request.getHeader(source);
			clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);
		}

		// HTTP Origin matching to Client config (multiple clients might match)
		if (clientIds.isEmpty()) {
			source = HttpHeaders.ORIGIN;
			url = request.getHeader(source);
			clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);
		}

		// This is only best-effort matching that can fail for the following reasons:
		// - RedirectUris.ACUrl contain regex that do not match startsWith test
		// - We might find an Oidc Client matching the URL, but it's the wrong one leading to failed client auth or wrong claims
		// Currently happens on trustrbroker-oidcclient logout with just the redirect-uri but no OPTIONAL client_id or
		// id_token_hint. See https://openid.net/specs/openid-connect-rpinitiated-1_0.html fpr details.
		var clientId = clientIds.isEmpty() ? null : clientIds.iterator().next();
		var endpoint = request.getRequestURI();
		var level = clientIds.size() > 1 ? Level.INFO : Level.DEBUG;
		log.atLevel(level).log("OIDC client guessed from httpSource={} url={} resulting in clientIds='{}' picking clientId={} on endpoint={} {}",
				source, StringUtil.clean(url), clientIds, clientId, endpoint, WebSupport.getClientHint(request, networkConfig));
		return clientId;
	}

	private static void getClientIdByRealm(RelyingPartyDefinitions relyingPartyDefinitions, String realm, Set<String> clientIds) {
		var oidcClient = relyingPartyDefinitions.getOidcClientsByPredicate(cl -> cl.isSameRealm(realm));
		if (oidcClient.size() == 1) {
			var clientId = oidcClient.get(0).getId();
			log.info("OIDC client configuration guessed from realm={} resulting in clientId={}", realm, clientId);
			clientIds.add(clientId);
		}
		else {
			log.debug("Number of clients={} found for realm={}, cannot guess the OIDC client by realm", oidcClient.size(), realm);
		}
	}

	// Similar to getOidcClientId we want to locate the containers sub-session referring to the client state
	// This one is essential to attach the HttpSession to the HttpRequest in the TomcatSessionManager.
	public static String getOidcSessionId(HttpServletRequest request,
										  RelyingPartyDefinitions relyingPartyDefinitions,
										  NetworkConfig networkConfig) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("Cannot locate sid from running HTTP request yet");
			return null;
		}

		// with a known client_id (from exchange cache or wire) we can switch to a sub-session
		var clientId = getOidcClientId(request, relyingPartyDefinitions, networkConfig);
		if (clientId == null) {
			log.trace("Cannot locate OIDC sub-session without client_id on requestUri={} from {}",
					request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
			return null;
		}

		// HTTP Authorization Bearer token
		var source = HttpHeaders.AUTHORIZATION;
		var authHeader = request.getHeader(source);
		var oidcSessionId = OidcUtil.getSessionIdFromAuthorizationHeader(authHeader);

		// HTTP GET /logout id_token_hint
		if (oidcSessionId == null) {
			source = OidcUtil.ID_TOKEN_HINT;
			var idTokenHint = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(idTokenHint);
			if (oidcSessionId == null && idTokenHint != null && !idTokenHint.isEmpty() && !JwtUtil.isJwt(idTokenHint)) {
				oidcSessionId = idTokenHint + OIDC_TOKEN_SESSION_SUFFIX;
			}
		}

		// HTTP POST /introspect token
		if (oidcSessionId == null) {
			source = OidcUtil.TOKEN_INTROSPECT;
			var introspectToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(introspectToken);
		}

		// HTTP POST /userinfo
		if (oidcSessionId == null) {
			source = OidcUtil.ACCESS_INTROSPECT;
			var accessToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(accessToken);
		}

		// HTTP POST /token
		if (oidcSessionId == null) {
			source = OidcUtil.OIDC_REFRESH_TOKEN;
			var refreshToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(refreshToken);
		}

		// HTTP GET/POST Cookie (BSESSION_CLIENT_ID) during federated login and for resilient code flow backing
		if (oidcSessionId == null) {
			source = "COOKIE";
			oidcSessionId = getSessionIdFromOidcCookie(request, clientId, networkConfig);
		}

		if (oidcSessionId == null && authHeader != null) {
			var toks = authHeader.split(" ");
			source = "AuthorizationHeader";
			oidcSessionId = toks[1] + OIDC_TOKEN_SESSION_SUFFIX;
		}

		if (oidcSessionId == null && request.getParameter("token") != null) {
			oidcSessionId = request.getParameter("token") + OIDC_TOKEN_SESSION_SUFFIX;
			source = "AuthorizationToken";
		}

		// logging only
		if (log.isDebugEnabled()) {
			if (oidcSessionId != null) {
				log.debug("Found OIDC sessionId={} for clientId={} from source={} called on path={} from {}",
						oidcSessionId, clientId, source, request.getRequestURI(),
						WebSupport.getClientHint(request, networkConfig));
			}
			else if (log.isTraceEnabled()) {
				log.trace("Missing OIDC sessionId for clientId={} from all sources on path={} with cookies='{}' from {}",
						clientId, request.getRequestURI(), StringUtil.clean(request.getHeader(HttpHeaders.COOKIE)),
						WebSupport.getClientHint(request, networkConfig));
			}
		}
		return oidcSessionId;
	}

	public static String getSessionIdFromOidcCookie(HttpServletRequest request, String clientId, NetworkConfig networkConfig) {
		var cookie = getOidcCookie(request, clientId, networkConfig);
		if (cookie != null) {
			return cookie.getValue();
		}
		return null;
	}

	// maybe discard this one, it's ambiguous and not an official spec compliant approach
	public static String getClientIdFromOidcCookie(HttpServletRequest request,
												   RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {
		var cookie = getOidcCookie(request, null, networkConfig);
		if (cookie != null) {
			var normalizedClientId = getNormalizedClientId(cookie.getName());
			var client = verifyNormalizedClientId(normalizedClientId, relyingPartyDefinitions);
			return client != null ? client.getId() : null;
		}
		return null;
	}

	static Cookie createOidcCookie(String clientId, String name, String cookieValue, boolean cookieHttpOnly, HttpServletRequest request,
								   RelyingPartyDefinitions relyingPartyDefinitions, TrustBrokerProperties trustBrokerProperties) {
		var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
		var sessionTtl = getSessionTtlFromClientConfig(client, trustBrokerProperties);
		var cookieSecure = trustBrokerProperties.isSecureBrowserHeaders();
		var cookieSameSite = getCookieSameSite(client, request, trustBrokerProperties);
		var params = CookieParameters.builder()
				.name(name)
				.value(cookieValue)
				.maxAge(sessionTtl)
				.secure(cookieSecure)
				.httpOnly(cookieHttpOnly)
				.sameSite(cookieSameSite)
				.build();
		return WebUtil.createCookie(params);
	}

	public static Cookie createOidcSsoSessionCookie(String clientId, String cookieValue, HttpServletRequest request,
													RelyingPartyDefinitions relyingPartyDefinitions, TrustBrokerProperties trustBrokerProperties) {
		var name = getSsoSessionCookieName(clientId);
		// Needs to be available to client OIDC JS adapters, thus httpOnly false
		return createOidcCookie(clientId, name, cookieValue, false, request, relyingPartyDefinitions, trustBrokerProperties);
	}

	// Caller must convert the internal value sameSite=Dynamic if used (currently only used by tests).
	public static Cookie createOidcClientCookie(String clientId, String sessionId, int validSec, boolean secure,
												String sameSite) {
		var name = getClientIdRelatedCookieName(clientId);
		var params = CookieParameters.builder()
				.name(name)
				.value(sessionId)
				.maxAge(validSec)
				.secure(secure)
				.httpOnly(true)
				.sameSite(sameSite)
				.build();
		return WebUtil.createCookie(params);
	}

	public static Cookie getOidcCookie(HttpServletRequest request, String clientId, NetworkConfig networkConfig) {
		if (request == null) {
			return null;
		}
		var cookies = request.getCookies();
		if (cookies == null || cookies.length == 0) {
			return null;
		}

		// We return client_id bound cookie without a known client_id as last resort only
		var clientCookieName = getClientIdRelatedCookieName(clientId);
		var bCookies = Arrays.stream(cookies).filter(c -> c.getName().equals(clientCookieName)).toList();
		if (bCookies.size() > 1) {
			// may be even info
			// NOTE: OIDC is usually quite resilient (clients retry, we can prevent interaction enabling SSO)
			var cookiesNames = HttpExchangeSupport.getCookiesAsString(request);
			log.error("Found OIDC bsessionCookies='{}' for clientId={} ambiguous so we deny all to caller {}",
					cookiesNames, clientId, WebSupport.getClientHint(request, networkConfig));
			return null;
		} else if (!bCookies.isEmpty()) {
			log.trace("Found OIDC sessionId={} from bsessionCookie={} for clientId={} caller {}",
					bCookies.get(0).getValue(), bCookies.get(0).getName(), clientId,
					WebSupport.getClientHint(request, networkConfig));
			return bCookies.get(0);
		}
		return null;
	}

	// Cookie is BSESSION_CLIENT_ID e.g. BSESSION_SOME-ORG if Client id=some-org in configuration
	// We use this (costly indirection) to add additional security measures later here.
	private static String getNormalizedClientId(String clientId) {
		return clientId != null ? clientId.replace(OIDC_SESSION_COOKIE_NAME_PREFIX, "").toUpperCase() : null;
	}

	private static String getClientIdRelatedCookieName(String clientId) {
		return clientId != null ?
				OIDC_SESSION_COOKIE_NAME_PREFIX + getNormalizedClientId(clientId) :
				CONTAINER_SESSION_COOKIE_NAME; // fallback to global session, we will cross-check the sessionid in there
	}

	private static String getSsoSessionCookieName(String clientId) {
		return OIDC_SSO_SESSION_COOKIE_NAME_PREFIX + clientId;
	}

	private static OidcClient verifyNormalizedClientId(String normalizedClientId,
													   RelyingPartyDefinitions relyingPartyDefinitions) {
		var client = relyingPartyDefinitions.getOidcClientByPredicate(
				c -> getNormalizedClientId(c.getId()).equals(normalizedClientId));
		return client.orElse(null);
	}

	// Multiple redirect_uri mentioned in specifications, some implementations might have mixed them up
	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
	public static String getRedirectUri(HttpServletRequest request) {
		var redirectUri = StringUtil.clean(request.getParameter(OidcUtil.LOGOUT_REDIRECT_URI)); // optional
		if (redirectUri == null) {
			// wrong but we have clients sending the same parameter as on /authorize
			redirectUri = StringUtil.clean(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
		}
		return redirectUri;
	}

	public static void setRedirectUri(HttpSession session, String redirectUri) {
		session.setAttribute(OIDC_SESSION_REDIRECT_URI, redirectUri);
	}

	public static String getInitialRedirectUri(HttpSession session) {
		return session != null ? (String) session.getAttribute(OIDC_SESSION_REDIRECT_URI) : null;
	}

	public static String getInitialClientState(HttpServletRequest request) {
		var state = StringUtil.clean(request.getParameter(OidcUtil.OIDC_STATE_ID));
		if (state != null) {
			return state;
		}
		var session = request.getSession(false);
		if (session == null) {
			return null;
		}
		var sessionState = session.getAttribute(OIDC_SESSION_CLIENT_STATE);
		if (sessionState instanceof String state2) {
			return state2;
		}
		return null;
	}

	// Use redirect parameters and HTTP headers to match a single client
	private static Set<String> getClientIdsFromMessageUrl(String messageUrl, String realm,
														  RelyingPartyDefinitions relyingPartyDefinitions) {
		Set<String> ret = new LinkedHashSet<>();
		if (relyingPartyDefinitions != null && messageUrl != null) {
			// Note: We could speed up locating client with using cl.isValidRedirectUri_s_ but ERROR less precise then
			var clients = relyingPartyDefinitions.getOidcClientsByPredicate(cl ->
					cl.isValidRedirectUri(messageUrl));
			if (clients.size() > 1) {
				// not enough information sent by client and matching via URL finds multiple configs using the same ACUrl
				var realmClients = clients.stream()
						.filter(cl -> cl.isSameRealm(realm))
						.distinct()
						.toList();
				if (realmClients.isEmpty()) {
					log.debug("Clients by messageUrl='{}' are ambiguous and trying realm={} has no result. HINT: Check "
									+ "Oidc.Client.realm correctness and application use and RedirectUris for redundancies.",
							messageUrl, realm);
				}
				else {
					clients = realmClients;
				}
			}
			clients.forEach(c -> ret.add(c.getId()));
		}
		return ret;
	}

	private static String getOidcSessionId() {
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			checkSessionHijacking(session);
			return session.getId();
		}
		return null;
	}

	private static String getAttributeFromPrincipal(Saml2AuthenticatedPrincipal principal,
													AttributeName attributeName,
													String clientId) {
		var attrs = principal.getAttribute(attributeName.getNamespaceUri());
		if (CollectionUtils.isEmpty(attrs)) {
			attrs = principal.getAttribute(attributeName.getName());
		}
		if (CollectionUtils.isEmpty(attrs)) {
			log.debug("No SSO join due to missing SAML attribute={} for clientId={} userPrincipal={}."
							+ " HINT: Claim not configured (check ClaimsSelection if you want full /app/sso and GLO support)",
					attributeName.getNamespaceUri(), clientId, principal.getName());
			return null;
		}
		return String.valueOf(attrs.get(0));
	}

	static String getSsoSessionIdFromPrincipal(Saml2AuthenticatedPrincipal principal, String clientId) {
		return getAttributeFromPrincipal(principal, CoreAttributeName.SSO_SESSION_ID, clientId);
	}

	public static StateData getStateData() {
		// spring wraps our request again so we either need to unwrap, use attributes or use our TX boundary
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			return session.getStateData();
		}
		return null;
	}

	public static String getSsoSessionId() {
		var session = getStateData();
		if (session != null) {
			return session.getSsoSessionId();
		}
		return null;
	}

	public static List<String> getSessionIdsFromAuthentication(Authentication authentication) {
		List<String> ret = Collections.emptyList();
		var principal = getSamlPrincipalFromAuthentication(authentication, null);
		if (principal != null) {
			// keep only our own added indexes (they might have even been duplicated by spring-calling us twice)
			ret = new ArrayList<>(principal.getSessionIndexes()); // copy-on-write
			while (ret.size() > 2) {
				ret.remove(0);
			}
		}
		return ret;
	}

	// main authentication context is SAML POST created context from XTB SAML side and the principal is therefore a SAML one
	public static Saml2AuthenticatedPrincipal getSamlPrincipalFromAuthentication(Authentication authentication,
																				 HttpServletRequest request) {
		var requestURI = request != null ? request.getRequestURI() : null;
		var oidcSessionId = getOidcSessionId();
		if (authentication == null) {
			log.info("No authentication found anymore for requestURI={} oidcSessionId={} from clientIP={}",
					requestURI, oidcSessionId, WebUtil.getClientIp(request));
		} else if (authentication.getPrincipal() == null) {
			log.error("Principal missing in authentication={} for requestURI={} oidcSessionId={} from clientIP={}",
					authentication.getName(), requestURI, oidcSessionId, WebUtil.getClientIp(request));
		} else if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal) {
			return principal;
		} else {
			log.error("Fishy principal in spring-security authenticatedPrincipal={}",
					authentication.getPrincipal().getClass());
		}
		return null;
	}

	public static void checkSessionHijacking(HttpSession session) {
		if (session != null) {
			var recordedSession = session.getAttribute(OIDC_SESSION_SESSION_ID);
			if (recordedSession != null && !recordedSession.equals(session.getId())) {
				throw new TechnicalException(String.format(
						"Prevented session hijacking on sessionId=%s owned by oidcSessionId=%s",
						session.getId(), recordedSession));
			}
		}
	}

	// make sure federation session tracking (OIDC session cookie) survives redirect from OIDC to SAML and back
	public static void checkSessionOnFederationRedirect(String path, HttpServletRequest request) {
		if (ApiSupport.isSpringFederationPath(path) && HttpExchangeSupport.getRunningHttpSession() == null) {
			var origin = StringUtil.clean(WebUtil.getOrigin(request));
			var referer = StringUtil.clean(WebUtil.getReferer(request));
			var cookies = StringUtil.clean(request.getHeader(HttpHeaders.COOKIE));
			var userAgent = StringUtil.clean(request.getHeader(HttpHeaders.USER_AGENT));
			throw new TechnicalException(String.format(
					"OIDC session on federation redirect missing on path='%s' userAgent='%s' referer='%s' origin='%s' cookies='%s'."
							+ " HINT: Check perimeterUrl and sessionCookieSameSite configurations.",
					path, userAgent, referer, origin, cookies));
		}
	}

	public static void setCurrentValuesFromExchange(
			TomcatSession session,
			String clientId,
			AuthenticatedPrincipal principal,
			String ssoSessionId,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		// track self-references on sessions to detect mistakes
		session.setOidcClientId(clientId);
		session.setAttributeInternal(OIDC_SESSION_CLIENT_ID, clientId);
		session.setAttributeInternal(OIDC_SESSION_SESSION_ID, session.getId());

		// error handling
		var currentRequest = HttpExchangeSupport.getRunningHttpRequest();
		if (currentRequest != null) {
			var redirectUri = getRedirectUri(currentRequest);
			if (redirectUri != null) {
				session.setAttributeInternal(OIDC_SESSION_REDIRECT_URI, redirectUri);
			}
			var state = currentRequest.getParameter(OidcUtil.OIDC_STATE_ID);
			if (state != null) {
				session.setAttributeInternal(OIDC_SESSION_CLIENT_STATE, state);
			}
		}

		// just tracking info (who and if SSO)
		if (ssoSessionId != null) {
			session.setAttributeInternal(SAML_SSO_SESSION_ID, ssoSessionId);
		}

		// login done we have a principal
		if (principal != null) {
			// leave a trace of the subject on HTTP and XTB session (DEBUG only)
			session.setAttributeInternal(SPRING_PRINCIPAL_NAME, principal.getName());
			session.setPrincipal(new SessionPrincipal(principal.getName()));
			session.getStateData().setSubjectNameId(principal.getName());
		}

		// NOTE: DB sync is triggered by spring-security context set

		// track on client to survive federation redirects and as a fallback to find auth state
		var request = HttpExchangeSupport.getRunningHttpRequest(); // we have a session, there must be a request
		var cookieName = getClientIdRelatedCookieName(clientId);
		var oidcSessionCookie = createOidcCookie(clientId, cookieName, session.getId(), true,
				request, relyingPartyDefinitions, trustBrokerProperties);
		var httpExchange = HttpExchangeSupport.getRunningHttpExchange();
		httpExchange.getResponse().addCookie(oidcSessionCookie);

		// exchange update also with client info
		// Note: Cookies for HTTP session tracking should only be emitted on OIDC side, SAML works without web session
		var req = httpExchange.getRequest();
		var host = req.getHeader(HttpHeaders.HOST);
		var conversationId = session.getStateData().getLastConversationId();
		if (principal != null) {
			// Note: Spring security sets the authentication context twice so this also gets logged twice (onResponse, final)
			if (!httpExchange.isAuthContextHandled()) {
				log.info("Established OIDC authentication for clientId={} userName={} ssoSessionId={} oidcSessionId={}"
								+ " conversationId={} trackingCookie={} on host={} requestUrl={}"
								+ " cookieValidSec={} cookieSecure={} ",
						clientId, principal.getName(), ssoSessionId, session.getId(),
						conversationId, oidcSessionCookie.getName(), host, req.getRequestURL(),
						oidcSessionCookie.getMaxAge(), oidcSessionCookie.getSecure());
				httpExchange.setAuthContextHandled(true);
			}
		}
		else {
			log.debug("Refresh OIDC authentication for clientId={} oidcSessionId={} conversationId={}"
							+ " trackingCookie={} on host={} requestUrl={} cookieValidSec={} cookieSecure={}",
					clientId, session.getId(), conversationId, oidcSessionCookie.getName(), host, req.getRequestURL(),
					oidcSessionCookie.getMaxAge(), oidcSessionCookie.getSecure());
		}
	}

	// Mainly Set-Cookie BSESSION_CLIENT_ID=sessionid to track the federated login and leave some cross-checking data on the
	// session, so we can validate when a session is retrieved not matching the caller context.
	// We keep the cookie as a hint to find client_id and session as a last resort to find the OIDC auth state in
	// getOidcSessionId.
	// NOTE: TomcatSession.getSession == HttpSession, they may have differing IDs potentially but not observed yet
	public static void setFinalValuesFromAuthentication(
			TomcatSession session,
			Object context,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties,
			StateCacheService stateCacheService, SsoService ssoService) {
		var securityContext = (SecurityContext) context;
		var saml2AuthenticatedPrincipal = getSamlPrincipalFromAuthentication(securityContext.getAuthentication(), null);
		if (saml2AuthenticatedPrincipal == null) {
			log.error("Unexpected call to setDerivedValuesFromAuthentication having authentication={} without a SAMl principal",
					securityContext.getAuthentication());
			return;
		}

		// leave some traces of the SAML side in the session
		var clientId = saml2AuthenticatedPrincipal.getRelyingPartyRegistrationId();
		var ssoSessionId = getSsoSessionIdFromPrincipal(saml2AuthenticatedPrincipal, clientId);

		// track in session and on client
		setCurrentValuesFromExchange(session, clientId,
				saml2AuthenticatedPrincipal, ssoSessionId,
				relyingPartyDefinitions, trustBrokerProperties);

		// leave some traces on the spring-sec context
		saml2AuthenticatedPrincipal.getSessionIndexes().add(ssoSessionId); // SAML side
		saml2AuthenticatedPrincipal.getSessionIndexes().add(session.getId()); // OIDC side

		// finally OIDC client as a participant on the SAML/SSO side
		// resilient fetch because we could have DB commit delays
		var ssoSession = stateCacheService.findBySsoSessionIdResilient(ssoSessionId, OidcSessionSupport.class.getName());
		ssoSession.ifPresent(state -> joinSsoSessionAsParticipant(stateCacheService, ssoService, state,
				saml2AuthenticatedPrincipal, session.getId()));
	}

	// Mainly Set-Cookie BSESSION_CLIENT_ID= to clear it.
	public static void clearDerivedValuesFromAuthentication(
			String clientId, String sessionId, String principalName,
			TrustBrokerProperties trustBrokerProperties) {
		var httpExchange = HttpExchangeSupport.getRunningHttpExchange();
		// best effort, logout might not contain any reference to session or client, so we do not clear the cookie then
		if (httpExchange != null && clientId != null) {
			boolean cookieSecure = trustBrokerProperties.isSecureBrowserHeaders();
			discardOidcClientCookie(clientId, httpExchange.getResponse(), cookieSecure);
			if (log.isDebugEnabled()) {
				log.debug("Cleared OIDC authentication for principalName={} clientId={} oidcSessionId={} "
								+ "trackingCookie={} on requestUrl={} cookieSecure={}",
						principalName, clientId, sessionId,
						getClientIdRelatedCookieName(clientId), httpExchange.getRequest().getRequestURL(), cookieSecure);
			}
		}
	}

	// Try our best, not the end of the world if that cookie survives, it's mostly a marker only.
	public static void clearDerivedValuesFromAuthentication(
			TomcatSession session, Object context,
			TrustBrokerProperties trustBrokerProperties) {
		if (context == null) {
			return;
		}
		var securityContext = (SecurityContext) context;
		var saml2AuthenticatedPrincipal = getSamlPrincipalFromAuthentication(securityContext.getAuthentication(), null);
		if (saml2AuthenticatedPrincipal != null) {
			var clientId = saml2AuthenticatedPrincipal.getRelyingPartyRegistrationId();
			clearDerivedValuesFromAuthentication(clientId, session.getId(), saml2AuthenticatedPrincipal.getName(),
					trustBrokerProperties);
		}
	}

	public static Saml2AuthenticatedPrincipal getAuthenticatedPrincipal(TomcatSession tomcatSession) {
		if (tomcatSession == null) {
			return null;
		}
		var securityContext = tomcatSession.getSecurityContext();
		if (securityContext == null) {
			return null;
		}
		return getSamlPrincipalFromAuthentication(securityContext.getAuthentication(), null);
	}

	// SSOService creates a mapping session for the StateData.ssoSessionId on establishing an SSO session.
	// A joining OIDC participant si added for GLO handling.
	// If there is no XTB SSO session an OIDC client exists on its own.
	// So summarized we have these session identifiers:
	// - Primary sessionId (SESS1) belongs to XTB_encoded_cp_subject
	// - SP SAML mapping spSessionId (SESS1): UUID belongs to the relying party
	// - SP OIDC mapping spSessionId (SESS2): BSESSIONID from HTTP session manager for OIDC login/logout
	private static void joinSsoSessionAsParticipant(StateCacheService stateCacheService, SsoService ssoService,
													StateData stateData, Saml2AuthenticatedPrincipal principal, String oidcSessionId) {
		if (!ssoService.isOidcPrincipalAllowedToJoinSsoSession(stateData, principal.getName(), oidcSessionId)) {
			return;
		}

		// OIDC session tracking on SSO session
		stateData.setOidcSessionId(oidcSessionId);
		stateData.getSpStateData().setOidcSessionId(oidcSessionId);
		log.trace("Updated ssoSessionId={} with oidcSessionId={}", stateData.getId(), oidcSessionId);

		// Adding OIDC application clients as session participant is a nice to have feature
		var clientId = principal.getRelyingPartyRegistrationId();
		var cpId = getAttributeFromPrincipal(principal, CoreAttributeName.HOME_REALM, clientId);
		if (cpId == null) {
			log.info("Ignore OIDC participant to join SSO session={}: participant={} (no {})",
					stateData.getId(), clientId, CoreAttributeName.HOME_REALM.getName());
			return;
		}

		// join
		var participant = SsoSessionParticipant.builder()
				.rpIssuerId(null) // OIDC clients are not tracked via RelyingParty.id
				.oidcClientId(clientId)
				.cpIssuerId(cpId)
				.assertionConsumerServiceUrl(stateData.getRpReferer())
				.oidcSessionId(oidcSessionId)
				.build();
		stateData.addSsoParticipant(participant);
		log.debug("Added OIDC participant to SSO session={}: participant={}", stateData.getId(), participant);

		addSsoCookie(ssoService, stateData);

		// save
		stateCacheService.save(stateData, OidcSessionSupport.class.getSimpleName());
		log.info("Updated sessionId={} with oidcSessionId={} userPrincipal=\"{}\" sessionIndexes={} clientId={} cpIssuer={}",
				stateData.getId(), oidcSessionId, principal.getName(), principal.getSessionIndexes(), clientId, cpId);
	}

	private static void addSsoCookie(SsoService ssoService, StateData stateData) {
		// SSO cookie for established session on OIDC domain
		var cookie = ssoService.generateCookie(stateData);
		HttpExchangeSupport.getRunningHttpResponse().addCookie(cookie);
		log.debug("Added SSO cookie={} for OIDC domain", cookie.getName());
	}

	public static StateData getSsoStateDataForClient(SsoService ssoService, HttpServletRequest request,
													 RelyingParty relyingParty,
													 String oidcClientId) {
		var stateData = HttpExchangeSupport.getRunningSsoState();
		if (stateData != null) {
			log.debug("Found running SSO stateId={}", stateData.getId());
			return stateData;
		}
		var states = ssoService.findValidStatesFromCookies(relyingParty, request.getCookies());
		var matchingStates = states.stream()
				.filter(state -> oidcClientParticipatingInSsoSession(state, oidcClientId))
				.toList();
		if (matchingStates.size() == 1) {
			stateData = matchingStates.get(0);
			log.debug("Found stateId={} from SSO cookies for rpIssuer={} clientId={}",
					stateData.getId(), relyingParty.getId(), oidcClientId);
		} else if (matchingStates.isEmpty()) {
			log.debug("Found no states from SSO cookies for rpIssuer={} clientId={}", relyingParty.getId(), oidcClientId);
		} else if (log.isInfoEnabled()) {
			// Cannot decide on the session.
			// (No OIDC session found, the principal could match some information in session depending on the config.)
			// The user could be prompted to select the session to logout from, but so far we lack a UI for that.
			log.info("Ignoring multiple matching stateIds={} from SSO cookies for rpIssuer={} clientId={}",
					matchingStates.stream()
							.map(StateData::getId)
							.toList(), relyingParty.getId(), oidcClientId);
		}
		return stateData;
	}

	private static boolean oidcClientParticipatingInSsoSession(StateData stateData, String oidcClientId) {
		var participants = stateData.initializedSsoState()
				.getSsoParticipants();
		return participants.stream()
				.anyMatch(participant -> oidcClientId.equals(participant.getOidcClientId()));
	}

	// return from federated login is done on an OIDC session already
	public static String getSamlExchangeClientId() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request != null) {
			return getSamlExchangeClientId(request.getRequestURI());
		}
		return null;
	}

	// Federation in both directions
	// /login/saml2/sso/client_id => client_id
	// /saml2/authenticate/client_id => client_id
	public static String getSamlExchangeClientId(String acsUrlPath) {
		if (acsUrlPath != null) {
			// SAML AuthnRequest by OIDC side to SAML side
			if (acsUrlPath.startsWith(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH)) {
				return acsUrlPath.split("/")[3];
			}
			// SAML Response from SAML side to OIDC side
			if (acsUrlPath.startsWith(ApiSupport.SPRING_SAML_FEDERATION_CTXPATH)) {
				return acsUrlPath.split("/")[4];
			}
		}
		return null;
	}

	// Federation from CP to RP on SAML response
	// https://domain/login/saml2/sso/client_id => client_id
	public static String getSamlExchangeAcsUrlClientId(String acsUrl) {
		// SAML AuthnRequest AssertionConsumerService URL received on SAM side
		if (acsUrl != null && acsUrl.contains(ApiSupport.SPRING_SAML_FEDERATION_CTXPATH)) {
			return acsUrl.replaceAll(".*" + ApiSupport.SPRING_SAML_FEDERATION_CTXPATH, "");
		}
		return null;
	}

	public static void invalidateSession(TrustBrokerProperties trustBrokerProperties, String errMsg) {
		var session = HttpExchangeSupport.getRunningHttpSession();
		var request = HttpExchangeSupport.getRunningHttpRequest();
		var response = HttpExchangeSupport.getRunningHttpResponse();
		if (session == null || request == null || response == null) {
			log.debug("Requiring all of session={} httpRequest={} httpResponse={}", session, request, response);
			return;
		}
		var clientId = session.getOidcClientId();
		invalidateSession(request, response, trustBrokerProperties, clientId, errMsg);
	}

	public static void invalidateSession(HttpServletRequest request, HttpServletResponse response,
										 TrustBrokerProperties trustBrokerProperties, String clientId, String errMsg) {
		var session = request.getSession(false);
		if (session != null) {
			discardOidcClientCookie(clientId, response, trustBrokerProperties.isSecureBrowserHeaders());
			log.debug("Cleared OIDC web sessionId={} because of failure='{}'", session.getId(), errMsg);
			session.invalidate();
		}
	}

	// To be able to have multiple OIDC clients in parallel we need to discard the global container based cookie
	// tracking as soon as the client got what he needed.
	public static void discardOidcGlobalCookie(HttpServletResponse response, boolean secure) {
		var params = CookieParameters.builder()
				.name(CONTAINER_SESSION_COOKIE_NAME)
				.value("")
				.maxAge(0)
				.secure(secure)
				.httpOnly(true)
				.build();
		var discardCookie = WebUtil.createCookie(params);
		response.addCookie(discardCookie);
	}

	public static void discardOidcClientCookie(String clientId, HttpServletResponse response, boolean secure) {
		var params = CookieParameters.builder()
				.name(getClientIdRelatedCookieName(clientId))
				.value("")
				.maxAge(0)
				.secure(secure)
				.httpOnly(true)
				.build();
		var discardCookie = WebUtil.createCookie(params);
		response.addCookie(discardCookie);
		discardOidcGlobalCookie(response, secure);
	}

	// If client wants to force a login we ignore returning a session, SAML side handles the forceAuthn=true afterward.
	// keycloak.js: Set options.prompt="login" in the console for the /authorize call to trigger a re-login.
	// This will loop because the adapter stores the options in the browser storage so a completed login triggers again
	static TomcatSession invalidateSessionOnPromptLoginOrStepup(
			TomcatSession session, String clientId, NetworkConfig networkConfig) {
		if (session == null) {
			return null;
		}

		// pending OIDC transaction
		var request = HttpExchangeSupport.getRunningHttpRequest();

		// pending login federation signaled by spring-security (see HttpSessionRequestCache)
		if (isAuthorizeInFederation(request)) {
			log.debug("Returning from federated login and continue with authorization_code generation for clientId={}", clientId);
			return session;
		}

		// discard session when a QoA step-up might be required
		if (isAcrValuesStepUpRequired(request, session, clientId)) {
			handleSessionDiscard(clientId, request, OidcUtil.OIDC_ACR_VALUES, networkConfig);
			return null;
		}

		// discard session when prompt=login forces a federated login
		if (OidcUtil.isOidcPromptLogin(request)) {
			handleSessionDiscard(clientId, request, OidcUtil.OIDC_PROMPT, networkConfig);
			return null;
		}

		return session;
	}

	public static void invalidateSsoState(HttpServletRequest request, StateCacheService stateCacheService,
										  StateData stateData, String actor) {
		if (!HttpExchangeSupport.isRunningLogoutRequest(request)) {
			return; // keep SSO session
		}
		// find SSO session...
		var ssoSessionId = stateData.getSsoSessionId();
		if (ssoSessionId == null) {
			return;
		}
		var ssoStateData = stateCacheService.findBySsoSessionId(ssoSessionId, actor);
		if (ssoStateData.isEmpty()) {
			return;
		}
		// ...and invalidate it without notifications
		ssoStateData.ifPresent(s -> {
			if (s.getSsoState().getSsoParticipants().size() > 2) {
				log.info("SSO/GLO notifications incomplete triggered by sessionId={} clientId={} participants='{}'",
						stateData.getId(), stateData.getOidcClientId(), s.getSsoState().getSsoParticipants());
			}
			// retain a reference for the SLO handling
			HttpExchangeSupport.getRunningHttpExchange().setSsoState(s);
			stateCacheService.tryInvalidate(s, actor);
		});
	}

	static String getCookieSameSite(Optional<OidcClient> client,
									HttpServletRequest request, TrustBrokerProperties trustBrokerProperties) {
		String sameSite = null;
		if (client.isPresent()) {
			sameSite = client.get().getOidcSecurityPolicies().getSessionCookieSameSite();
		}
		if (WebUtil.isSameSiteDynamic(sameSite)) {
			var redirectUri = getRedirectUri(request);
			// Dynamic mapped to STRICT when redirect_uri in message matches perimeterUrl from config, otherwise use global default
			sameSite = redirectUri == null ?
					trustBrokerProperties.getCookieSameSite() :
					WebUtil.getCookieSameSite(trustBrokerProperties.getPerimeterUrl(), redirectUri);
			// SameSite=None not allowed on insecure transports
			if (!request.isSecure() && WebUtil.COOKIE_SAME_SITE_NONE.equalsIgnoreCase(sameSite)) {
				log.debug("Discarding SameSite=None on insecure transport");
				sameSite = null;
			}
		} else if (client.isPresent()) { // must be present
			log.debug("OidcClient={} requires cookie sameSite={}", client.get().getId(), sameSite);
		}
		return sameSite;
	}

	private static int getSessionTtlFromClientConfig(Optional<OidcClient> client,
													 TrustBrokerProperties trustBrokerProperties) {
		if (trustBrokerProperties.getOidc().isSessionCookie()) {
			return WebSupport.COOKIE_MAXAGE_SESSION;
		}
		// persist cookie marked with configured session TTL
		var ttl = trustBrokerProperties.getOidc().getSessionLifetimeSec(); // 1800
		if (client.isPresent()) {
			var policies = client.get().getOidcSecurityPolicies();
			if (policies.getTokenTimeToLiveMin() != null) { // undefined per default
				ttl = 60 * policies.getTokenTimeToLiveMin();
			}
			if (policies.getSessionTimeToLiveMin() != null) { // undefined per default
				ttl = 60 * policies.getSessionTimeToLiveMin();
			}
		}
		return ttl;
	}

	public static String getStateParam(HttpServletRequest request) {
		return StringUtil.clean(request.getParameter(OidcUtil.OIDC_STATE_ID));
	}

	public static String getSessionInitiator() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request == null) {
			return null;
		}
		var initiator = getRedirectUri(request);
		if (initiator == null) {
			initiator = WebUtil.getOriginOrReferer(request);
		}
		return initiator;
	}

	public static void rememberAcrValues(HttpServletRequest request) {
		var messageAcrValues = OidcUtil.getAcrValues(request);
		if (!messageAcrValues.isEmpty() && request.getSession(false) instanceof TomcatSession session) {
			session.getStateData().setContextClasses(messageAcrValues);
		}
	}

	public static boolean isAcrValuesStepUpRequired(HttpServletRequest request, TomcatSession session, String clientId) {
		var messageAcrValues = OidcUtil.getAcrValues(request);
		var sessionAcrValues = session.getStateData().getContextClasses();
		if (sessionAcrValues != null && !messageAcrValues.equals(sessionAcrValues)) {
			log.info("OIDC step-up triggered by clientId={} with messageAcrValues='{}' not matching sessionAcrValues='{}'",
					clientId, messageAcrValues, sessionAcrValues);
			return true;
		}
		return false;
	}

	private static boolean isAuthorizeInFederation(HttpServletRequest request) {
		var savedRequest = request.getParameter("continue"); // spring-security v6 uses message tagging
		var authPath = ApiSupport.isOidcAuthPath(request.getRequestURI());
		return !authPath || savedRequest != null;
	}

	private static void handleSessionDiscard(String clientId, HttpServletRequest request,
											 String triggerParameter, NetworkConfig networkConfig) {
		var triggerValue = StringUtil.clean(request.getParameter(triggerParameter));
		var referer = WebUtil.getValidOrigin(WebUtil.getOriginOrReferer(request));
		log.info("Drop web session for clientId={} triggered by {}='{}' on endpoint={} called by referer='{}' from network='{}'",
				clientId, triggerParameter, triggerValue, request.getRequestURI(),
				referer, WebSupport.getClientHint(request, networkConfig));
		request.getSession()
				.invalidate();
	}

	static boolean isSessionIdOidcToken(String sessionId) {
		return sessionId.endsWith(OIDC_TOKEN_SESSION_SUFFIX);
	}

	static String extractTokenFromSessionId(String sessionId) {
		return sessionId.substring(0, sessionId.length() - OIDC_TOKEN_SESSION_SUFFIX.length());
	}
}
