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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Session;
import org.apache.catalina.session.ManagerBase;
import org.apache.commons.lang3.SerializationUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.TomcatSessionMode;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.CustomOAuth2AuthorizationService;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.oidc.tx.OidcTxRequestWrapper;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Inspired by (but not copied from) hazelcast-tomcat-sessionmanager
 */
@Slf4j
@AllArgsConstructor
public class TomcatSessionManager extends ManagerBase {

	private static final String NAME = TomcatSessionManager.class.getSimpleName();

	private final StateCacheService stateCacheService;

	private final SsoService ssoService;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final TomcatSessionMode mode; // mode is defined in application.yml

	private final CustomOAuth2AuthorizationService customOAuth2AuthorizationService;

	@Override
	public void startInternal() throws LifecycleException {
		setState(LifecycleState.STARTING);
		super.startInternal();
		super.generateSessionId();
		// set an upper limit to work against (D)DOS in BOTH and IN_MEMORY mode
		super.setMaxActive(trustBrokerProperties.getStateCache().getTargetMaxEntries() * 2);
		super.setPersistAuthentication(true); // principal to/from DB for logout
		log.info("{} started (using sessionMode={})", NAME, mode);
	}

	@Override
	public void stopInternal() throws LifecycleException {
		log.info("{} stopping...", NAME);
		setState(LifecycleState.STOPPING);
		super.stopInternal();
		log.info("{} stopped", NAME);
	}

	@Override
	public void load() {
		log.info("Skip loading sessions from start cache");
	}

	@Override
	public void unload() {
		log.info("Skip offloading sessions into shutdown cache");
	}

	@Override
	public Session createEmptySession() {
		return new TomcatSession(this);
	}

	@Override
	public Session createSession(String sessionId) {
		// new sessions only for OIDC
		if (!HttpExchangeSupport.isRunningOidcExchange()) {
			log.error("Unexpected call to createSession({}), check session load/save boundary", sessionId);
		}

		// new initial session
		var session = new TomcatSession(this);
		var newSessionId = sessionId != null ? sessionId : generateSessionId();
		var cacheTtl = getCacheTtl(trustBrokerProperties.getSsoSessionLifetimeSec());
		log.debug("Create session newSessionId={} sessionId={} cacheTtlSec={}", newSessionId, sessionId, cacheTtl);
		session.setId(newSessionId);
		session.setNew(true);
		session.setValid(true);
		session.setCreationTime(System.currentTimeMillis());
		session.setMaxInactiveInterval(cacheTtl);
		session.setPrincipal(new SessionPrincipal("ANONYMOUS")); // prevent session save warnings
		logSession(session, "createSession");

		// attach sessiondb state (also IN_MEMORY mode only, just not saved/loaded)
		checkAndInitStateData(session);

		// also remember this via cookies for OIDC clients running on federation
		setCurrentValuesFromExchange(session);
		return session;
	}

	// Create an initial session with sessiondb backing
	private static StateData createSessionState(String clientId, String sessionId, long sessionTtl) {
		// Session lifecycle depending on SSO or not:
		// - SSO: We inherit the XTB SSO session and should not end up here
		// - OIDC: We need the session for the OIDC lifecycle depending on token and refresh_token lifetime
		// Session TTL is handled on established authentication later.
		var nowInstant = Instant.now();
		var now = Timestamp.from(nowInstant);
		var expiration = nowInstant.plusSeconds(sessionTtl);
		var exp = Timestamp.from(expiration);
		var lifecyle = Lifecycle.builder()
				.lifecycleState(swiss.trustbroker.sessioncache.dto.LifecycleState.ESTABLISHED)
				.initTime(now)
				.expirationTime(exp)
				.build();
		log.debug("Created sessionId={} expirationTime='{}'", sessionId, expiration);
		// SP side state (note that we are not SSO ourselves except for the client_id using the BSESSION_CLIENT_ID related state)
		var initiator = OidcSessionSupport.getSessionInitiator();
		return StateData.builder()
				.id(sessionId) // primary key for OIDC session
				.oidcClientId(clientId)
				.oidcSessionId(sessionId) // just for completeness, findByOidcSessionId will return 2 sessions
				.subjectNameId("<ANONYMOUS>")
				.lifecycle(lifecyle) // no SsoState
				.referer(initiator)
				.build();
	}

	@Override
	public TomcatSession findSession(String id) {
		// session check without a key? no way
		if (id == null) {
			id = OidcSessionSupport.getOidcSessionId(null, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		}
		if (id == null) {
			return null;
		}
		if (!HttpExchangeSupport.isRunningOidcExchange()) {
			log.trace("SESSMGR.findSession sessionId={} not yet ready assuming getSession(false)", id);
			return null;
		}

		// cache for faster processing, update triggered by isValid()
		var session = (TomcatSession) sessions.get(id);
		if (session == null && mode != TomcatSessionMode.IN_MEMORY) {
			session = findSessionState(id);
			// pulled from DB created on other service instance and we cache
			if (session != null) {
				log.debug("SESSMGR.findSession sessionId={} clientId={} tokens={} attributes={} loaded into MEMORY",
						id, session.getOidcClientId(), session.getTokenCount(), session.getAttributeCount());
				// check if session shall be ignored
				session = checkOidcSubSession(session);
			}
		}

		// security check: we assert that the new session ID is not ambiguous: Don't trust a distributed
		// random generator and better have a blocked login than session hijacking.
		if (session != null) {
			OidcSessionSupport.checkSessionHijacking(session.getSession());
		}
		return session;
	}

	// Session not cached yet on sessions so try to load it from DB.
	// We only do that for OIDC related sessions knowing the client_id derived from various requests data in getOidcClientId.
	private TomcatSession findSessionState(String sessionId) {
		try {
			if (mode == TomcatSessionMode.IN_MEMORY) {
				log.error("Unexpected call to {}.findSessionState() for IN_MEMORY mode", NAME);
			}
			// Fetch from DB because request could run in another POD
			// WARN: All the request.getSession(false) could trigger this, so we have a bit of a DB query overhead
			// NOTE: Finding web session by token is deprecated as we use the oauth2_authorization table after login too.
			Optional<StateData> stateData = Optional.empty();
			if (sessionId != null) {
				if (!OidcSessionSupport.isSessionIdOidcToken(sessionId)) {
					stateData = stateCacheService.findOptionalResilient(sessionId, NAME);
				}
				else {
					// find session by token
					sessionId = OidcSessionSupport.extractTokenFromSessionId(sessionId);
					var authorization = findAuthorizationByToken(sessionId);
					if (authorization != null) {
						OAuth2Authorization.Token<OidcIdToken> token = authorization.getToken(OidcIdToken.class);
						if (token == null) {
							log.error("Could not find OIDC token for sessionId={}", sessionId);
							return null;
						}
						sessionId = token.getToken().getClaim(OidcUtil.OIDC_SID).toString();
						stateData = stateCacheService.findOptionalResilient(sessionId, NAME);
					}
				}
			}
			else {
				log.info("Missing state ID in call from actor={}", NAME);
			}

			if (stateData.isEmpty()) {
				return null;
			}

			// bail out on IN_DB expiration (state or time driven)
			if (stateData.get().isExpired()) {
				log.info("IN_DB sessionId={} has expired state, ignoring it. Lifecycle data: {}",
						sessionId, stateData.get().getLifecycle());
				return null;
			}
			if (stateData.get().isOverdueAt(Instant.now())) {
				log.info("IN_DB sessionId={} is overdue, ignoring it. Lifecycle data: {}",
						sessionId, stateData.get().getLifecycle());
				return null;
			}
			if (stateData.get().getOidcSessionData() == null) {
				log.error("IN_DB sessionId={} saved with data=null, ignoring it. Check code.", sessionId);
				return null;
			}

			// really load
			var session = decodeSession(stateData.get(), sessionId);
			return attachStateData(session, stateData.get());
		}
		catch (TechnicalException ex) {
			// WARN: If we get a new embedded tomcat here it's possible that deserialization fails
			log.error("Failed to load OIDC sessionId={} from DB: {}", sessionId, ex.getInternalMessage(), ex);
		}
		return null;
	}

	private OAuth2Authorization findAuthorizationByToken(String token) {
		if (token == null || token.isEmpty()) {
			log.debug("No authorization token found");
			return null;
		}
		var authorization = customOAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			// find session by IdToken (logout with encrypted IdToken hint)
			authorization = customOAuth2AuthorizationService.findByToken(token, new OAuth2TokenType(OidcUtil.TOKEN_RESPONSE_ID_TOKEN));
		}
		return authorization;
	}

	@Override
	protected void changeSessionId(Session session, String newId, boolean notifySessionListeners,
			boolean notifyContainerListeners) {
		logSession(session, "changeSessionId");
		var oldId = session.getId();
		super.changeSessionId(session, newId, notifySessionListeners, notifyContainerListeners);
		if (session instanceof TomcatSession tomcatSession) {
			changeSessionState(tomcatSession, oldId, newId);
		}
	}

	private int getCacheTtl(long cacheTtl) {
		return mode == TomcatSessionMode.IN_DB ? -1 : (int) cacheTtl; // -1 means expiration is handled IN_DB only
	}

	@Override
	public void processExpires() {
		var count = sessions.size();
		var sessionLimit = trustBrokerProperties.getStateCache().getTargetMaxEntries() / 10 * 8; // 80%
		if (mode == TomcatSessionMode.IN_DB && count < sessionLimit) {
			log.debug("Session cache reaper not required IN_DB mode would run on sessionCount={} items now", count);
			return;
		}
		if (count >= sessionLimit) {
			log.warn("Session cache has sessionCount={} items, growing above warnLimit={} (80%)", count, sessionLimit);
		}
		log.debug("Session cache reaping sessionCount={} items", count);
		super.processExpires();
	}

	private void changeSessionState(TomcatSession session, String oldId, String newId) {
		log.debug("SESSMGR.changeSessionId sessionId={} tokens={} attributes={} switching oldSessionId={} to newSessionId={}",
				session.getId(), session.getTokenCount(), session.getAttributeCount(), oldId, newId);
		setCurrentValuesFromExchange(session);
		var oldDbState = session.getStateData();
		if (!oldId.equals(oldDbState.getId())) {
			throw new TechnicalException(String.format("Unexpected session/dbState oldId=%s dbOldId=%s",
					oldId, oldDbState.getId()));
		}
		var newDbState = SerializationUtils.clone(oldDbState);
		newDbState.setId(newId); // primary key
		newDbState.setOidcSessionId(newId); // just FYI
		// init time set to time of session ID change for later re-calculation of expirationTime,
		// which may be updated in updateSessionExpirationSettings
		var now = Instant.now();
		newDbState.getLifecycle().setInitTime(Timestamp.from(now));
		if (log.isDebugEnabled()) {
			log.debug("Updated init time of changed sessionId={} initTime={} expirationTime={}", newDbState.getId(), now,
					newDbState.getLifecycle().getExpirationTime().toInstant());
		}
		session.setStateData(newDbState);
		// switch complete: clean up, TX boundary will save the new state
		stateCacheService.tryInvalidate(oldDbState, NAME);
	}

	// remove/add is triggered on TomcatSession.changeSessionId to prevent session pinning
	@Override
	public void add(Session session) {
		logSession(session, "add");
		super.add(session);
		// we always deal with TomcatSessions
		if (!(session instanceof TomcatSession tomcatSession)) {
			throw new TechnicalException(String.format("sessionId=%s has class=%s expected TomcatSession",
					session.getId(), session.getClass().getName()));
		}
		// remember that we also need to save it
		HttpExchangeSupport.getRunningHttpExchange().setOidcSession(tomcatSession);
	}

	// called on changeSessionId (add/remove) with update=false
	// called by logout/invalidate/expire to clean up sessions with update=true
	@Override
	public void remove(Session session, boolean update) {
		logSession(session, "remove");
		if (update && mode != TomcatSessionMode.IN_MEMORY) {
			var sess = (TomcatSession) sessions.get(session.getId());
			if (sess != null && sess.getStateData() != null) {
				invalidateSessionState(sess.getStateData());
			}
		}
		// remove from cache (super.remove actually does the same with update=false)
		super.remove(session, update);
		// save session will also be done invalidated as IN_DB we keep track with the StateCacheService reaper
	}

	private void invalidateSessionState(StateData stateData) {
		// SSO session (on logout only)
		OidcSessionSupport.invalidateSsoState(null, stateCacheService, stateData, NAME);

		// OIDC session
		stateCacheService.tryInvalidate(stateData, NAME);
	}

	@Override
	public void expireSession(String sessionId) {
		// all just INFO logging
		if (mode == TomcatSessionMode.IN_DB) {
			log.debug("SESSMGR.expireSession sessionId={} IN_DB handled by {} and remove()", sessionId, NAME);
		}
		var session = sessions.get(sessionId);
		if (session instanceof TomcatSession tomcatSession) {
			logSession(session, "expireSession");
			// only insights when session is also held IN_MEMORY, on logout we get INFO too
			var principalName = session.getPrincipal();
			var clientId = tomcatSession.getOidcClientId();
			log.info("Expire OIDC authentication for userName={} clientId={} oidcSessionId={}",
					principalName, clientId, sessionId);
			remove(tomcatSession); // invalidate in DB
		}
		// standard procedure
		super.expireSession(sessionId); // invalidate in tomcat
	}

	public void load(OidcTxRequestWrapper request) {
		// assume session handling on all these paths
		if (!request.isOidcSessionPath()) {
			log.trace("No OIDC session handling on path={}", request.getRequestURI());
			return;
		}

		// mark interchange as potentially stateful (optimization to not to session checking on /app and /api)
		var clientId = OidcSessionSupport.getOidcClientId(request, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		HttpExchangeSupport.setRunningOidcClientId(clientId);

		// authorize code interchange
		var sessionId = OidcSessionSupport.getOidcSessionId(
				request, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		if (sessionId == null) {
			return;
		}

		// if found, make sure we also cached it during execution, and it was not expiring in the meantime in sessiondb
		var session = findSession(sessionId);
		if (isSessionValid(session)) {
			ensureSessionIsCached(session);
			// we now run on the OIDC session
			HttpExchangeSupport.getRunningHttpExchange().setOidcSession(session);
			request.setSubSession(session);

			var lifecycle =  session.getStateData().getLifecycle();
			lifecycle.incAccessCount();

			if (log.isDebugEnabled()) {
				var oidcData = session.getStateData().getOidcSessionData();
				log.debug("SESSMGR.load session cacheCount={} sessionId={} clientId={} oidcSessionId={}"
						+ " refreshToken={} accessCount={} expirationTime='{}' size={} tokens={} attributes={} {}",
						sessions.size(),
						session.getId(),
						session.getOidcClientId(),
						session.getStateData().getOidcSessionId(),
						session.getStateData().getOidcRefreshToken(),
						lifecycle.getAccessCount(),
						lifecycle.getExpirationTime().toInstant(),
						oidcData != null ? oidcData.length() : null,
						session.getTokenCount(),
						session.getAttributeCount(),
						Collections.list(session.getAttributeNames()));
			}
		}

		if (isSessionInvalid(session)) {
			log.info("Discard sessionId={} expired in the sessiondb", session.getId());
		}
	}

	private void ensureSessionIsCached(TomcatSession session) {
		var cachedSession = sessions.get(session.getId());
		if (cachedSession == null) {
			throw new TechnicalException(String.format(
					"Loaded OIDC sessionId=%s not found in cache. Check code.", session.getId()));
		}
	}

	private static boolean isSessionInvalid(TomcatSession session) {
		return session != null && !session.isValid();
	}

	private static boolean isSessionValid(TomcatSession session) {
		return session != null && session.isValid(); // computes expiration and sends events
	}

	private TomcatSession checkOidcSubSession(TomcatSession session) {
		// if session does not belong to a new exchange
		var request = HttpExchangeSupport.getRunningHttpRequest();
		var messageClient = OidcSessionSupport.getOidcClientId(
				request, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		var sessionClient = session.getAttribute(OidcSessionSupport.OIDC_SESSION_CLIENT_ID);
		if (sessionClient != null && messageClient != null && !sessionClient.equals(messageClient)) {
			log.info("Ignoring sessionClientId={} sessionId={} for messageClient={}",
					sessionClient, session.getId(), messageClient);
			return null; // session does not match current exchange
		}

		// found, cache for further processing
		sessions.put(session.getIdInternal(), session);

		// session invalidate if forced, otherwise continue with it
		return OidcSessionSupport.invalidateSessionOnPromptLoginOrStepup(session,
				messageClient, trustBrokerProperties.getNetwork());
	}

	private boolean isClearSessionsInSingleUserTesting(String sessionId) {
		return trustBrokerProperties.isServerSingleUser()
				&& trustBrokerProperties.getOidc().getSessionMode() != TomcatSessionMode.IN_MEMORY
				&& (!sessions.isEmpty() && (sessionId == null || sessions.get(sessionId) == null));
	}

	public void save() {
		// No or no OIDC session yet (OIDC sessions are de-coupled from web container sessions with spring-sec/6
		var session = HttpExchangeSupport.getRunningHttpSession();
		var sessionId = session != null ? session.getId() : null;

		// proper IN_DB testing with a single process by clearing any leaking sessions
		if (isClearSessionsInSingleUserTesting(sessionId)) {
			log.error("Clearing sessions={} for incoming sessionId={} in single user DEV mode",
					CollectionUtil.toLogString(sessions.keySet()), sessionId);
			sessions.clear();
		}

		// no session yet in this exchange
		if (sessionId == null) {
			return;
		}

		// cache => make sure it's getting loaded when changed on another pod
		if (mode == TomcatSessionMode.IN_DB) {
			sessions.remove(sessionId);
		}

		// consistent code
		var state = session.getStateData();
		if (!state.getId().equals(sessionId)) {
			// inconsistent code, our session is not in sync anymore with our primary DB key
			throw new TechnicalException(String.format("Cannot save sessionId=%s in dbSessionId=%s",
					sessionId, state.getId()));
		}

		// save to sessiondb (also if session was invalidated because stateData was marked as EXPIRED)
		if (mode != TomcatSessionMode.IN_MEMORY) {
			var stateDateString = encodeSession(session);
			state.setOidcSessionData(stateDateString);
			var expiration = state.getLifecycle().getExpirationTime().toInstant();
			stateCacheService.save(state, expiration, NAME);
		}
		if (log.isDebugEnabled()) {
			var attrNames = session.isValid() ? Collections.list(session.getAttributeNames()) : List.of();
			var lifecycle = session.getStateData().getLifecycle();
			log.debug("SESSMGR.save session cacheCount={} sessionId={} clientId={} oidcSessionId={}"
							+ " refreshToken={} accessCount={} expirationTime='{}' size={} tokens={} attributes={} {}",
					sessions.size(),
					session.getId(),
					session.getOidcClientId(),
					session.getStateData().getOidcSessionId(),
					session.getStateData().getOidcRefreshToken(),
					lifecycle.getAccessCount(),
					lifecycle.getExpirationTime().toInstant(),
					state.getOidcSessionData().length(),
					session.getTokenCount(),
					session.getAttributeCount(),
					attrNames);
		}
	}

	// Addon method storing state in DB on setAttribute and friends
	// Context means we have an established OIDC login leading to increased timeouts.
	void updateSession(TomcatSession session, Object context) {
		logSession(session, "updateSession");

		// attach SSO state received from SAMl side
		var clientId = session.getOidcClientId();
		attachSsoSession(session, clientId, context);

		// update session timeouts when we receive an authentication context
		if (context != null) {
			updateSessionExpirationSettings(session, clientId);
		}
	}

	// Initial timing is applied for the interchange with the federated CP.
	private int getInitialTtlSec() {
		// around 10 to 30 minutes to allow a slow login paying with many sessions IN_DB
		return trustBrokerProperties.getOidc().getSessionLifetimeSec();
	}

	// Established timing is usually in sync with the token lifetime per RP/client/application.
	private int getEstablishedTtlSec(OidcClient oidcClient) {
		// allow shorter OIDC session lifetime
		var ttlMin = oidcClient.getOidcSecurityPolicies().getSessionTimeToLiveMin();
		if (ttlMin == null) {
			ttlMin = oidcClient.getOidcSecurityPolicies().getTokenTimeToLiveMin();
		}
		if (ttlMin == null) {
			return getInitialTtlSec(); // stay on initial values, should not happen - value in seconds, returned as is
		}
		// session remains for at least 10sec to finish the login sequence, otherwise user needs to login again
		return ttlMin > 0 ? ttlMin * 60 : 10;
	}

	private void checkAndInitStateData(TomcatSession session) {
		logSession(session, "checkAndInitStateData");
		var stateData = session.getStateData();
		if (stateData == null) {
			var clientId = session.getOidcClientId();
			var ttl = getInitialTtlSec();
			stateData = createSessionState(clientId, session.getId(), ttl);
			attachStateData(session, stateData);
			log.debug("Attached initial state for clientId={} sessionIdInDb={} ttl={} stateTtl={}",
					clientId, session.getId(), ttl, stateData.getLifecycle().getTtlSec());
		}
	}

	private TomcatSession attachStateData(TomcatSession session, StateData stateData) {
		logSession(session, "attachStateData");
		// IN_DB or mixed mode, let's check early on expired sessions still in the DB
		var createTime = stateData.getLifecycle().getInitTime();
		var ttl = getCacheTtl(stateData.getLifecycle().getTtlSec());

		// apply persisted session data (in HYBRID mode timing is relevant))
		session.setStateData(stateData);
		session.setCreationTime(createTime.getTime());
		session.setMaxInactiveInterval(getCacheTtl(ttl)); // -1 so we spare us the expire overhead

		// attach conversation to thread (detach along traceId)
		TraceSupport.switchToConversation(stateData.getLastConversationId());

		// result debugging
		var idle = session.getIdleTimeInternal() / 1000L;
		log.debug("Applied timing to sessionId={} with createTime='{}' ttlSec={} idleSec={} attributes={} conversationId={}",
				session.getId(), createTime, ttl, idle, session.getAttributeCount(), stateData.getLastConversationId());
		return session;
	}

	// update SSO back-ref to SSO session if authenticated to see OIDC client on /app/sso
	private void attachSsoSession(TomcatSession session, String clientId, Object context) {
		logSession(session, "attachSsoSession");
		if (context == null || session.getStateData() == null) {
			return;
		}
		var sessionIds = OidcSessionSupport.getSessionIdsFromAuthentication(((SecurityContext) context).getAuthentication());
		if (sessionIds != null && sessionIds.size() == 2) {
			var ssoSessionId = sessionIds.get(0);
			var oidcSessionId = sessionIds.get(1);
			log.debug("Attach sessionId={} for clientId={} oidcSessionId={} to ssoSessionId={}",
					session.getId(), clientId, oidcSessionId, ssoSessionId);
			session.getStateData().setSsoSessionId(ssoSessionId); // so we can track back to our SAML side input state
		}
	}

	private void updateSessionExpirationSettings(TomcatSession session, String clientId) {
		logSession(session, "updateSessionExpirationSettings");
		var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
		if (client.isPresent()) {
			// session state settings
			var ttlSec = getEstablishedTtlSec(client.get());
			var maxTtl = session.getMaxInactiveInterval();
			var lifecycle = session.getStateData().getLifecycle();
			var initInstant = lifecycle.getInitTime().toInstant();
			var expiration = initInstant.plusSeconds(ttlSec);
			lifecycle.setExpirationTime(Timestamp.from(expiration));
			if (log.isDebugEnabled()) {
				log.debug("Updated expiration time of sessionId={} initTime='{}' expirationTime='{}' now='{}'",
						session.getId(), initInstant, expiration, Instant.now());
			}
			// session cache settings
			if (getCacheTtl(ttlSec) != maxTtl) {
				session.setMaxInactiveInterval(ttlSec);
				log.info("Changing expiration setting on clientId={} sessionId={} from maxInactiveInterval={} to oidcTtl={}",
						clientId, session.getId(), session.getMaxInactiveInterval(), ttlSec);
			}
		}
	}

	// we do not need web session backing for /token retrieval
	void validateOidcTokenState(TomcatSession session, Object context) {
		logSession(session, "validateOidcTokenState");
		if (context == null) {
			var request = HttpExchangeSupport.getRunningHttpRequest();
			if (request != null && request.getRequestURI() != null) {
				var isTokenRequest = request.getRequestURI().endsWith(ApiSupport.OIDC_TOKEN);
				if (isTokenRequest) {
					log.info("OIDC /token access not backed by web sessionId={} for clientId={}",
							session.getId(), WebSupport.getClientHint(HttpExchangeSupport.getRunningHttpRequest(),
									trustBrokerProperties.getNetwork()));
				}
			}
		}
	}

	void validateSamlFederationState(TomcatSession session, Object context, String missingAttribute) {
		logSession(session, "validateSamlFederationState");
		if (context == null) {
			var clientId = OidcSessionSupport.getSamlExchangeClientId();
			if (clientId != null) {
				var attrNames = session.getAttributeNamesInternal();
				throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.SERVER_ERROR,
						String.format("SAML AuthnRequest state lost for clientId=%s sessionId=%s missingAttr=%s allAttrs='%s'",
								clientId, session.getId(), missingAttribute, attrNames), "Lost session");
			}
		}
	}

	void setCurrentValuesFromExchange(TomcatSession session) {
		logSession(session, "setCurrentValuesFromExchange");
		var clientId = OidcSessionSupport.getOidcClientId(null, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		OidcSessionSupport.setCurrentValuesFromExchange(session, clientId, null, null,
				relyingPartyDefinitions, trustBrokerProperties);
	}

	void setFinalValuesFromAuthentication(TomcatSession session, Object context) {
		logSession(session, "setFinalValuesFromAuthentication");
		OidcSessionSupport.setFinalValuesFromAuthentication(session, context,
				relyingPartyDefinitions, trustBrokerProperties, stateCacheService, ssoService);
	}

	void clearDerivedValuesFromAuthentication(TomcatSession session, Object context) {
		logSession(session, "clearDerivedValuesFromAuthentication");
		// clear OIDC session tracking cookie, spring-sec saveContext can call this multiple time on may be invalidated session
		if (session != null && session.getOidcClientId() != null) {
			var principalName = session.getPrincipal() != null ? session.getPrincipal().getName() : null;
			OidcSessionSupport.clearDerivedValuesFromAuthentication(session.getOidcClientId(), session.getId(), principalName,
					trustBrokerProperties);
		}
		// fallback to authentication context client_id
		else if (context != null) {
			OidcSessionSupport.clearDerivedValuesFromAuthentication(session, context, trustBrokerProperties);
		}
		// fallback to message
		else {
			var clientId = OidcSessionSupport.getOidcClientId(null, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
			OidcSessionSupport.clearDerivedValuesFromAuthentication(clientId, null, null, trustBrokerProperties);
		}
	}

	// Crosscheck that we do not end up in a loop because of issues in state handling.
	void checkAuthorizationTrigger() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request != null) {
			var triggerUri = request.getRequestURI();
			log.debug("Authentication triggered on requestUri={}", triggerUri);
			if (!ApiSupport.isOidcSessionPath(triggerUri)) {
				// we end up on HRD or IDP again here
				log.error("Authentication triggered again on requestUri={} on return from login", triggerUri);
			}
		}
	}

	private TomcatSession decodeSession(StateData stateData, String sessionId) {
		try {
			var byteInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(stateData.getOidcSessionData()));
			var objectInputStream = new ObjectInputStream(byteInputStream);
			var session = new TomcatSession(this);
			session.readObjectData(objectInputStream);
			log.trace("Decoded sessionId={} attributes={}", sessionId, session.getAttributeCount());
			return session;
		}
		catch (Exception ex) {
			// possible cause: serialization compatibility issues (e.g. serialVersionUID changed, class removed)
			log.error("Failed to decode sessionId={} - invalidating: cause={}", sessionId, ex.getMessage());
			stateCacheService.tryInvalidate(stateData, NAME);
			throw new TechnicalException(String.format("Failed to decode sessionId=%s: %s",
					sessionId, ex.getMessage()), ex);
		}
	}

	private String encodeSession(TomcatSession session) {
		try {
			var byteOutputStream = new ByteArrayOutputStream();
			var objectOutputStream = new ObjectOutputStream(byteOutputStream);
			session.writeObjectData(objectOutputStream);
			var ret = Base64.getEncoder().encodeToString(byteOutputStream.toByteArray());
			log.trace("Encoded sessionId={} size={} attributes={}",
					session.getId(), ret.length(), session.getAttributeCount());
			return ret;
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Failed to encode sessionId=%s: %s",
					session.getId(), ex.getMessage()), ex);
		}
	}

	private void logSession(Session session, String action) {
		if (log.isTraceEnabled() && session instanceof TomcatSession tomcatSession) {
			var httpSessionId = (session.getSession() != null ? session.getSession().getId() : null);
			var httpRequest = HttpExchangeSupport.getRunningHttpRequest();
			var cookies = HttpExchangeSupport.getCookiesAsString(httpRequest);
			var requestUri = httpRequest != null ? httpRequest.getRequestURI() : null;
			log.trace("SESSMGR.{} session={} sessionId={} attributes={} httpSessionId={} cookies='{}' on requestUri={} from {}",
					action, session, session.getId(), tomcatSession.getAttributeCount(),
					httpSessionId, cookies, requestUri,
					WebSupport.getClientHint(httpRequest, trustBrokerProperties.getNetwork()));
		}
	}

}
