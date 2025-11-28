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

import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.session.StandardSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import swiss.trustbroker.sessioncache.dto.StateData;

@Slf4j
@Getter
@Setter
@SuppressWarnings("javaarchitecture:S7027")
public class TomcatSession extends StandardSession implements Serializable {

	// Spring attaches our SAML principal to the HttpSession and SessionRegistry (the correct abstraction) to deal with it
	// is too high up in the software stack, as we also need to replicate HttpSession ro oder service instances/pods.
	private static final String SPRING_SECURITY_CONTEXT = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

	// Spring-sec and spring-auth use a (package) private in HttpSessionRequestCache and WebSessionServerRequestCache.
	// So we cannot make this compile-time save, but it's used for exception improvements only anyway.
	private static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

	// Just for debugging purposes we want to know when spring is processing the SAML response on OIDC side
	private static final String SAML2_AUTHN_REQUEST = "org.springframework.security.saml2.provider.service.web."
			+ "HttpSessionSaml2AuthenticationRequestRepository.SAML2_AUTHN_REQUEST";

	private transient TomcatSessionManager tomcatSessionManager;

	private transient StateData stateData; // not serialized to DB

	public TomcatSession(TomcatSessionManager manager) {
		super(manager);
		this.tomcatSessionManager = manager;
	}

	@Override
	public void setAttribute(String key, Object value) {
		var context = setAttributeInternal(key, value);
		updateSession(context);
	}

	@Override
	public Object getAttribute(String name) {
		return getAttributeInternal(name);
	}

	@Override
	public boolean isValid() {
		var validBefore = isValid;
		var validNow = super.isValid();
		if (validBefore != validNow) {
			// if tomcat changes something in validity checking we might end up here and need to fix the multi session handling
			log.error("Lost session={} during load validBefore={} validNow={} idleTime={} maxInactiveInterval={} expiring={}",
					id, validBefore, validNow, getIdleTimeInternal(), maxInactiveInterval, expiring);
		}
		return validNow;
	}

	public Object getAttributeInternal(String name) {
		var valid = isValid;
		var ret = valid ? super.getAttribute(name) : null;
		if (log.isTraceEnabled()) {
			log.trace("SESS.getAttribute={} on sessionId={} returning ret='{}' of type={} valid={}",
					name, getId(), ret, ret != null ? ret.getClass().getName() : null, valid);
		}
		if (name.equals(SPRING_SECURITY_SAVED_REQUEST)) {
			tomcatSessionManager.validateSamlFederationState(this, ret, name);
		}
		else if (name.equals(SAML2_AUTHN_REQUEST)) {
			log.debug("Check for SAML Response from federation using sessionId={}", getId());
		}
		else if (name.equals(SPRING_SECURITY_CONTEXT)) {
			tomcatSessionManager.validateOidcTokenState(this, ret);
		}
		return ret;
	}

	public Set<String> getAttributeNamesInternal() {
		return attributes != null ? attributes.keySet() : null;
	}

	public int getAttributeCount() {
		return attributes != null ? attributes.size() : -1;
	}

	public int getTokenCount() {
		return stateData != null ?  stateData.getOidcTokenCount() : 0;
	}

	public Object setAttributeInternal(String name, Object value) {
		Object ret = null;
		if (name.equals(SPRING_SECURITY_SAVED_REQUEST)) {
			tomcatSessionManager.checkAuthorizationTrigger();
		}
		else if (name.equals(SAML2_AUTHN_REQUEST)) {
			log.debug("Trigger SAML AuthnRequest starting federation using sessionId={}", getId());
		}
		else if (name.equals(SPRING_SECURITY_CONTEXT)) {
			ret = value;
			tomcatSessionManager.setFinalValuesFromAuthentication(this, value);
		}
		if (log.isTraceEnabled()) {
			log.trace("SESS.setAttribute={} on sessionId={} to value='{}' of type={}",
					name, getId(), value, value != null ? value.getClass().getName() : null);
		}
		super.setAttribute(name, value);
		return ret;
	}

	@Override
	public void removeAttribute(String name) {
		var valid = isValid;
		log.trace("SESS.removeAttribute={} on sessionId={} isValid={}", name, getId(), valid);
		if (HttpExchangeSupport.isRunningUserInfoExchange()) {
			log.debug("Skip discarding SAML principal on OIDC /userinfo (spring bug)");
			return;
		}
		else if (name.equals(SPRING_SECURITY_SAVED_REQUEST)) {
			log.debug("Authentication finished on sessionId={} trigger={}", getId(), name);
		}
		else if (name.equals(SAML2_AUTHN_REQUEST)) {
			log.debug("Federation finished on sessionId={} trigger={}", getId(), name);
		}
		else if (name.equals(SPRING_SECURITY_CONTEXT)) {
			log.debug("Authentication invalidated on sessionId={} trigger={}", getId(), name);
			var value = valid ? super.getAttribute(SPRING_SECURITY_CONTEXT) : null;
			tomcatSessionManager.clearDerivedValuesFromAuthentication(this, value);
		}
		if (valid) {
			super.removeAttribute(name);
			updateSession(null);
		}
	}

	@Override
	public void setPrincipal(Principal principal) {
		if (principal != null) {
			log.debug("SESS.setPrincipal={} on sessionId={}", principal, getId());
		}
		super.setPrincipal(principal);
		// WARN: Do not updateSession here as reading IN_DB states triggers write again
	}

	@Override
	public long getLastAccessedTime() {
		updateSession(null);
		return super.getLastAccessedTime();
	}

	@Override
	public void invalidate() {
		log.debug("SESS.invalidate on sessionId={} clientId={} valid={}", getId(), getOidcClientId(), isValid);
		if (isValid) {
			super.invalidate();
		}
	}

	@Override
	public void recycle() {
		log.debug("SESS.recycle on sessionId={} clientId={} valid={}", getId(), getOidcClientId(), isValid);
		super.recycle();
		this.stateData = null;
	}

	@Override
	public void expire(boolean notify) {
		log.debug("SESS.expire on sessionId={} clientId={} valid={} notify={} maxInactiveInterval={} idleTime={}",
				getId(), getOidcClientId(), isValid, notify, maxInactiveInterval, getIdleTimeInternal());
		super.expire(notify);
	}

	private void updateSession(Object context) {
		((TomcatSessionManager) manager).updateSession(this, context);
	}

	// keep track of client in session (along session.attributes)
	public String getOidcClientId() {
		return stateData != null ? stateData.getOidcClientId() : null;
	}

	public void setOidcClientId(String oidcClientId) {
		log.trace("Setting oidcClientId={} on stateData={}",
				oidcClientId, stateData != null ? stateData.getId() : null);
		if (stateData != null && oidcClientId != null) {
			stateData.setOidcClientId(oidcClientId);
		}
	}

	public SecurityContext getSecurityContext() {
		return (SecurityContext) getAttributeInternal(SPRING_SECURITY_CONTEXT);
	}

}
