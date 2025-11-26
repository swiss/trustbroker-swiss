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

package swiss.trustbroker.oidc;

import java.util.Collections;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

/**
 * No-op SessionRegistry - sessions are handled in the DB.
 * The default implementation leads to leaks if the <code>SessionDestroyedEvent</code> is not received
 * (e.g. multi-pod setup).
 */
@Slf4j
public class CustomSessionRegistry implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	@Override
	public List<Object> getAllPrincipals() {
		log.debug("SessionRegistry: get all principals - no effect");
		return Collections.emptyList();
	}

	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		log.debug("SessionRegistry: refresh last request on principal={} includeExpiredSessions={} - no effect",
				principal, includeExpiredSessions);
		return Collections.emptyList();
	}

	@Override
	public SessionInformation getSessionInformation(String sessionId) {
		log.debug("SessionRegistry: get session information for sessionId={} - no effect", sessionId);
		return null;
	}

	@Override
	public void refreshLastRequest(String sessionId) {
		log.debug("SessionRegistry: refresh last request on sessionId={} - no effect", sessionId);
	}

	@Override
	public void registerNewSession(String sessionId, Object principal) {
		log.debug("SessionRegistry: register sessionId={} for principal={} - no effect", sessionId, principal);
	}

	@Override
	public void removeSessionInformation(String sessionId) {
		log.debug("SessionRegistry: remove sessionId={} - no effect", sessionId);
	}

	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		log.debug("SessionRegistry: session event event={} - no effect", event != null ? event.getClass().getSimpleName() : null);
	}
}
