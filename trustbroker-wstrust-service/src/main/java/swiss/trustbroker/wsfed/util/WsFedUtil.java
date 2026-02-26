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

package swiss.trustbroker.wsfed.util;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpMethod;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.wsfed.dto.WsFedAction;
import swiss.trustbroker.wsfed.dto.WsFedRequestData;

/**
 * WS-FED constants and utilities
 *
 * @see <a href="https://specs.xmlsoap.org/ws/2006/12/federation/ws-federation.pdf">WS-Federation</a>
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class WsFedUtil {

	public static final String ACTION = "wa";

	public static final String REPLY = "wreply";

	public static final String CONTEXT = "wctx";

	public static final String ATTRIBUTE = "wattr";

	public static final String ATTRIBUTE_PARAMETER = "wattrptr";

	public static final String RESULT = "wresult";

	public static final String RESULT_PARAMETER = "wresultptr";

	public static final String REFRESH = "wfresh";

	public static final String AUTH_LEVEL = "wauth";

	public static final String FORCE_AUTHN = "0";

	public static final String REALM = "wtrealm";

	public static final String RESOURCE = "wtres";

	public static final String FEDERATION = "wfed";

	public static final String HOME_REALM = "whr";

	public static final String CURRENT_TIME = "wct";

	public static final Set<String> ALLOWED_METHODS = Set.of(HttpMethod.GET.name(), HttpMethod.POST.name());

	public static Optional<WsFedAction> getAction(HttpServletRequest request) {
		var action = request.getParameter(ACTION);
		return WsFedAction.of(action);
	}

	public static WsFedAction getRequiredAction(HttpServletRequest request) {
		var action = getAction(request);
		if (!action.isPresent()) {
			throw new RequestDeniedException(String.format("Missing or invalid WS-Fed action=%s", request.getParameter(ACTION)));
		}
		return action.get();
	}

	// optional
	public static String getReplyUrl(HttpServletRequest request) {
		return request.getParameter(REPLY);
	}

	// optional
	public static String getRealm(HttpServletRequest request) {
		var realm = request.getParameter(REALM);
		if (realm == null) {
			// legacy
			realm = request.getParameter(RESOURCE);
		}
		return realm;
	}

	// optional
	public static final String getFederation(HttpServletRequest request) {
		return request.getParameter(FEDERATION);
	}

	// optional
	public static String getAuthLevel(HttpServletRequest request) {
		return request.getParameter(AUTH_LEVEL);
	}

	// optional
	public static Optional<Boolean> isForceAuthn(HttpServletRequest request) {
		var refresh = request.getParameter(REFRESH);
		if (refresh == null) {
			return Optional.empty();
		}
		return Optional.of(refresh.equals(FORCE_AUTHN));
	}

	// optional
	public static String getContext(HttpServletRequest request) {
		return request.getParameter(CONTEXT);
	}

	// optional
	public static Instant getCurrentTime(HttpServletRequest request) {
		var currentTime = request.getParameter(CURRENT_TIME);
		if (currentTime == null) {
			return null;
		}
		try {
			return Instant.parse(currentTime);
		}
		catch (DateTimeParseException ex) {
			throw new RequestDeniedException(String.format("Not in ISO date time format: %s='%s'", CURRENT_TIME, currentTime));
		}
	}

	public static WsFedRequestData createWsFedRequestData(HttpServletRequest request) {
		var replyUrl = getReplyUrl(request);
		var action = getRequiredAction(request);
		var context = getContext(request);  // optional
		var realm = getRealm(request);  // optional
		var forceAuthn = isForceAuthn(request); // optional
		var currentTime = getCurrentTime(request); // optional
		var authLevel = getAuthLevel(request); // optional
		return WsFedRequestData.builder()
							   .action(action)
							   .replyUrl(replyUrl)
							   .authLevel(authLevel)
							   .context(context)
							   .realm(realm)
							   .forceAuth(forceAuthn.orElse(null))
							   .timestamp(currentTime)
							   .build();
	}
}
