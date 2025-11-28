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

package swiss.trustbroker.oidc.tx;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.util.ApiSupport;

// spring-security does not handle fragment mode properly, so we patch it outside until that's fixed
// we need to remember the fact across a fill federation execution from /authorize to the application code redirect.
@Slf4j
public class FragmentUtil {

	public static final String OIDC_RESPONSE_MODE = "response_mode";

	public static final String OIDC_RESPONSE_FRAGMENT = "fragment";

	private static final String CODE_TAG = OidcUtil.OIDC_CODE + "=";

	private static final String ERROR_TAG = OidcUtil.OIDC_ERROR + "=";

	private static final String ERROR_URI_TAG = OidcExceptionHelper.ERROR_URI_PARAM + "=";

	private static final String ERROR_DESC_TAG = OidcExceptionHelper.ERROR_DESCRIPTION_PARAM + "=";

	private static final List<String> ERROR_TAGS = List.of(ERROR_TAG, ERROR_URI_TAG, ERROR_DESC_TAG);

	private FragmentUtil() {
	}

	public static boolean isFragmentResponseMode(String responseType) {
		return OIDC_RESPONSE_FRAGMENT.equals(responseType);
	}

	static void checkAndRememberFragmentMode(HttpServletRequest request) {
		var session = request.getSession(false);
		if (session == null) {
			return;
		}
		if (isFragmentResponseMode(request.getParameter(OIDC_RESPONSE_MODE))) {
			log.debug("Handling fragment response_type on session={}", session);
			session.setAttribute(OIDC_RESPONSE_MODE, OIDC_RESPONSE_FRAGMENT);
		}
		// make sure we keep the fragment mode across the federated login
		else if (ApiSupport.isOidcAuthPath(request.getPathInfo())) {
			removeFragmentModeFlag(session);
		}
	}

	static String checkAndFixRedirectUri(String redirect, HttpSession session, String responseMode) {
		var ret = redirect;
		if (redirect == null) {
			return null;
		}
		// code redirect
		var codeIdx = ownParametersPosition(ret, CODE_TAG);
		if (codeIdx >= 0 && session != null && OIDC_RESPONSE_FRAGMENT.equals(session.getAttribute(OIDC_RESPONSE_MODE))) {
			removeFragmentModeFlag(session);
			ret = reorganizeRedirectUri(redirect, codeIdx);
		}
		// error redirect
		var errorIdx = ownParametersPosition(ret, ERROR_TAG);
		if (errorIdx >= 0 && codeIdx < 0 && OIDC_RESPONSE_FRAGMENT.equals(responseMode)) {
			ret = reorganizeRedirectUri(redirect, errorIdx);
		}
		// code redirect with error we received back from previous trials
		if (errorIdx >= 0) {
			ret = discardAmbiguousErrorsInRedirect(ret, errorIdx, codeIdx >= 0);
		}
		return ret;
	}

	static String reorganizeRedirectUri(String location, int patchIndex) {
		var ret = location;
		// spring-sec attaches the ?code=x&state=y between query and fragment using UriComponentsBuilder so for applications
		// sending query and/or fragments we need to re-order the parts to honor RFC3986.
		if (patchIndex >= 0 && location != null) {
			var endIdx = location.indexOf("#");
			var separator = endIdx >= 0 ? "&" : "#"; // fragment already ?
			var endIdx2 = location.indexOf("?", patchIndex + 1); // invalid additional query?
			endIdx = endIdx < 0 ? endIdx2 : endIdx; // switch to invalid query
			endIdx = endIdx > endIdx2 && endIdx2 >= 0 ? endIdx2 : endIdx; // switch to app fragment or query
			var ownParams = location.substring(patchIndex, endIdx > patchIndex ? endIdx : location.length());
			// swap to end, app fragment or query preserved
			ret = location.replace(ownParams, "") + separator + ownParams.substring(1);
		}
		log.debug("Handled code redirect switch to fragment on location='{}' result='{}'", location, ret);
		return ret;
	}

	public static String discardAllErrorsInRedirect(String location) {
		var errIdx = ownParametersPosition(location, ERROR_TAG);
		if (errIdx >= 0) {
			return discardAmbiguousErrorsInRedirect(location, errIdx, true);
		}
		return location;
	}

	// workaround to handle OIDC applications echoing our own error redirects back to us (usually some faulty javascript adapter)
	static String discardAmbiguousErrorsInRedirect(String location, int patchIndex, boolean dropAllErrors) {
		// make sure it's our own error
		var errorUriIdx = StringUtils.indexOfIgnoreCase(location, ERROR_URI_TAG, patchIndex);
		if (errorUriIdx < 0) {
			return location;
		}
		var parts = location.split("[?#&]");
		var ret = new StringBuilder();
		var sep = "";
		Map<String, Integer> errorCounts = new HashMap<>();
		for (var part : parts) {
			if (!ret.isEmpty()) {
				var tokPos = StringUtils.indexOfIgnoreCase(location, part);
				var nextSep = location.substring(tokPos - 1, tokPos);
				sep = !nextSep.equals("&") ? nextSep : sep;
			}
			if (keepParameter(dropAllErrors, part, errorCounts)) {
				ret.append(sep).append(part);
				if (!sep.equals("&")) {
					sep = "&";
				}
			}
		}
		var redirect = ret.toString();
		log.debug("Handled error redirect problems on location='{}' result='{}'", location, redirect);
		return redirect;
	}

	private static boolean keepParameter(boolean dropAllErrors, String part, Map<String, Integer> errorCounts) {
		for (var errorTag : ERROR_TAGS) {
			if (StringUtils.startsWithIgnoreCase(part, errorTag)) {
				int errorCount = errorCounts.getOrDefault(errorTag, 0) + 1;
				errorCounts.put(errorTag, errorCount);
				if (dropAllErrors || errorCount > 1) {
					return false;
				}
			}
		}
		return true;
	}

	// prevent storing session by checking on attribute existence
	private static void removeFragmentModeFlag(HttpSession session) {
		if (session.getAttribute(OIDC_RESPONSE_MODE) != null) {
			session.removeAttribute(OIDC_RESPONSE_MODE);
		}
	}

	static int ownParametersPosition(String redirect, String startParameter) {
		for (var sep : List.of("?", "&", "#")) {
			var ret = StringUtils.indexOfIgnoreCase(redirect, sep + startParameter);
			if (ret >= 0) {
				return ret;
			}
		}
		return -1;
	}

	static int ownParametersPosition(String redirect) {
		for (var check : List.of(CODE_TAG, ERROR_TAG)) {
			var ret = ownParametersPosition(redirect, check);
			if (ret >= 0) {
				return ret;
			}
		}
		return -1;
	}

}
