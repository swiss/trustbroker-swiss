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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.HttpHeaders;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.util.ApiSupport;

@Slf4j
public class OidcTxRequestWrapper extends HttpServletRequestWrapper {

	private static final List<Pair<String, String>> SUFFIX_LIST = List.of(
			Pair.of("/auth", "/oauth2/authorize"),
			Pair.of("/certs", "/oauth2/jwks"),
			Pair.of("/token", "/oauth2/token"),
			Pair.of("/token/introspect", "/oauth2/introspect"),
			Pair.of(ApiSupport.OIDC_USERINFO, ApiSupport.OIDC_USERINFO),
			Pair.of(ApiSupport.OIDC_LOGOUT, ApiSupport.OIDC_LOGOUT),
			Pair.of(ApiSupport.OIDC_REVOKE, "/oauth2/revoke"),
			Pair.of(ApiSupport.PUBLIC_OIDC_CONFIG_PATH, ApiSupport.PUBLIC_OIDC_CONFIG_PATH),
			Pair.of(ApiSupport.XTB_OIDC_CONFIG_PATH, ApiSupport.PUBLIC_OIDC_CONFIG_PATH),
			Pair.of("/3p-cookies/step1.html", "/3p-cookies/step1"),
			Pair.of("/3p-cookies/step2.html", "/3p-cookies/step2"),
			Pair.of("/login-status-iframe.html", "/login-status-iframe"),
			Pair.of("/login-status-iframe.html/init", "/login-status-iframe-init")
	);

	private HttpSession oidcSubSession; // per request cache for OIDC session

	private boolean oidcSubSessionTried = false;

	public OidcTxRequestWrapper(HttpServletRequest originRequest) {
		super(originRequest);
	}

	// Fake the realms concept of Keycloak internally redirecting to /realms/xy-realm/protocol/openid-connect/endpoint
	private static String rewriteKeycloakToSpringAuthServerPath(String webPath) {
		var securePath = StringUtil.clean(webPath);
		if (ApiSupport.isOidcConfigPath(securePath)) {
			log.trace("OIDC config path={}", securePath);
			return ApiSupport.PUBLIC_OIDC_CONFIG_PATH;
		}
		// Keycloak namespace validation
		if (ApiSupport.isKeyloakRealmsPath(securePath)) {
			for (var suffix : SUFFIX_LIST) {
				if (securePath.endsWith(suffix.getKey())) {
					log.trace("Apply mapping {} for path={}", suffix, securePath);
					return suffix.getValue();
				}
			}
			throw new TechnicalException(String.format("Invalid access to Keycloak path=%s use one of %s",
					securePath, SUFFIX_LIST));
		}
		// spring-authorization-server namespace validation
		if (ApiSupport.isOidcSubSystemPath(securePath)) {
			for (var suffix : SUFFIX_LIST) {
				if (securePath.equals(suffix.getValue())) {
					log.trace("Accept mapping {} for path={}", suffix, securePath);
					return securePath;
				}
			}
			throw new TechnicalException(String.format("Invalid access to spring-security path=%s use one of %s",
					securePath, SUFFIX_LIST));
		}
		return securePath;
	}

	private static String discardNullAuthorizationValue(String value) {
		return value != null && value.equalsIgnoreCase(OidcUtil.OIDC_BEARER_NULL) ? null : value;
	}

	private static String discardUnwantedAuthorizationHeader(String path, String name, String value) {
		if (name.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)) {
			// Ignore Authorization: Bearer null
			value = discardNullAuthorizationValue(value);
			// Ignore Authorization: Bearer any non /userinfo accidentally sent by some adapters.
			if (value != null && value.startsWith(OidcUtil.OIDC_BEARER) && !ApiSupport.isUserInfoRequest(path)) {
				// Valid tokens would actually work but expired ones are blocking the flow.
				log.debug("Discard unnecessary Bearer token on public endpoint={} token={}", path, value);
				return null;
			}
		}
		return value;
	}

	public boolean isOidcSessionPath() {
		return ApiSupport.isOidcSessionPath(super.getRequestURI());
	}

	@Override
	public String getRequestURI() {
		return rewriteKeycloakToSpringAuthServerPath(super.getRequestURI());
	}

	@Override
	@SuppressWarnings("java:S1149") // StringBuffer is given by the interface
	public StringBuffer getRequestURL() {
		var url = super.getRequestURL();
		return url == null || url.isEmpty() ? url :
				new StringBuffer(rewriteKeycloakToSpringAuthServerPath(url.toString()));
	}

	@Override
	public String getPathInfo() {
		return rewriteKeycloakToSpringAuthServerPath(super.getPathInfo());
	}

	@Override
	public String getPathTranslated() {
		return rewriteKeycloakToSpringAuthServerPath(super.getPathTranslated());
	}

	@Override
	public String getServletPath() {
		return rewriteKeycloakToSpringAuthServerPath(super.getServletPath());
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return OidcRequestUtil.cleanScopeParamSpaces(super.getParameterMap());
	}

	@Override
	public String[] getParameterValues(String name) {
		return OidcRequestUtil.cleanScopeParamSpaces(super.getParameterValues(name), name);
	}

	@Override
	public String getHeader(String name) {
		return discardUnwantedAuthorizationHeader(super.getRequestURI(), name, super.getHeader(name));
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		var values = super.getHeaders(name);
		var path = super.getRequestURI();
		if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name) && values != null
				&& values.hasMoreElements() && discardUnwantedAuthorizationHeader(path, name, values.nextElement()) == null) {
			return null;
		}
		return values;
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		var names = super.getHeaderNames();
		if (super.getHeader(HttpHeaders.AUTHORIZATION) == null // no Authorization
				|| this.getHeader(HttpHeaders.AUTHORIZATION) != null) { // no null Authorization
			return names;
		}
		// case insensitive removal, might be a lambda for that somewhere => enum is old
		var ret = new ArrayList<String>();
		while (names.hasMoreElements()) {
			var name = names.nextElement();
			if (!HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
				ret.add(name);
			}
		}
		return Collections.enumeration(ret);
	}

	@Override
	public HttpSession getSession() {
		return getSession(true);
	}

	@Override
	public HttpSession getSession(boolean create) {
		if (oidcSubSession != null) {
			return oidcSubSession; // cache hit when TomcatSessionManager.load kicked in
		}
		else if (oidcSubSessionTried && !create) {
			return null; // tried but none found IN_MEMORY/IN_DB initially
		}
		oidcSubSession = super.getSession(create); // find initially or create triggered by spring-sec
		if (oidcSubSession == null) {
			log.debug("No session on initial check on path={} requireSession={}",
					this.getRequestURI(), ApiSupport.isOidcSessionPath(this.getRequestURI()));
			oidcSubSessionTried = true; // first try missed, remember that until create=true
		}
		return oidcSubSession;
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return oidcSubSession != null;
	}

	public void setSubSession(HttpSession oidcSubSession) {
		this.oidcSubSession = oidcSubSession;
	}

}
