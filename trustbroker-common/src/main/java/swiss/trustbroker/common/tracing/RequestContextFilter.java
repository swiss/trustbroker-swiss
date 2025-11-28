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

package swiss.trustbroker.common.tracing;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.util.WebUtil;

@Slf4j
public class RequestContextFilter implements Filter {

	private static final String TRACE_POINT = RequestContextFilter.class.getSimpleName();

	private static final String CLIENT_ID = System.getProperty(RequestContextFilter.class.getName(), "clientId");

	private static final String USERNAME_FALLBACK_DEFAULT = WebUtil.HTTP_REMOTE_USER;

	private final ThreadLocal<Boolean> isFirstPass = new ThreadLocal<>();

	private OpTraceLogger oplog = null;

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		Object ex = null;
		try {
			logInitialEnter(request, response);
			if (response instanceof HttpServletResponse httpResp) {
				response = new OpTraceResponseWrapper(httpResp);
			}
			chain.doFilter(request, response);
		}
		// store thrown exception for logging purpose
		catch (IOException | ServletException | RuntimeException e) {
			ex = e;
			throw e;
		}
		finally {
			try {
				isFirstPass.remove();
				Object[][] args = null;
				if (response instanceof OpTraceResponseWrapper respWrapper) {
					var httpStatus = respWrapper.getStatus();
					ex = httpStatus >= 400 && httpStatus <= 599 ? "HTTP/" + httpStatus : null;
					args = new Object[][] { { "httpSC", httpStatus } };
				}
				oplog.logInitialReturn(ex, args);
			}
			catch (Exception e) {
				log.error("Error in OpTrace! -> continue with application", e);
			}
		}
	}

	private void logInitialEnter(ServletRequest request, ServletResponse response) {
		try {
			if (isFirstPass.get() == null && request instanceof HttpServletRequest httpRequest) {
				isFirstPass.set(Boolean.TRUE);
				// collect attribute values
				var principal = getUserName(httpRequest);
				var calledMethod = getCalledMethod(httpRequest);
				var clientId = getClientId(httpRequest);
				var traceId = getTraceId(httpRequest);
				oplog.logInitialEnter(traceId, TRACE_POINT, calledMethod, principal, null, clientId,
						request, response);
			}
		}
		catch (Exception e) {
			log.error("Error in OpTrace! -> continue with application", e);
		}
	}


	@Override
	public void init(FilterConfig cfg) throws ServletException {
		oplog = OpTraceLoggerFactory.getLogger();
	}

	protected String getUserName(HttpServletRequest req) {
		String userName = null;
		var principal = req.getUserPrincipal();
		if (principal != null) {
			userName = principal.getName();
			if (log.isDebugEnabled()) {
				log.debug("Principal-Name='{}'; as string='{}'", userName, principal);
			}
		}
		else if (log.isTraceEnabled()) {
			log.trace("request.getUserPrincipal is null !");
		}
		if (userName == null) {
			userName = req.getHeader(USERNAME_FALLBACK_DEFAULT);
		}
		return userName;
	}

	@SuppressWarnings("java:S1172")
	protected String getTraceId(HttpServletRequest req) {
		return TraceSupport.getOwnTraceParent();
	}

	protected String getClientId(HttpServletRequest req) {
		var clientId = req.getHeader(CLIENT_ID); // perimeter injected client ID
		if (clientId == null) {
			var session = req.getSession(false);
			clientId = (session == null) ? null : session.getId(); // session tracking via cookies
		}
		if (clientId == null || clientId.trim().isEmpty()) {
			log.debug("no clientId found in header and no sessionId");
			clientId = null;
		}
		return clientId;
	}

	protected String getCalledMethod(HttpServletRequest req) {
		String calledMethod = req.getMethod() + " " + req.getRequestURI();
		String query = req.getQueryString();
		if ((query != null) && (!query.trim().isEmpty())) {
			calledMethod += "?" + query;
		}
		return calledMethod;
	}

}
