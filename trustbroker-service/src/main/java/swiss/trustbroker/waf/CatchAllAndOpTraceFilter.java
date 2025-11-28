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

package swiss.trustbroker.waf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.tracing.OpTraceLoggerFactory;
import swiss.trustbroker.common.tracing.RequestContextFilter;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.exception.GlobalExceptionHandler;

/**
 * Springify OpTrace filter and add a UUID and client IP in a thread-local so:
 * - GlobalException catcher can send UUID to the user to find the logs
 * - Logback via the logging.pattern.console: ... [%X{clientIp:-}] [%X{traceId:-}] ... can annotate all log lines.
 * Note that not annotating the fields with clientIp=x and traceId=y is to save some bytes we log.
 * UUID and IP address searches work quite well this way.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
@AllArgsConstructor
@Slf4j
public class CatchAllAndOpTraceFilter extends RequestContextFilter {

	private GlobalExceptionHandler globalExceptionHandler;

	private TrustBrokerProperties trustBrokerProperties;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		try {
			var httpRequest = (HttpServletRequest) request;
			TraceSupport.setMdcTraceContext((HttpServletRequest) request);

			var oplog = OpTraceLoggerFactory.getLogger();
			if (SilenceRules.isSilenced(httpRequest, oplog.isInfoEnabled(), oplog.isDebugEnabled(),
					trustBrokerProperties.getNetwork())) {
				log.debug("Silenced path={} encountered", httpRequest.getRequestURI());
				chain.doFilter(request, response);
				return;
			}

			super.doFilter(request, response, chain);
		}
		catch (Exception ex) {
			// we do not behave like ADFS (HTTP/404) here but differentiate between:
			// - Blocked by security checks (HTTP/403)
			// - Implementation and backend issues (HTTP/500)
			globalExceptionHandler.handleAnyException(ex, (HttpServletResponse) response);
		}
		finally {
			TraceSupport.clearMdcTraceContext();
		}
	}

}
