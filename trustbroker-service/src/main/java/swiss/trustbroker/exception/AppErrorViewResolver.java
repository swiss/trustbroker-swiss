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

package swiss.trustbroker.exception;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@Component
@AllArgsConstructor
@Slf4j
public class AppErrorViewResolver implements ErrorViewResolver {

	private final ApiSupport apiSupport;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public ModelAndView resolveErrorView(HttpServletRequest request, HttpStatus status, Map<String, Object> model) {
		var traceId = TraceSupport.getOwnTraceParent();
		var errorPage = resolveErrorPage(status, traceId);
		if (OidcExceptionHelper.hasAuthenticationException(request)) {
			var location = OidcExceptionHelper.buildLocationForAuthenticationException(request, errorPage,
					trustBrokerProperties.getOidc().getIssuer(), "spring-mvc", apiSupport::isInternalUrl);
			if (location != null) {
				log.debug("Authentication exception resulted in location={}", location);
				errorPage = location;
			}
		}
		log.debug("sprint-mvc path={} query=\"{}\" called for statusCode={} and model=\"{}\" redirecting to {} traceId={}",
				request.getRequestURI(), request.getQueryString(), status.value(), model, errorPage, traceId);
		// the model parameters are appended to the URL, don't expose them to the client
		return new ModelAndView(WebSupport.getViewRedirectResponse(errorPage), Collections.emptyMap());
	}

	private String resolveErrorPage(HttpStatus status, String traceId) {
		return switch (status) {
			case FORBIDDEN -> apiSupport.getErrorPageUrl(StandardErrorCode.REQUEST_DENIED.getLabel(), traceId);
			default -> apiSupport.getErrorPageUrl(StandardErrorCode.REQUEST_REJECTED.getLabel(), traceId);
		};
	}

}
