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

package swiss.trustbroker.oidcmock;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import swiss.trustbroker.common.util.WebUtil;

@Slf4j
public class CustomAuthorizationFailureHandler implements AuthenticationFailureHandler {

	private final String type;

	private final HttpMessageConverter<OAuth2Error> errorResponseConverter;

	public CustomAuthorizationFailureHandler(String authorize) {
		this.type = authorize;
		this.errorResponseConverter = new OAuth2ErrorHttpMessageConverter();
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		var clientId = request.getParameter("client_id");
		var referrer = WebUtil.getReferer(request);

		String errMsg;
		if (exception instanceof OAuth2AuthenticationException authException) {
			var error = authException.getError();
			errMsg = String.format("Failed OIDC %s for oidcClient=%s and httpReferer=%s with errorCode=%s " +
							"exceptionMessage='%s' exceptionClass=%s description='%s' ", type, clientId, referrer,
					error.getErrorCode(), exception.getMessage(), exception.getClass().getSimpleName(),
					getDescription(exception, error.getDescription()));
		}
		else {
			errMsg = String.format("Failed %s for oidcClient=%s of httpReferer=%s with exceptionMessage='%s' exceptionClass=%s",
					type, clientId, referrer, exception.getMessage(), exception.getClass().getName());
		}

		log.error("OIDC client failure caused by: {}", errMsg);
		try (var httpResponse = new ServletServerHttpResponse(response)) {
			httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
			if (exception instanceof OAuth2AuthenticationException ex) {
				errorResponseConverter.write(ex.getError(), null, httpResponse);
			}
		}
	}

	private static String getDescription(AuthenticationException exception, String errorDescription) {
		return errorDescription != null && !errorDescription.equals(exception.getMessage()) ? errorDescription :
				"https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	}
}
