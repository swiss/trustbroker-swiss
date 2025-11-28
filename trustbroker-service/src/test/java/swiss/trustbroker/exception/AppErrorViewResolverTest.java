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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.doReturn;

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.ErrorCode;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@SpringBootTest(classes = AppErrorViewResolver.class)
class AppErrorViewResolverTest {

	private static final String ISSUER = "https://localhost:4200";

	private static final String REDIRECT_URI = ISSUER + "/client";

	private static final String FAILURE_PATH = "/failure/url";

	@MockitoBean
	private ApiSupport apiSupport;

	@MockitoBean
	private TrustBrokerProperties properties;

	@Autowired
	private AppErrorViewResolver appErrorViewResolver;

	@ParameterizedTest
	@MethodSource
	void resolveErrorView(HttpStatus status, ErrorCode errorCode, AuthenticationException ex,
			String issuer, String url, String expected) {
		var traceIdOnTheWire = "00-000102030405060708090a0b0c0d0e0f-0102030405060708-00";
		var request = new MockHttpServletRequest();
		request.addHeader(TraceSupport.W3C_TRACEPARENT, traceIdOnTheWire);
		request.setParameter(OidcUtil.REDIRECT_URI, REDIRECT_URI);
		TraceSupport.setMdcTraceContext(request);
		OidcExceptionHelper.saveAuthenticationException(request, ex);
		var oidcProperties = new OidcProperties();
		oidcProperties.setIssuer(issuer);
		doReturn(oidcProperties).when(properties).getOidc();
		doReturn(true).when(apiSupport).isInternalUrl(REDIRECT_URI);
		doReturn(url).when(apiSupport).getErrorPageUrl(errorCode.getLabel(), TraceSupport.getOwnTraceParent());
		Map<String, Object> model = Map.of("test", "value");
		var result = appErrorViewResolver.resolveErrorView(request, status, model);
		assertThat(result.getViewName(), is(WebSupport.getViewRedirectResponse(expected)));
		assertThat(result.getModel(), is(Collections.emptyMap()));
		TraceSupport.clearMdcTraceContext();
	}

	static Object[][] resolveErrorView() {
		var ex = new OAuth2AuthenticationException("test");
		var exceptionResult = REDIRECT_URI + "?error=test&error_uri=" + WebUtil.urlEncodeValue(ISSUER + FAILURE_PATH);
		return new Object[][] {
				{ HttpStatus.NOT_FOUND, StandardErrorCode.REQUEST_REJECTED, null, ISSUER, FAILURE_PATH, FAILURE_PATH },
				{ HttpStatus.FORBIDDEN, StandardErrorCode.REQUEST_DENIED, ex, ISSUER, FAILURE_PATH, exceptionResult
				},
				{ HttpStatus.FORBIDDEN, StandardErrorCode.REQUEST_DENIED, ex, "urn:issuer", ISSUER + FAILURE_PATH, exceptionResult }
		};
	}

}
