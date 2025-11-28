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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.ErrorMarker;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest
@ContextConfiguration(classes = GlobalExceptionHandler.class)
class GlobalExceptionHandlerTest {

	private static final String REDIRECT_URL = "https://localhost";

	@MockitoBean
	private ApiSupport apiSupport;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private GlobalExceptionHandler globalExceptionHandler;

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getRootCause(int levels) {
		var ex = buildExceptionChain(levels, true);
		var result = ExceptionUtil.getRootCause(ex);
		assertThat(result, is(not(nullValue())));
		assertThat(result.getMessage(), is("Level 1"));
	}

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getMessageOfExceptionOrCause(int levels) {
		var ex = buildExceptionChain(levels, false);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, false);
		assertThat(result, is("Level 1"));
	}

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getMessageOfExceptionOrCauseWithToString(int levels) {
		var ex = buildExceptionChain(levels, false);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, true);
		if (levels == 1) {
			assertThat(result, is(ex.getMessage()));
		}
		else {
			assertThat(result, is("java.lang.Exception: Level 1"));
		}
	}

	@Test
	void getMessageOfExceptionOrCauseWithMessage() {
		var ex = buildExceptionChain(2, true);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, false);
		assertThat(result, is(ex.getMessage()));
	}

	@Test
	void handleDeniedException() {
		var ex = givenRequestDeniedException();
		doReturn(REDIRECT_URL).when(apiSupport).getErrorPageUrl(eq(StandardErrorCode.REQUEST_DENIED.getLabel()), any());
		var result = globalExceptionHandler.handleDeniedException(ex);
		assertThat(result.getStatusCode(), is(HttpStatus.SEE_OTHER));
		assertThat(result.getBody(), is(""));
		assertThat(result.getHeaders().get(HttpHeaders.LOCATION), is(List.of(REDIRECT_URL)));
	}

	@Test
	void handleTechnicalException() {
		var ex = givenTechnicalException();
		doReturn(REDIRECT_URL).when(apiSupport).getErrorPageUrl(eq(StandardErrorCode.REQUEST_REJECTED.getLabel()), any());
		var result = globalExceptionHandler.handleTechnicalException(ex);
		assertThat(result.getStatusCode(), is(HttpStatus.SEE_OTHER));
		assertThat(result.getBody(), is(""));
		assertThat(result.getHeaders().get(HttpHeaders.LOCATION), is(List.of(REDIRECT_URL)));
	}

	@Test
	void handleAnyException() {
		var ex = new RuntimeException();
		doReturn(REDIRECT_URL).when(apiSupport).getErrorPageUrl(eq(StandardErrorCode.REQUEST_REJECTED.getLabel()), any());
		var response = new MockHttpServletResponse();
		globalExceptionHandler.handleAnyException(ex, response);
		assertThat(response.getStatus(), is(HttpStatus.FOUND.value()));
		assertThat(response.getHeader(HttpHeaders.LOCATION), is(REDIRECT_URL));
	}

	@Test
	void handleAnyExceptionClientGone() {
		var cause = new IOException("Broken pipe");
		var ex = new RuntimeException(cause);
		var response = new MockHttpServletResponse();
		globalExceptionHandler.handleAnyException(ex, response);
		assertThat(response.getStatus(), is(HttpStatus.OK.value()));
	}

	private static TechnicalException givenTechnicalException() {
		var cause = new IOException();
		var ex = new TechnicalException(ErrorMarker.CLIENT_DISCONNECT, "message2", cause);
		assertThat(ex.getErrorCode(), is(StandardErrorCode.REQUEST_REJECTED));
		assertThat(ex.getErrorMarker(), is(ErrorMarker.CLIENT_DISCONNECT));
		assertThat(ex.getCause(), is(cause));
		assertThat(ex.getMessage(), is("Service rejected"));
		assertThat(ex.getInternalMessage(), is("xtbCode=CLIENT_DISCONNECT message2"));
		return ex;
	}

	private static RequestDeniedException givenRequestDeniedException() {
		var ex = new RequestDeniedException("message1");
		assertThat(ex.getErrorCode(), is(StandardErrorCode.REQUEST_DENIED));
		assertThat(ex.getErrorMarker(), is(ErrorMarker.DEFAULT));
		assertThat(ex.getMessage(), is("Access denied"));
		assertThat(ex.getInternalMessage(), is("message1"));
		return ex;
	}

	private Exception buildExceptionChain(int levels, boolean messageForAll) {
		// root cause is always level 1
		Exception cause = null;
		for (int ii = 1; ii <= levels; ++ii) {
			String message = null;
			if (messageForAll || ii == 1) {
				message = "Level " + ii;
			}
			cause = new Exception(message, cause);
		}
		return cause;
	}

}
