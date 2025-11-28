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

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import swiss.trustbroker.common.exception.ErrorCode;
import swiss.trustbroker.common.exception.ErrorMarker;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Spring MVC exception handler towards REST and WEB clients.
 * Exception stacks are not shown, except when DEBUG is enabled. This is needed because most of the exceptions below
 * are either thrown when data from the network is unexpected (in this case we can track back to code without the
 * exception stack, because the error message is speaking enough) or because under load we have threading problems
 * in which case the exception stack is more than needed and if caught and discarded in code within is lost otherwise.
 */
@ControllerAdvice
@Slf4j
@AllArgsConstructor
public class GlobalExceptionHandler {

	private final ApiSupport apiSupport;

	private final TrustBrokerProperties trustBrokerProperties;

	@ExceptionHandler(RequestDeniedException.class)
	public ResponseEntity<String> handleDeniedException(RequestDeniedException ex) {
		var level = ex.getErrorMarker().getLevel();
		logException(ex, ex.getInternalMessage(), log.isDebugEnabled(),  trustBrokerProperties.getNetwork(), level);
		return redirectToErrorPage(ex);
	}

	@ExceptionHandler(TechnicalException.class)
	public ResponseEntity<String> handleTechnicalException(TechnicalException ex) {
		var level = ex.getErrorMarker().getLevel();
		// no stack trace on INFO/WARN level (which are known conditions with a specific marker)
		var withStack = (level == Level.ERROR) && log.isErrorEnabled();
		logException(ex, ex.getInternalMessage(), withStack,  trustBrokerProperties.getNetwork(), level);
		return redirectToErrorPage(ex);
	}

	// We could also check for OIDC specific error handling sending failures to the client here
	public void handleAnyException(Exception ex, HttpServletResponse response) {
		// output stream disrupted, do not log stacks and do not redirect
		if (ExceptionUtil.isClientDisconnected(ex)) {
			var msg2 = TrustBrokerException.getMarkerMessage(ErrorMarker.CLIENT_DISCONNECT, "Client gone");
			logException(ex, msg2, false,  trustBrokerProperties.getNetwork(), Level.WARN);
			return;
		}
		// normal case
		logException(ex);
		redirectToErrorPage(ex, response);
	}

	private void redirectToErrorPage(Exception ex, HttpServletResponse response) {
		try {
			var location = getErrorPageUrl(ex);
			response.sendRedirect(location);
		}
		catch (IOException ioex) {
			log.info("Handling response to client failed", ex);
		}
	}

	private ResponseEntity<String> redirectToErrorPage(TrustBrokerException ex) {
		return ResponseEntity
				.status(HttpStatus.SEE_OTHER)
				.header(HttpHeaders.LOCATION, getErrorPageUrl(ex.getErrorCode()))
				.body("");
	}

	private String getErrorPageUrl(Exception ex) {
		if (ex instanceof TrustBrokerException tex) {
			return getErrorPageUrl(tex.getErrorCode());
		}
		return getErrorPageUrl(StandardErrorCode.REQUEST_REJECTED);
	}

	private String getErrorPageUrl(ErrorCode errorCode) {
		return apiSupport.getErrorPageUrl(errorCode.getLabel(), TraceSupport.getOwnTraceParent());
	}

	// we print the stack only when it's some internal issue, exception triggered by client data are shortened
	private static void logException(Exception ex, String internalMessage, boolean withStack, NetworkConfig networkConfig,
			Level level) {
		var request = WebSupport.getWebRequest();
		var clientHint = WebSupport.getClientHint(request, networkConfig);
		var serviceHint = WebSupport.getServiceContext(request);
		// where it came from
		var causingEx = ExceptionUtil.getRootCause(ex);
		// using toString here instead of getMessage as some exceptions of interest
		// do not have the full information in the message: e.g. SAXParseException (missing line/column), NullPointerException
		var causingMessage = (causingEx != ex) ? causingEx.toString() : null;
		if (withStack) {
			log.atLevel(level).log("{}: {} | {} |"
				+ " Cause: {} | Called on {} | Called by {}",
				ex.getClass().getSimpleName(), ex.getMessage(), internalMessage,
				causingMessage, serviceHint, clientHint, ex);
		}
		else {
			var causing = causingEx.getStackTrace()[0];
			var causingLocation = causing.getFileName() + ":" + causing.getLineNumber();
			var causingMethod = causing.getClassName() + "." + causing.getMethodName();

			// when we handled it towards here (known exception)
			// Note: We could extract from Thread.currentThread().getStackTrace()[1] to show the handler position
			var handler = ex.getStackTrace()[0];
			var handlerLocation = handler.getFileName() + ":" + handler.getLineNumber();
			var handlerMethod = handler.getClassName() + "." + handler.getMethodName();

			// one liner error
			log.atLevel(level).log("{}: {} | {}"
					+ " | Cause: {} | Called on {} | Called by {}"
					+ " | Thrown at causingMethod='{}' causingLocation='{}'"
					+ " | Handled at handlerMethod='{}' handlerLocation='{}'",
					ex.getClass().getSimpleName(), ex.getMessage(), internalMessage,
					causingMessage, serviceHint, clientHint,
					causingMethod, causingLocation,
					handlerMethod, handlerLocation);
		}
	}

	public int logException(Throwable ex) {
		return logException(ex, trustBrokerProperties.getNetwork());
	}

	// for use in static context, networkConfig may be null
	public static int logException(Throwable ex, NetworkConfig networkConfig) {
		if (ex instanceof RequestDeniedException rex) {
			logException(rex, rex.getInternalMessage(), log.isDebugEnabled(), networkConfig, rex.getErrorMarker().getLevel());
			return HttpStatus.FORBIDDEN.value();
		}
		else if (ex instanceof TechnicalException tex) {
			logException(tex, tex.getInternalMessage(), true, networkConfig, tex.getErrorMarker().getLevel());
		}
		else if (ex instanceof BeanCreationException bex && bex.getCause() instanceof TrustBrokerException) {
			logException(bex.getCause(), networkConfig); // handle exceptions in constructors, @PostConstruct etc unwrapped
		}
		else if (ex instanceof Exception eex) {
			// we see 'java.lang.NullPointerException: null' without stack traces but the message is there
			// consider: https://stackoverflow.com/questions/2411487/nullpointerexception-in-java-with-no-stacktrace
			// make sure these cannot be disabled
			logException(eex, "-", true, networkConfig, Level.ERROR);
		}
		else {
			log.error("Throwable caught: {}", ex.getMessage(), ex);
		}
		return HttpStatus.INTERNAL_SERVER_ERROR.value();
	}

	/**
	 * @param ex
	 * @return message of the exception or of the root cause if the exception has a null message
	 */
	public static String getMessageOfExceptionOrCause(Exception ex, boolean useToStringForCause) {
		var causingMessage = ex.getMessage();
		if (causingMessage != null) {
			return causingMessage;
		}
		var causingEx = ExceptionUtil.getRootCause(ex);
		if (useToStringForCause) {
			return causingEx.toString();
		}
		return causingEx.getMessage();
	}

}
