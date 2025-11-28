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

import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

/**
 * Pointcut to allow @Traced annotation on services doing client calls to external services the trustbroker depends on.
 * Some funny hacks for the user limit reuse somewhat.
 */
@Component
@Aspect
@Slf4j
public class SpringOpTraceInterceptor {

	private static final OpTraceLogger OP =
			OpTraceLoggerFactory.getLogger(OpTraceConfiguration.getLoggerName() + ".spring");

	private static final RequestContextFactory REQUEST_CONTEXT_FACTORY = OpTraceConfiguration.getRequestContextFactory();

	@Around("@annotation(swiss.trustbroker.common.tracing.Traced) ||"
			+ "@within(swiss.trustbroker.common.tracing.Traced)")
	public Object trace(ProceedingJoinPoint joinPoint) throws Throwable {
		// prevent optracing if @Traced component is accidentally used in the logging statement calling its toString method
		MethodSignature signature = (MethodSignature) joinPoint.getSignature();
		String method = signature.getMethod().getName();
		if (method.equals("toString")) {
			return getClass() + ":" + (String) joinPoint.proceed();
		}

		// if used in batch classes, we do not have a context from the web servlet filter
		Throwable ex = null;
		if (REQUEST_CONTEXT_FACTORY.getRequestContext() == null) {
			createRequestContext(joinPoint);
		}

		try {
			// ====>
			var self = joinPoint.getTarget();
			var object = self.getClass().getSimpleName();
			REQUEST_CONTEXT_FACTORY.extendTransferId(object, method);
			OP.logClientCall(object, method);
			// invoke target
			return joinPoint.proceed();
		}
		catch (Throwable t) {
			ex = t;
			throw t;
		}
		finally {
			OP.logClientReturn(ex);
			REQUEST_CONTEXT_FACTORY.delete();
		}
	}

	// batch client not having an injection point yet
	private void createRequestContext(ProceedingJoinPoint joinPoint) {
		boolean isOpTraceDebugEnabled = OP.isDebugEnabled();
		try {
			final var objName = joinPoint.getTarget().getClass().getSimpleName();
			final var signature = (MethodSignature) joinPoint.getSignature();
			final var method = signature.getMethod().getName();
			final var username = "TechTB"; // statically identify XTB on server side, check config for tech accounts
			final var clientId = genClientId(username);
			if (isOpTraceDebugEnabled) {
				var opTraceParams = getParameters(signature);
				OP.logInitialEnter(null, objName, method, username, opTraceParams, clientId);
			}
			else {
				OP.logInitialEnter(null, objName, method, username, clientId);
			}
		}
		catch (Exception e) {
			if (log.isInfoEnabled()) {
				var traceEx = (log.isDebugEnabled() ? e : null);
				log.info("Exception at business boundary to be handled by caller: {}: {}", e.getClass().getName(),
						e.getMessage(), traceEx);
			}
		}
	}

	private static Object[][] getParameters(MethodSignature signature) {
		var parameters = signature.getParameterNames();
		if (parameters != null) {
			var opTraceParams = new Object[parameters.length][2];
			for (int i = 0; i < parameters.length; i++) {
				opTraceParams[i][0] = "arg" + i;
				opTraceParams[i][1] = parameters[i];
			}
			return opTraceParams;
		}
		return new Object[0][];
	}

	/**
	 * A utility method to generate client ID as a combination of : - current thread id - principal/username - current time - a
	 * random unique identifier
	 */
	private static String genClientId(String username) {
		var clientId = new StringBuilder();
		var threadId = String.valueOf(Thread.currentThread().getId());
		var time = String.valueOf(System.currentTimeMillis());
		var uniqueId = UUID.randomUUID().toString();
		// simulate a clientId
		clientId.append(threadId).append(".");
		clientId.append(username).append(".");
		clientId.append(time).append(".");
		clientId.append(uniqueId);
		return clientId.toString();
	}

}
