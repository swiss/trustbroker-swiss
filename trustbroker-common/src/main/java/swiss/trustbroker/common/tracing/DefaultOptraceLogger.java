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

import java.util.concurrent.atomic.AtomicLong;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;

@Slf4j
public class DefaultOptraceLogger implements OpTraceLogger {

	private static final RequestContextFactory REQUEST_CONTEXT_FACTORY = OpTraceConfiguration.getRequestContextFactory();

	private static final String OPTRACE_SERVER_REQUEST = ">>>>>";

	private static final String OPTRACE_SERVER_RESPONSE = "<<<<<";

	private static final String OPTRACE_CLIENT_REQUEST = "====>";

	private static final String OPTRACE_CLIENT_RESPONSE = "<====";

	private static final String OPTRACE_THREADCTX_ERROR = "RequestContext missing in current thread";

	private static final String OPTRACE_PROCESSING_ERROR = "Skip OpTrace caused by exception";

	private static final Runtime RUNTIME = Runtime.getRuntime();

	private static final AtomicLong pendingRequests = new AtomicLong();

	private static final AtomicLong concurrentRequests = new AtomicLong();

	@SuppressWarnings("java:S1312")
	private final Logger oplog;

	public DefaultOptraceLogger(Logger logger) {
		oplog = logger;
	}

	@Override
	public RequestContext getRequestContext() {
		return REQUEST_CONTEXT_FACTORY.getRequestContext();
	}

	@Override
	public void logInitialEnter(String traceId, String object, String method, String principal, String clientId) {
		logInitialEnter(traceId, object, method, principal, null, clientId, null, null);
	}

	@Override
	public void logInitialEnter(
			String traceId, String object, String method, String principal, Object[][] optional, String clientId
	) {
		logInitialEnter(traceId, object, method, principal, optional, clientId, null, null);
	}

	@Override
	public void logInitialEnter(
			String traceId, String object, String method, String principal, Object[][] optional, String clientId,
			Object fullRequestContext, Object fullResponseContext
	) {
		try {
			var numberRequests = concurrentRequests.incrementAndGet();
			var rc = REQUEST_CONTEXT_FACTORY.create(object, method, traceId, principal, clientId,
					fullRequestContext, fullResponseContext);
			if (oplog.isDebugEnabled()) {
				var addonMetrics = getUsedMemoryAndRequests(numberRequests, false);
				StaticOptraceHelper.logEnter(oplog, OPTRACE_SERVER_REQUEST, rc, addonMetrics, optional);
			}
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
	}

	@Override
	public void logClientCall(String calledObject, String calledMethod) {
		logClientCall(calledObject, calledMethod, new Object[0][0]);
	}

	@Override
	public void logClientCall(String calledObject, String calledMethod, Object[][] optional) {
		try {
			var numberRequests = pendingRequests.incrementAndGet();
			var rc = REQUEST_CONTEXT_FACTORY.extendTransferId(calledObject, calledMethod);
			rc.getFanOutRequestCounter()
			  .incrementAndGet();
			if (oplog.isDebugEnabled()) {
				var addonMetrics = getUsedMemoryAndRequests(numberRequests, false);
				StaticOptraceHelper.logEnter(oplog, OPTRACE_CLIENT_REQUEST, rc, addonMetrics, optional);
			}
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
	}

	@Override
	public void logClientReturn(Object exception) {
		logClientReturn(exception, null);
	}

	@Override
	public void logClientReturn(Object exception, Object[][] optional) {
		try {
			var numberRequests = pendingRequests.decrementAndGet();
			var rc = REQUEST_CONTEXT_FACTORY.getRequestContext();
			if (rc == null) {
				throw new IllegalStateException(OPTRACE_THREADCTX_ERROR);
			}
			if (oplog.isInfoEnabled()) {
				var addonMetrics = getUsedMemoryAndRequests(numberRequests, false);
				StaticOptraceHelper.logExit(oplog, OPTRACE_CLIENT_RESPONSE, rc, exception, addonMetrics, optional);
			}
			REQUEST_CONTEXT_FACTORY.delete();
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
	}

	@Override
	public void logInitialReturn(Object exception, Object[][] optional) {
		try {
			var numberRequests = concurrentRequests.decrementAndGet();
			var rc = getRequestContext();
			if (oplog.isInfoEnabled()) {
				var addonMetrics = getUsedMemoryAndRequests(numberRequests, true);
				StaticOptraceHelper.logExit(oplog, OPTRACE_SERVER_RESPONSE, rc, exception, addonMetrics, optional,
						new LogParameter(StaticOptraceHelper.FAN_OUT_REQUESTS_NAME, rc.getFanOutRequestCounter())
				);
			}
			REQUEST_CONTEXT_FACTORY.delete();
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
	}

	@Override
	public RequestContext logAsyncClientCall(String calledObject, String calledMethod) {
		return logAsyncClientCall(calledObject, calledMethod, null);
	}

	@Override
	public RequestContext logAsyncClientCall(String calledObject, String calledMethod, Object[][] optional) {
		RequestContext rc = null;
		try {
			rc = REQUEST_CONTEXT_FACTORY.getNextTransferId(calledObject, calledMethod);
			if (oplog.isDebugEnabled()) {
				String[][] mem =
						{ { StaticOptraceHelper.MEM_USED, String.valueOf(RUNTIME.totalMemory() - RUNTIME.freeMemory()) } };
				StaticOptraceHelper.logEnter(oplog, OPTRACE_CLIENT_REQUEST, rc, mem, optional);
			}
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
		return rc;
	}

	@Override
	public void logAsyncClientReturn(RequestContext rc, Object exception) {
		logAsyncClientReturn(rc, exception, null);
	}

	@Override
	public void logAsyncClientReturn(RequestContext rc, Object exception, Object[][] optional) {
		try {
			if (oplog.isInfoEnabled()) {
				String[][] mem =
						{ { StaticOptraceHelper.MEM_USED, String.valueOf(RUNTIME.totalMemory() - RUNTIME.freeMemory()) } };
				StaticOptraceHelper.logExit(oplog, OPTRACE_CLIENT_RESPONSE, rc, exception, mem, optional);
			}
		}
		catch (Exception e) {
			log.error(OPTRACE_PROCESSING_ERROR, e);
		}
	}

	private static String[] makeConcurrentRequestsStrings(final long concurrentRequests) {
		final String numberRequestsString = String.valueOf(concurrentRequests);
		return new String[] { "cR", numberRequestsString };
	}

	private static String[][] getUsedMemoryAndRequests(long numberRequests, boolean freeToo) {
		var curReqCnt = makeConcurrentRequestsStrings(numberRequests);
		var freeMem = RUNTIME.freeMemory();
		var usedMemAmount = new String[] { StaticOptraceHelper.MEM_USED, String.valueOf(RUNTIME.totalMemory() - freeMem) };
		var freeMemAmount = new String[] { StaticOptraceHelper.MEM_FREE, String.valueOf(freeMem) };
		if (freeToo) {
			return new String[][] { curReqCnt, usedMemAmount, freeMemAmount };
		}
		return new String[][] { curReqCnt, usedMemAmount };
	}

	@Override // <<<<<
	public boolean isInfoEnabled() {
		return oplog.isInfoEnabled();
	}

	@Override // >>>>>
	public boolean isDebugEnabled() {
		return oplog.isDebugEnabled();
	}

	@Override // transport details
	public boolean isTraceEnabled() {
		return oplog.isTraceEnabled();
	}

}
