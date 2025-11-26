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


/**
 * This class is used to do manual operation tracing (OP-tracing). The methods to emit log entries are pairs. If the first
 * method of the call chain is entered one uses logInitialEnter to initialize the RequestContext and
 * emit a log entry. If one leaves that method one uses logInitialReturn to delete the RequestContext
 * and emit a log entry. For all other methods one uses logEnter and logReturn. If one calls another
 * service (so one is client) logClientCall is used to extend the traceId to mark that call and to
 * emit a log entry. If one returns from that call one uses logClientReturn to restore the traceId
 * and to emit a log entry.
 */
public interface OpTraceLogger {

	/**
	 * Get the actually set RequestContext.
	 * @return actually set RequestContext or null if not set.
	 */
	RequestContext getRequestContext();

	/**
	 * Emit a service entering statement into the OP-TraceLog.
	 *
	 * Use this method to log the entering into the first service called on this JVM for a
	 * given request/thread. A new RequestContext is created with the given parameters and
	 * the current time. It is assumed that no RequestContext object exists yet in this
	 * thread.
	 *
	 * In general this will be done when a request enters the web tier or when entering the
	 * business tier e.g. remote-ejb or webservice.
	 *
	 * @param traceId initial traceId for that request (received from e.g. reverse proxy)
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param principal userPrincipal emitted in the log statement.
	 * @param clientId id of client as received from front-end (e.g. reverse proxy) server or session ID
	 */
	void logInitialEnter(String traceId, String calledObject, String calledMethod, String principal, String clientId);

	/**
	 * Emit a service entering statement into the OP-TraceLog.
	 **
	 * @param traceId initial traceId for that request (received from e.g. reverse proxy)
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param principal userPrincipal emitted in the log statement.
	 * @param optional name/value pairs to be appended at the end of the log entry
	 * @param clientId id of client as received from front-end (e.g. reverse proxy) server or session ID
	 */
	void logInitialEnter(String traceId, String calledObject, String calledMethod, String principal, Object[][] optional,
			String clientId);

	/**
	 * Emit a service entering statement into the OP-TraceLog.
	 **
	 * @param traceId initial traceId for that request (received from e.g. reverse proxy)
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param principal userPrincipal emitted in the log statement.
	 * @param optional name/value pairs to be appended at the end of the log entry
	 * @param clientId id of client as received from front-end (e.g. reverse proxy) server or session ID
	 * @param fullRequestContext injection point dependent data (e.g. the HttpServletRequest)
	 */
	@SuppressWarnings("java:S107")
	void logInitialEnter(String traceId, String calledObject, String calledMethod, String principal, Object[][] optional,
			String clientId, Object fullRequestContext, Object fullResponseContext);

	/**
	 * Emit a service invocation statement into the OP-TraceLog.
	 *
	 * Used to emit a log entry if one calls another service. The traceId is extended to give this
	 * call a unique traceId. Only use this method for synchronous calls. You have to call logClientReturn
	 * after using this method.
	 *
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 */
	void logClientCall(String calledObject, String calledMethod);

	/**
	 * Emit a service invocation statement into the OP-TraceLog.
	 *
	 * @see OpTraceLogger#logClientCall(String, String)
	 *
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param optional name/value pairs to be appended at the end of the log entry
	 */
	void logClientCall(String calledObject, String calledMethod, Object[][] optional);


	/**
	 * Emit a return from service invocation statement into the OP-TraceLog.

	 * Used when returning from a call to another service. Only use this method,
	 * if you used logClientCall before.
	 *
	 * @param exception optional object which represents an error condition (null on success)
	 */
	void logClientReturn(Object exception);


	/**
	 * Emit a return from service invocation statement into the OP-TraceLog.
	 *
	 * @see OpTraceLogger#logClientReturn(Object)
	 *
	 * @param exception optional object which represents an error condition (null on success)
	 * @param optional name/value pairs to be appended at the end of the log entry
	 */
	void logClientReturn(Object exception, Object[][] optional);

	/**
	 * Emit a service leaving statement into the OP-TraceLog.
	 *
	 * Used before returning from a service method. Only use this method, if you used one of the
	 * logInitialEnter methods before.
	 *
	 * @param exception optional object which represents an error condition (null on success)
	 */
	void logInitialReturn(Object exception, Object[][] optional);


	/**
	 * Emit a asynchronous service invocation statement into the OP-TraceLog.
	 *
	 * Used to emit a log entry if one calls another service. The traceId is extended
	 * to give this call a unique traceId. Only use this method for asynchronous calls.
	 * You have to call logAsyncClientReturn after using this method where you have to
	 * pass the RequestContext object returned by this method.
	 *
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @return RequestContext used for the call to logAsyncClientReturn
	 */
	RequestContext logAsyncClientCall(String calledObject, String calledMethod);

	/**
	 * Emit a asynchronous service invocation statement into the OP-TraceLog.
	 *
	 * @see OpTraceLogger#logAsyncClientCall(String, String)
	 *
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param optional name/value pairs to be appended at the end of the log entry
	 * @return RequestContext used for the call to logAsyncClientReturn
	 */
	RequestContext logAsyncClientCall(String calledObject, String calledMethod, Object[][] optional);

	/**
	 * Emit the return from a asynchronous service invocation statement into the OP-TraceLog.
	 *
	 * Used to emit a log return if one returns from a service. Only use this method for
	 * asynchronous calls. You may have called logAsyncClientCall in advance an use the
	 * RequestContext returned by it.
	 *
	 * @param rc returned RequestContext by the corresponding logAsyncClientCall
	 * @param exception optional object which represents an error condition (null on success)
	 */
	void logAsyncClientReturn(RequestContext rc, Object exception);

	/**
	 * Emit the return from a asynchronous service invocation statement into the OP-TraceLog.
	 *
	 * @see OpTraceLogger#logAsyncClientReturn(RequestContext, Object)
	 *
	 * @param rc returned RequestContext by the corresponding logAsyncClientCall
	 * @param exception optional object which represents an error condition (null on success)
	 * @param optional name/value pairs to be appended at the end of the log entry
	 */
	void logAsyncClientReturn(RequestContext rc, Object exception, Object[][] optional);

	/**
	 * Check if we should log responses
	 * @return true if logging responses is INFO
	 */
	boolean isInfoEnabled();

	/**
	 * Check if we should log responses
	 * @return true if logging responses is DEBUG
	 */
	boolean isDebugEnabled();

	/**
	 * Check if we should log transport details
	 * @return true if logging responses is TRACE
	 */
	boolean isTraceEnabled();

}
