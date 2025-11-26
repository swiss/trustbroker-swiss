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
 * Factory for getting hold of the currently valid request context. I.e. the context
 * associated with the current user's current request.
 *
 * @author  kkj
 * @since 26-09-2004 17:29:20
 * @version $Revision$
 */
public interface RequestContextFactory {

	/**
	 * Creates a new RequestContext with the given traceId and principal.
	 *
	 * @param calledObject called object or called servlet/filter or database name
	 * @param calledMethod method called or request URL or SQL query
	 * @param traceId traceId that will be set for the RequestContext
	 * @param principal userPrincipal to set for the RequestContext
	 * @param clientId  clientId to set for the RequestContext
	 * @param fullRequestContext injection point dependent data (e.g. the HttpServletRequest)
	 * @return newly created RequestContext
	 */
	RequestContext create(String calledObject, String calledMethod, String traceId, String principal, String clientId,
			Object fullRequestContext, Object fullResponseContext);


	/**
     * Creates a new RequestContext based on the provided context.
     */
    RequestContext create(String calledObject, String calledMethod, RequestContext context);

    /**
     * Puts a new RequestContext with an extended traceId onto the request context stack.
     *
     * This is done when a synchronous client call is done. Asynchronous client calls also
     * get a RequestContext with an extended traceId but that RequestContext may not be put
     * onto the request context stack. The client doing the asynchronous call must manage the
     * returned RequestContext by itself.
     * @see RequestContextFactory#getNextTransferId(String, String)
     * @return current RequestContext with extended traceId
     */
    RequestContext extendTransferId(String obj, String mth);

    /**
     * Creates a new RequestContext with an extended traceId.
	 *
     * Generates a new unique Transfer-Id. The new Transfer-Id is built by appending a process-wide
     * unique Request-Id to the Transfer-Id stored in the current RequestContext on top of the
     * request context stack. The resulting RequestContext is not put itself onto the request
     * context stack. Asynchronous client calls use this method to get a RequestContext with an
     * extended traceId.
     *
     * @return unique traceId
     * @throws IllegalArgumentException when no RequestContext is available
     */
    RequestContext getNextTransferId(String obj, String mth);

   	/**
     * Used to get the actual RequestContext from the top of the request context stack.
     *
     * It only returns the top of the stack it does not remove it.
     *
     * @return actual RequestContext or null if none exists
     */
    RequestContext getRequestContext();

    /**
     * Puts the RequestContext onto the request context stack.
     *
     * Server side entering (logInitialEnter, logEnter) and the synchronous client side service
     * invocation (logClientCall) statement put there RequestContext onto that stack. There
     * corresponding return statements will later remove them form the stack again.
     * NOTE: The request context stack itself is stored in a thread local.
     * @param rc new RequestContext which will be put onto the request context stack
     */
    void setRequestContext(RequestContext rc);

    /**
     * Removes the last RequestContext from the request context stack.
     *
     * Any synchronous return statement (logInitialReturn, logReturn, logClientReturn)
     * removes its RequestContext from the stack.
     * @see RequestContextFactory#setRequestContext(RequestContext)
     */
    void delete();

}
