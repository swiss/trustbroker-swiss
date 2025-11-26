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

/**
 * Implemented by classes that provide an application wide request context.
 * Each request context has its own ID, which is unique per request. The ID can hence
 * be used for tracking specific user requests by correlating it with user name.
 * The request context references a ApplicationContext, which can be used to store
 * name-value-pairs. The ApplicationContext allows to have a application-wide session if
 * it is stored between requests (what is done by the RequestContextFilter).
 * <p>
 * Note: As request contexts can be serialized it is imperative that any referenced
 * objects are also serializable and that the overall size is kept at a minimum.
 */
public interface RequestContext {

	String getTraceId();

	String getConversationId();

	String getClientId();

	String getPrincipal();

	String getCalledObject();

	String getCalledMethod();

	long getStart();

	AtomicLong getFanOutRequestCounter();

	Object[][] getFullRequestContext();

	Object[][] getFullResponseContext();
}
