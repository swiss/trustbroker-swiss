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

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.Data;
import swiss.trustbroker.common.util.StringUtil;

@Data
@Builder
public class DefaultRequestContext implements RequestContext {

	private final String clientId;

	private final String traceId;

	private final String calledObject;

	private final String calledMethod;

	private final Object fullRequestContext;

	private final Object fullResponseContext;

	private final AtomicLong fanOutRequestCounter;

	@Builder.Default
	private final String principal = "ANONYMOUS";

	@Builder.Default
	private final long start = System.currentTimeMillis();

	@Override
	public String getConversationId() {
		return TraceSupport.getOwnTraceParent();
	}

	@Override
	public AtomicLong getFanOutRequestCounter() {
		return fanOutRequestCounter;
	}

	@Override
	public Object[][] getFullRequestContext() {
		if (fullRequestContext instanceof HttpServletRequest) {
			return getInternalRequestContext().toArray(new Object[0][]);
		}
		return new Object[0][];
	}

	@Override
	public Object[][] getFullResponseContext() {
		if (fullResponseContext instanceof HttpServletResponse httpServletResponse) {
			var ret = getInternalRequestContext(); // on response add request protocol too
			var names = httpServletResponse.getHeaderNames();
			if (names != null) {
				for (var name : names) {
					var value = httpServletResponse.getHeader(name);
					var pair = new String[] { "http.res." + name.toLowerCase(), value };
					ret.add(pair);
				}
				return ret.toArray(new Object[0][]);
			}
		}
		return new Object[0][];
	}

	private ArrayList<Object[]> getInternalRequestContext() {
		var ret = new ArrayList<Object[]>();
		if (fullRequestContext instanceof HttpServletRequest httpServletRequest) {
			var names = httpServletRequest.getHeaderNames();
			while (names != null && names.hasMoreElements()) {
				var name = names.nextElement();
				var value = httpServletRequest.getHeader(name);
				var pair = new String[] { "http.req." + name.toLowerCase(), value };
				ret.add(pair);
			}
			var params = httpServletRequest.getParameterNames();
			while (params != null && params.hasMoreElements()) {
				var name = StringUtil.clean(params.nextElement());
				var value = StringUtil.clean(httpServletRequest.getParameter(name));
				var pair = new String[] { "http.param." + name, value };
				ret.add(pair);
			}
		}
		return ret;
	}


}
