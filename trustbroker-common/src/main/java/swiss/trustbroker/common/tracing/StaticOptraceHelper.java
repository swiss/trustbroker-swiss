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

import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Slf4j
public final class StaticOptraceHelper {

	@SuppressWarnings("java:S1312")
	private static final Logger HTTP_LOG_DETAILS = LoggerFactory.getLogger(OpTraceConfiguration.getLoggerName() + ".http");

	private static final String STRING_NOK = "EXCEPTION";

	private static final String STRING_OK = "OK";

	private static final String PKG_NAME = OpTraceConfiguration.getPkgName();

	private static final String PKG_VERSION = OpTraceConfiguration.getPkgVersion();

	private static final String INSTANCE_NAME = OpTraceConfiguration.getInstanceName();

	private static final String P_CTX_NAME = "pCtx";

	private static final String RT_CTX_NAME = "rtCtx";

	private static final String STATUS_CODE_NAME = "sC";

	private static final String DURATION_NAME = "dTms";

	private static final String OBJECT_NAME = "obj";

	private static final String METHOD_NAME = "mth";

	private static final String TRANSFERID_NAME = "tID"; // traceId (historically transferId)

	private static final String CLIENTID_NAME = "clID";

	private static final String PRINCIPAL_NAME = "pri";

	public static final String FAN_OUT_REQUESTS_NAME = "foR";

	public static final String MEM_USED = "usedMem";

	public static final String MEM_FREE = "freeMem";

	static final String CONVERSATION_ID = "conversationId";

	private static final String P_CTX_STRING = P_CTX_NAME + "=" + OpTraceUtil.HOST_IP_HEX_8 + "-" + OpTraceUtil.PID_HEX_4;

	private static final String RT_CTX_STRING = RT_CTX_NAME + "=" + PKG_NAME + PKG_VERSION + INSTANCE_NAME;

	private static final Pattern SIMPLE_VALUE_PATTERN = Pattern.compile("\\w*");

	private StaticOptraceHelper() {
	}

	static void logEnter(
			Logger opLog, String direction, RequestContext rc, Object[][] optionalInternal, Object[][] optional
	) {
		var builder = getFirstPartOfEntry(new StringBuilder(256), direction, rc);
		appendParams(builder, optionalInternal);
		appendParams(builder, optional);

		// identify client device if possible
		appendClientId(builder, rc.getClientId());

		// protocol details
		if (opLog.isTraceEnabled() && rc.getFullRequestContext() != null) {
			appendParams(builder, rc.getFullRequestContext());
		}

		// incoming output only in DEBUG
		if (opLog.isDebugEnabled()) {
			opLog.debug(builder.toString());
		}
	}

	static void logExit(Logger opLog, String direction, RequestContext rc, Object exception,
			Object[][] optionalInternal, Object[][] optional, LogParameter... extraParameters) {

		var builder = getFirstPartOfEntry(new StringBuilder(256), direction, rc);

		var state = (exception == null) ? STRING_OK : STRING_NOK;
		builder.append(", " + STATUS_CODE_NAME + "=")
			   .append(state);

		var time = System.currentTimeMillis() - rc.getStart();
		builder.append(", " + DURATION_NAME + "=")
			   .append(time);

		appendParams(builder, optionalInternal);
		appendParams(builder, optional);

		appendClientId(builder, rc.getClientId());
		appendExtraParameters(builder, extraParameters);

		// HTTP req(uest) / res(ponse) / param(eters) protocol debugging attaching everything to response line
		var protocolContext = logProtocolDetails(rc);
		appendParams(builder, protocolContext);

		if (opLog.isInfoEnabled()) {
			opLog.info(builder.toString());
		}
	}

	private static Object[][] logProtocolDetails(RequestContext rc) {
		// WIth TRACE we log everything, with DEBUG only conversational access
		if (HTTP_LOG_DETAILS.isTraceEnabled()
				|| (HTTP_LOG_DETAILS.isDebugEnabled() && !rc.getTraceId().equals(rc.getConversationId()))) { //
			return rc.getFullResponseContext();
		}
		return new Object[0][];
	}

	private static StringBuilder getFirstPartOfEntry(StringBuilder sb, String direction, RequestContext rc) {
		var calledObject = rc.getCalledObject();
		var calledMethod = quoteIfNecessary(rc.getCalledMethod());
		var tid = rc.getTraceId();
		var principal = rc.getPrincipal();

		sb.append(OpTraceConfiguration.getOptraceVersion());
		sb.append(" ")
		  .append(direction);

		// observed on intercepted object (obj)....
		sb.append(" ")
		  .append(OBJECT_NAME)
		  .append("=")
		  .append(calledObject);
		// ...and  method (mth)
		sb.append(", ")
		  .append(METHOD_NAME)
		  .append("=")
		  .append(calledMethod);

		// request identifier (tID) based on injected traceparent, x-request-id, uber-trace-id, x-b3-traceid, ot-tracer-traceid
		sb.append(", ")
		  .append(TRANSFERID_NAME)
		  .append("=")
		  .append(tid);

		// conversation os optional, tID switches when during processing on higher protocol level we het a new ID
		var conversationId = rc.getConversationId();
		if (!tid.equals(conversationId)) {
			sb.append(", " + CONVERSATION_ID + "=")
			  .append(conversationId);
		}

		// authenticated user principal if available
		if (!StringUtils.isEmpty(principal)) {
			sb.append(", ")
			  .append(PRINCIPAL_NAME)
			  .append("=")
			  .append(principal);
		}

		// runtime context (rCtx)
		sb.append(", ")
		  .append(RT_CTX_STRING);

		// process context (pCtx = hex(ip).hex(pid).hex(tid))
		sb.append(", ")
		  .append(P_CTX_STRING)
		  .append("-")
		  .append(OpTraceUtil.getThreadHex8());

		return sb;
	}

	public static void appendParams(StringBuilder result, Object[][] params) {
		// validate params format
		if (params != null) {
			for (Object[] param : params) {
				result.append(", ");
				result.append(param[0]);
				result.append("=");
				result.append(quoteIfNecessary(param[1]));
			}
		}
	}

	private static void appendClientId(StringBuilder builder, String clientId) {
		if (!StringUtils.isEmpty(clientId)) {
			builder.append(", ")
				   .append(CLIENTID_NAME)
				   .append("=")
				   .append(clientId);
		}
	}

	private static void appendExtraParameters(StringBuilder builder, LogParameter[] param) {
		for (LogParameter logParameter : param) {
			builder.append(logParameter.toLogString());
		}
	}

	private static Object quoteIfNecessary(Object value) {
		if (value instanceof String stringValue && !SIMPLE_VALUE_PATTERN.matcher(stringValue).matches()) {
			return "'" + stringValue + "'"; // Splunk etc. compatible
		}
		return value;
	}

}
