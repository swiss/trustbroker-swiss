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

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import swiss.trustbroker.common.util.WebUtil;

/**
 * This class adopts the OpenTelemetry effort providing these features:
 * <ul>
 *   <li>MDC traceId to tag every log line with the OpenTelemetry compatible traceId.spanId where spanId is our own root</li>
 *   <li>OpTrace logs are tagged with trID=traceId.spanId for request based tracing</li>
 *       The related W3C specification (see <a href=""/> lists these propagations:
 *   <li>traceparanet is set by XTB if not received from client, we derive traceId from x-request-id if it's compliant.</li>
 *   <li>tracestate is not (yet) supported</li>
 * </ul>
 * Note that the ID displayed in error screen are either based on current requests or the related login conversation
 * depending on the processing phase within XTB. If we do not yet know a conversation because OpenTelemetry tracing is
 * not supported by our user-agent, the ID can switch from one to the other.
 */
@Slf4j
public class TraceSupport {

	public static final String XTB_CLIENTIP = "clientIp";

	public static final String XTB_GATEWAYIP = "gatewayIp";

	public static final String HTTP_REQUEST_ID = "X-Request-Id"; // set by LB

	public static final String W3C_TRACEPARENT = "traceparent";

	public static final String XTB_TRACEID = "traceId"; // hex32 traceId (conversation, fallback to request)

	private static final String XTB_PARENTID = "parentId"; // hex16 spanId (our own current request parent)

	private static final String W3C_TRACEPARENT_REGEXP = "[\\d]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[\\d]{2}";

	private static final String MDC_TRACEID_REGEXP = "[0-9a-f]{32}\\.[0-9a-f]{16}";

	private static final String HTTP_RREQUST_REGEXP = "[0-9a-zA-Z]*"; // truncate, pad, toLower

	private static final String PREFIX_SAML = "S2-"; // SAML message ID prefix vers

	// x-request-id is default, alternatives are transferId, x-request-id, uber-trace-id, x-b3-traceid, ot-tracer-traceid
	private static String httpHeaderTraceId = HTTP_REQUEST_ID;

	private TraceSupport() {
	}

	/**
	 * Provide traceId injected by client. If present our own request or conversation is derived from it.
	 * @return request client injected may be OpenTelemetry compliant traceId[.parentId]
	 */
	public static String getCallerTraceParent() {
		return getMdcTraceParent();
	}

	/**
	 * Provide traceId for logging, error handling and backend propagation.
	 * @return request or conversation based own OpenTelemetry complaint traceId parent spanId
	 */
	public static String getOwnTraceParent() {
		return getMdcTraceId();
	}

	/**
	 * Provide OpenTelemetry compliant traceId for HTTP propagation to services.
	 * @return OpenTelemetry compliant HTTP traceparent header.
	 */
	public static String getOwnTraceParentForHttp() {
		return getOwnTraceParentForWire("00-", "-01");
	}

	/**
	 * Provide SAML compliant traceId for propagation in own SAML messages.
	 * SAML compliant means: XML ID must start with a _ or character, RelayState max 80 characters.
	 * @return SAML compliant traceparent representation.
	 */
	public static String getOwnTraceParentForSaml() {
		// postfix for security and to get 4 tokens like traceparent
		return getOwnTraceParentForWire(PREFIX_SAML, "-" + generateRandomId(24));
	}

	// On the wire we use - as separator, in MDC and logs we use .
	private static String getOwnTraceParentForWire(String prefix, String postfix) {
		var traceId = getMdcTraceId().replace(".", "-"); // log uses x.y wire uses x-y
		return prefix + traceId + postfix;
	}

	// NOTE: TraceIds pop up on XTB error screen and are used to correlate the request in the logs across services.
	// OpenTelemetry hex32 traceIds and hex16 spanIds are used on HTTP and SAML protocols, logs and the state cache.
	private static String getOrCreateParentTraceId(HttpServletRequest request, String httpDefaultTraceIdHeader) {
		// consider client being an OpenTelemetry enabled user-agent
		var source = W3C_TRACEPARENT;
		var ret = getW3cTraceParent(request);
		// LB injected header as configured
		if (ret == null) {
			source = httpDefaultTraceIdHeader;
			ret = getW3cTraceParentFromRequestId(request, source);
		}
		// internet common use
		if (ret == null) {
			source = HTTP_REQUEST_ID;
			ret = getW3cTraceParentFromRequestId(request, source);
		}
		if (ret == null) {
			ret = generateInitialTraceId();
			log.debug("Generated traceId={}", ret);
		}
		else {
			log.trace("Found traceId={} in source={}", ret, source);
			ret = appendInitialSpanId(ret);
		}
		return ret; // hex32 lowercase
	}

	private static String getW3cTraceParent(HttpServletRequest request) {
		var parent = WebUtil.getHeader(W3C_TRACEPARENT, request);
		if (parent == null) {
			return null;
		}
		if (parent.matches(W3C_TRACEPARENT_REGEXP)) {
			var toks = parent.split("-");
			log.debug("Detected HTTP {}={} having client based traceId={}", W3C_TRACEPARENT, parent, toks[1]);
			MDC.put(W3C_TRACEPARENT, toks[1] + "." + toks[2]); // just internal context save
			return toks[1];
		}
		log.info("Ignoring HTTP {}={} violating '{}'", W3C_TRACEPARENT, parent, W3C_TRACEPARENT_REGEXP);
		return null;
	}

	private static String getW3cTraceParentFromRequestId(HttpServletRequest request, String headerName) {
		var ret = WebUtil.getHeader(headerName, request);
		if (ret == null) {
			return null;
		}
		// make sure we are not spamming our log facility
		ret = ret.replace("-", ""); // accept also UUID notation (hex8-hex4-hex4-hex4-hex12)
		if (!ret.matches(HTTP_RREQUST_REGEXP)) {
			log.warn("Ignoring traceId from {}={} violating validation '{}'", headerName, ret, HTTP_RREQUST_REGEXP);
			return null;
		}
		// save original value for reference even though it's not OpenTelemetry compliant without parentSpan
		MDC.put(W3C_TRACEPARENT, ret);
		var len = ret.length();
		if (len > 32) {
			log.debug("Truncating traceId from {}={} to 32 chars", headerName, ret);
			ret = ret.substring(0, 32); // we accept hex uppercase and make it OpenTelemtry compliant
		}
		else if (len < 32) {
			log.debug("Padding traceId from {}={} to 32 chars", headerName, ret);
			ret = StringUtils.leftPad(ret, 32, "0");
		}
		ret = ret.toLowerCase();
		return ret;
	}

	private static String generateRandomId(int len) {
		return UUID.randomUUID()
				   .toString()
				   .replace("-", "")
				   .substring(0, len)
				   .toLowerCase();
	}

	private static String generateInitialTraceId() {
		return appendInitialSpanId(generateRandomId(32));
	}

	private static String appendInitialSpanId(String traceId) {
		return traceId + "." + generateRandomId(16);
	}

	public static String getHttpTraceIdHeaderName() {
		return httpHeaderTraceId;
	}

	// NOT thread-save but only used at startup when wiring our setup.
	// We can switch to any HTTP injected request identifier (X-Request-Id or X-B3-TraceId) used in errors and MDC based logging.
	public static void setHttpTraceIdHeaderName(String newHttpHeaderLbTraceId) {
		httpHeaderTraceId = newHttpHeaderLbTraceId;
	}

	public static void setMdcTraceContext(HttpServletRequest request) {
		var traceId = getOrCreateParentTraceId(request, httpHeaderTraceId);
		setMdcTraceContext(traceId);
		MDC.put(XTB_CLIENTIP, WebUtil.getClientIp(request));
		MDC.put(XTB_GATEWAYIP, WebUtil.getGatewayIp(request, true));
	}

	// For testing
	public static void setMdcTraceContext(String traceId) {
		MDC.put(XTB_TRACEID, traceId); // injected own traceparent (might be conversational or request based or generated)
		MDC.put(XTB_PARENTID, traceId.substring(33)); // parent span only
	}

	public static void clearMdcTraceContext() {
		MDC.remove(XTB_CLIENTIP); // TCP tracing
		MDC.remove(XTB_GATEWAYIP); // Infrastructure tracing
		MDC.remove(W3C_TRACEPARENT); // HTTP request tracing
		MDC.remove(XTB_TRACEID); // HTTP/SAML request or conversation tracing
		MDC.remove(XTB_PARENTID); // Own spanId replacing traceparent spanId
	}

	// initial one for clients or batch jobs not having a boundary injection e.g. clients like a system test
	private static String getOrCreatedTraceId(String mdcKey) {
		var traceId = MDC.get(mdcKey);
		if (traceId != null) {
			return traceId;
		}
		traceId = generateInitialTraceId();
		log.debug("Generated new initial traceId={}", traceId);
		setMdcTraceContext(traceId);// nothing provided yet
		MDC.put(XTB_CLIENTIP, "0.0.0.0/LIB");
		return MDC.get(mdcKey);
	}

	// We at various protocol layers pass the conversation and re-apply it here with our current own parent spanId.
	// When traceId is logged on every log line, traceId part switches from request to conversation, parent spanId is retained.
	static void switchMdcTraceContext(String conversationId) {
		if (conversationId != null) {
			var toks = conversationId.split("[-.]"); // wire uses v-t-p-f, MDC we use t.p
			var traceId = toks.length > 2 ? toks[1] : toks [0];
			var ownConversationTraceId = traceId + "." + MDC.get(XTB_PARENTID);
			if (!ownConversationTraceId.matches(MDC_TRACEID_REGEXP)) {
				log.warn("Ignoring traceId={} violating validation '{}'", ownConversationTraceId, MDC_TRACEID_REGEXP);
			}
			else if (!getMdcTraceId().equals(ownConversationTraceId)) {
				log.debug("Switched to conversational traceId={} from currentTraceId={}",
						ownConversationTraceId, getMdcTraceId());
				MDC.put(XTB_TRACEID, ownConversationTraceId);
			}
		}
	}

	static String getMdcTraceId() {
		return getOrCreatedTraceId(XTB_TRACEID);
	}

	static String getMdcParentId() {
		return getOrCreatedTraceId(XTB_PARENTID);
	}

	static String getMdcTraceParent() {
		return MDC.get(W3C_TRACEPARENT);
	}

	public static String getClientIp() {
		return MDC.get(XTB_CLIENTIP);
	}

	public static String getGatewayIp() {
		return MDC.get(XTB_GATEWAYIP);
	}

	public static void switchToConversation(String messageId) {
		if (messageId != null) {
			switchMdcTraceContext(messageId);
		}
	}

	public static String switchToConversationFromSamlId(String messageId) {
		if (messageId != null && messageId.startsWith(PREFIX_SAML)) {
			switchToConversation(messageId);
		}
		return getMdcTraceId();
	}

}
