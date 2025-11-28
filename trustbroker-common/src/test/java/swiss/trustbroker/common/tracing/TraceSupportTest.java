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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.util.WebUtil;

class TraceSupportTest {

	@BeforeEach
	@AfterEach
	void clearMdc() {
		TraceSupport.clearMdcTraceContext();
	}

	@ParameterizedTest
	@CsvSource(value = {
			"00-000102030405060708090a0b0c0d0e0f-0102030405060708-01,true", // valid
			"00-000102030405060708090a0b0c0d0e0F-0102030405060708-01,false", // HEX uppercase
			"000-000102030405060708090a0b0c0d0e0F-0102030405060708-01,false", // version too long
			"00-000102030405060708090a0b0c0d0e0f0-0102030405060708-01,false", // traceId too long
			"00-000102030405060708090a0b0c0d0e0f-01020304050607080-01,false", // parentId too long
			"00-000102030405060708090a0b0c0d0e0f-0102030405060708-010,false", // flags too long
			"a0-000102030405060708090a0b0c0d0e0f-0102030405060708-01,false", // version 00 violated
			"000102030405060708090a0b0c0d0e0f,false" // not a traceparent
	})
	void checkAcc(String id, boolean match) {
		var request = new MockHttpServletRequest();
		request.addHeader(TraceSupport.W3C_TRACEPARENT, id);
		TraceSupport.setMdcTraceContext(request);
		var expectedCallerId = match ?
				String.join(".", id.split("-")[1], id.split("-")[2]) :
				TraceSupport.getCallerTraceParent();
		var expectedOwnId = match ?
				String.join(".", id.split("-")[1], TraceSupport.getMdcParentId()) :
				TraceSupport.getOwnTraceParent();
		assertThat(TraceSupport.getCallerTraceParent(), is(expectedCallerId));
		assertThat(TraceSupport.getOwnTraceParent(), is(expectedOwnId));
	}

	@Test
	void testTraceIdForSamlMessages() {
		var id = TraceSupport.getOwnTraceParentForSaml();
		assertThat(id, is(notNullValue()));
		assertThat(id.length(), is(77)); // not more than 80 but long enough for 12h to not collide
		assertThat(id, is(notNullValue()));
		assertThat(id, startsWith("S2-"));
		assertThat(id.split("-").length, is(4));
	}

	@Test
	void testConversationSwitch() {
		var request = new MockHttpServletRequest();

		// incoming request with too short but acceptable trace header (pad and toLower will be applied)
		var injectedTraceId = "01020304-0506-0708-090A-0b0c0d0e0f"; // pad to hex32 and toLower and accept UUID notation
		request.addHeader(TraceSupport.HTTP_REQUEST_ID, injectedTraceId);
		request.addHeader(WebUtil.HTTP_HEADER_X_FORWARDED_FOR, "127.0.0.2");
		TraceSupport.setMdcTraceContext(request);
		var expectedTraceId = injectedTraceId.replaceAll("-", "");

		// initial wire based traceId setup, parent spanId is generated as it's missing in X-Request-Id
		var parentSpanId = TraceSupport.getMdcParentId();
		var expectedTracePart = "00" + expectedTraceId.toLowerCase();
		assertThat(TraceSupport.getCallerTraceParent(), is(expectedTraceId)); // not OpenTelemetry compliant
		assertWireTrace(expectedTracePart + ".0000000000000000");
		assertThat(TraceSupport.getClientIp(), is("127.0.0.2/XFF"));

		// switch to conversation from state cache
		var savedConversationId = "11111111111111111111111111111110.0000000000000000";
		TraceSupport.switchToConversation(savedConversationId);
		assertConversationTrace(savedConversationId.split("\\.")[0] + "." + parentSpanId);

		// switch to conversation from HTTP traceparent (given it get's propagated correctly by user-agent), parent spanid stays
		var conversationIdW3c = "00-11111111111111111111111111111111-0000000000000001-00";
		TraceSupport.switchToConversation(conversationIdW3c);
		assertThat(TraceSupport.getCallerTraceParent(), is(expectedTraceId)); // unchanged
		assertConversationTrace(conversationIdW3c.split("-")[1] + "." + parentSpanId);

		// switch to conversation from SAML ID or InResponseTo
		var conversationIdSaml = "S2-11111111111111111111111111111112-0000000000000002-00000002";
		TraceSupport.switchToConversationFromSamlId(conversationIdSaml);
		assertConversationTrace(conversationIdSaml.split("-")[1] + "." + parentSpanId);

		// should not switch
		var rpId = "XX-11111111111111111111111111111112-0000000000000002-00000002";
		TraceSupport.switchToConversationFromSamlId(rpId);
		assertWireTrace(rpId.substring(3, 52).replace("-", "."));
	}

	private void assertWireTrace(String callerTraceId) {
		assertThat(callerTraceId.length(), is(49));
		var toksWire = callerTraceId.split("\\.");
		var toksMdc = TraceSupport.getOwnTraceParent().split("\\.");
		assertThat(toksWire[0], is(toksMdc[0]));
		assertThat(toksWire[1], not(toksMdc[1]));
		// traceId the same, parentId on own trace parent replaced
	}

	private void assertConversationTrace(String expectedTraceId) {
		var toksConv = expectedTraceId.split("\\.");
		var toksMdc = TraceSupport.getOwnTraceParent().split("\\.");
		assertThat(toksConv[0].length(), is(32));
		assertThat(toksConv[1].length(), is(16));
		assertThat(toksConv[0], is(toksMdc[0]));
		assertThat(toksConv[1], is(toksMdc[1]));
		// traceId changed, parentId the same
	}

}
