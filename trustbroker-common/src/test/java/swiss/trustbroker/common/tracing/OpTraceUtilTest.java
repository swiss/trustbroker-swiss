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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.Test;

class OpTraceUtilTest {

	@Test
	void testThreadHex8() {
		var tid = OpTraceUtil.getThreadHex8();
		assertThat(tid.length(), is(8));
		assertThat(tid, not(equalTo("00000000")));
		assertThat(tid, equalTo(String.format("%08x", Thread.currentThread().hashCode())));
	}

	@Test
	void testProcessHex4() {
		var pid = OpTraceUtil.getProcessHex4();
		assertThat(pid.length(), is(4));
		assertThat(pid, not(equalTo("0000")));
	}

	@Test
	void testLocalhostIpHex8() {
		var ip = OpTraceUtil.getLocalhostIpHex8();
		assertThat(ip.length(), is(8));
		assertThat(ip, not(equalTo("00000000")));
	}

	@Test
	void testByteArrayToHexString() {
		var bytes = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9 };
		var hex = OpTraceUtil.byteArrayToHexString(bytes);
		assertThat(hex, is("010203040506070809"));
	}

}
