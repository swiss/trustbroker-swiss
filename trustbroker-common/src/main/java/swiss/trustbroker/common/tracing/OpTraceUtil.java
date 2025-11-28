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

import java.net.InetAddress;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

@Slf4j
public class OpTraceUtil {

	public static final String HOST_IP_HEX_8 = getLocalhostIpHex8();

	public static final String PID_HEX_4 = getProcessHex4();

	private OpTraceUtil() {
	}

	public static String getThreadHex8() {
		try {
			return String.format("%08x", Thread.currentThread().hashCode());
		}
		catch (Exception e) {
			log.debug("getThreadHex8 failed {}", e.getMessage());
		}
		return "00000000";
	}

	static String getProcessHex4() {
		try {
			return String.format("%04x", ProcessHandle.current().pid()).substring(0, 4);
		}
		catch (Exception e) {
			log.debug("getProcessHex4 failed {}", e.getMessage());
		}
		return "0000";
	}

	static String getLocalhostIpHex8() {
		try {
			return Hex.encodeHexString(InetAddress.getLocalHost().getAddress());
		}
		catch (Exception e) {
			log.debug("getLocalhostIpHex failed {}", e.getMessage());
		}
		return "00000000";
	}

	public static String byteArrayToHexString(byte[] bytes) {
		return Hex.encodeHexString(bytes);
	}

}
