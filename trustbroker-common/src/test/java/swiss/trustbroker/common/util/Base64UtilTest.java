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

package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.Base64Util;

class Base64UtilTest {

	private static final byte[] SHORT_INPUT = new byte[] { (byte) -1, 17, 107, (byte) -98, 79, 49, 30, (byte) -22 };

	public static final String SHORT_INPUT_ENCODED = "/xFrnk8xHuo=";

	public static final String SHORT_INPUT_URL_ENCODED = SHORT_INPUT_ENCODED
			.replace("/", "_").replace("+", "-").replace("=", "");

	private static final String LONG_INPUT = "12345678901234567890123456789012345678901234567890123456789012";

	private static final String LONG_INPUT_ENCODED_CHUNKED =
			"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3\nODkwMTI=";

	private static final String LONG_INPUT_ENCODED = LONG_INPUT_ENCODED_CHUNKED.replace("\n", "");

	private static final String LONG_INPUT_URL_ENCODED = LONG_INPUT_ENCODED.replace("=", "");

	@Test
	void encodeException() {
		assertThrows(TechnicalException.class, () -> Base64Util.encode((byte[]) null, Base64Util.Base64Encoding.UNCHUNKED));
	}

	@ParameterizedTest
	@MethodSource
	void encode(byte[] input,  Base64Util.Base64Encoding encoding, String expected) {
		var result = Base64Util.encode(input, encoding);
		assertThat(result, is(expected));
	}

	static Object[][] encode() {
		return new Object[][]{
				{ new byte[0], Base64Util.Base64Encoding.UNCHUNKED, "" },
				{ SHORT_INPUT, Base64Util.Base64Encoding.UNCHUNKED, SHORT_INPUT_ENCODED },
				{ LONG_INPUT.getBytes(StandardCharsets.UTF_8), Base64Util.Base64Encoding.CHUNKED, LONG_INPUT_ENCODED_CHUNKED },
				{ LONG_INPUT.getBytes(StandardCharsets.UTF_8), Base64Util.Base64Encoding.UNCHUNKED, LONG_INPUT_ENCODED }
		};
	}

	@Test
	void encodeString() {
		assertThat(Base64Util.encode(LONG_INPUT, Base64Util.Base64Encoding.CHUNKED), is(LONG_INPUT_ENCODED_CHUNKED));
		assertThat(Base64Util.encode(LONG_INPUT, Base64Util.Base64Encoding.UNCHUNKED), is(LONG_INPUT_ENCODED));
	}

	@Test
	void decodeException() {
		assertThrows(TechnicalException.class, () -> Base64Util.decode(null));
		assertThrows(TechnicalException.class, () -> Base64Util.decode("a=b"));
	}

	@ParameterizedTest
	@MethodSource
	void decode(String input, byte[] expected) {
		var result = Base64Util.decode(input);
		assertThat(result, is(expected));
	}

	static Object[][] decode() {
		return new Object[][]{
				{ "", new byte[0] },
				{ SHORT_INPUT_ENCODED, SHORT_INPUT },
				{ LONG_INPUT_ENCODED_CHUNKED, LONG_INPUT.getBytes(StandardCharsets.UTF_8) },
				{ LONG_INPUT_ENCODED, LONG_INPUT.getBytes(StandardCharsets.UTF_8) }
		};
	}

	@ParameterizedTest
	@MethodSource
	void urlEncode(byte[] input, String expected) {
		var result = Base64Util.urlEncode(input);
		assertThat(result, is(expected));
		result = Base64Util.urlEncode(input != null ? new String(input, StandardCharsets.UTF_8) : null);
		assertThat(result, is(expected));
	}

	static Object[][] urlEncode() {
		return new Object[][]{
				{ null, null },
				{ new byte[0], "" },
				{ LONG_INPUT.getBytes(StandardCharsets.UTF_8), LONG_INPUT_URL_ENCODED }
		};
	}

	@ParameterizedTest
	@MethodSource
	void urlDecode(String input, String expected) {
		var result = Base64Util.urlDecode(input);
		assertThat(result, is(expected));
		result = Base64Util.urlDecode(input, true);
		assertThat(result, is(expected));
	}

	static Object[][] urlDecode() {
		return new Object[][]{
				{ null, null },
				{ "", "" },
				{ SHORT_INPUT_URL_ENCODED, new String(SHORT_INPUT, StandardCharsets.UTF_8) },
				{ LONG_INPUT_URL_ENCODED, LONG_INPUT }
		};
	}

	@Test
	void urlDecodeException() {
		assertThrows(TechnicalException.class, () -> Base64Util.urlDecode(SHORT_INPUT_ENCODED));
		assertThat(Base64Util.urlDecode(SHORT_INPUT_ENCODED, true), is(nullValue()));
	}

}
