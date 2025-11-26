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

package swiss.trustbroker.common.saml.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.codec.Base64Support;
import net.shibboleth.shared.codec.DecodingException;
import net.shibboleth.shared.codec.EncodingException;
import net.shibboleth.shared.logic.ConstraintViolationException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.StringUtil;

@Slf4j
public class Base64Util {

	@Getter
	@AllArgsConstructor(access = AccessLevel.PRIVATE)
	public enum Base64Encoding {
		CHUNKED(Base64Support.CHUNKED),
		UNCHUNKED(Base64Support.UNCHUNKED);

		private final boolean chunked;
	}

	private Base64Util() {
	}

	public static byte[] decode(String stringData) {
		try {
			return Base64Support.decode(stringData);
		}
		catch (DecodingException | ConstraintViolationException e) {
			throw new TechnicalException(String.format("Cannot decode input string=%s", stringData), e);
		}
	}

	public static String encode(String stringData, Base64Encoding encoding) {
		return encode(stringData.getBytes(StandardCharsets.UTF_8), encoding);
	}

	public static String encode(byte[] bytes, Base64Encoding encoding) {
		try {
			return Base64Support.encode(bytes, encoding.isChunked());
		}
		catch (EncodingException | ConstraintViolationException e) {
			throw new TechnicalException(String.format("Message encoding exception=%s", e.getMessage()), e);
		}
	}

	public static String urlDecode(String stringData) {
		return urlDecode(stringData, false);
	}

	public static String urlDecode(String stringData, boolean tryOnly) {
		if (stringData == null) {
			return null;
		}
		try {
			var decoded = Base64.getUrlDecoder()
								  .decode(stringData);
			return new String(decoded, StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException e) {
			if (tryOnly) {
				log.debug("Input string={} is not Base64-URL-encoded: {}", StringUtil.clean(stringData), e.getMessage());
				return null;
			}
			throw new TechnicalException(String.format("Cannot Base64-URL-decode input string=%s", stringData), e);
		}
	}

	public static String urlEncode(String stringData) {
		if (stringData == null) {
			return null;
		}
		return urlEncode(stringData.getBytes(StandardCharsets.UTF_8));
	}

	public static String urlEncode(byte[] data) {
		if (data == null) {
			return null;
		}
		return Base64.getUrlEncoder()
					 .withoutPadding()
					 .encodeToString(data);
	}
}
