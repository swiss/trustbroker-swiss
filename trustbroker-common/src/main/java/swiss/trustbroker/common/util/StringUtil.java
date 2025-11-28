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

import org.apache.commons.lang3.StringUtils;

public class StringUtil {

	private static final String WHITE_SPACES = "[\n\r\t]";

	static final String NULL = "<null>";

	static final String MASKED = "<SECRET-MASKED>";

	private StringUtil() {
	}

	/**
	 * @param dataToBeLogged
	 * @return input with all newlines, carriage returns, and tabs replaced with underscores
	 */
	public static String clean(String dataToBeLogged) {
		return clean(dataToBeLogged, null);
	}

	/**
	 * @param dataToBeLogged
	 * @param replace        if null an undercore is used
	 * @return input with all newlines, carriage returns, and tabs replaced with replace
	 */
	public static String clean(String dataToBeLogged, String replace) {
		if (dataToBeLogged == null) {
			return null;
		}
		if (replace == null) {
			replace = "_";
		}
		return dataToBeLogged.replaceAll(WHITE_SPACES, replace);
	}

	/**
	 * @param secret
	 * @return secret masked if not null
	 */
	public static String maskSecret(String secret) {
		return secret == null ? NULL : MASKED;
	}

	/**
	 * @param value
	 * @param secrets
	 * @return value with secrets masked
	 */
	public static String maskSecrets(String value, String... secrets) {
		if (StringUtils.isEmpty(value)) {
			return value;
		}
		for (var secret : secrets) {
			if (StringUtils.isNotEmpty(secret)) {
				value = value.replace(secret, MASKED);
			}
		}
		return value;
	}

}
