/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import java.util.List;
import java.util.Map;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.exception.TechnicalException;

class JsonUtilTest {

	@ParameterizedTest
	@CsvSource(delimiter = '|', quoteCharacter = '\'', textBlock = """
		'{"name":"john","active":true,"roles":["a","b"],"meta":{"x":"y"}}'|false|MAP
		'null'|true|NULL
		'["a"]'|true|NULL
		'{'|true|NULL
		'["a"]'|false|EXCEPTION
		'{'|false|EXCEPTION
		""")
	void parseJsonObject(String json, boolean tryOnly, String expectedType) {
		if ("EXCEPTION".equals(expectedType)) {
			assertThrows(TechnicalException.class, () -> JsonUtil.parseJsonObject(json, tryOnly));
			return;
		}
		var result = JsonUtil.parseJsonObject(json, tryOnly);
		if ("NULL".equals(expectedType)) {
			assertThat(result, is(nullValue()));
			return;
		}
		var expected = Map.of(
				"name", "john",
				"active", true,
				"roles", List.of("a", "b"),
				"meta", Map.of("x", "y"));
		assertThat(result, is(expected));
	}

}
